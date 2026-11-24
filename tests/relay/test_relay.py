"""Relay adapter, branch pool, and HTTP front-end tests plus SEC-4, SEC-10, SEC-11, SEC-13."""

from __future__ import annotations

import http.client
import json
import logging
import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

from acp_gateway.core.acp_connection import AcpConnection, AcpRpcError
from acp_gateway.core.permission import PermissionGate
from acp_gateway.core.session import new_session
from acp_gateway.relay.__main__ import make_spawn
from acp_gateway.relay.adapter import sse, to_message, to_openai
from acp_gateway.relay.pool import BranchPool, PoolFull
from acp_gateway.relay.server import Handler, group_key, make_server, pick_model, pick_thinking

HERE = Path(__file__).parent
FAKE = str(HERE.parent / "core" / "fake_agy.py")
FIX = HERE / "fixtures"
SAMPLE_429 = ("E1123 02:31:21.478230     119 errorreport.go:273] Error 429, Message: Resource has been exhausted "
              "(e.g. check quota)., Status: RESOURCE_EXHAUSTED, Details: []")


def fixture(name):
    return json.loads((FIX / f"{name}.json").read_text(encoding="utf-8"))["body"]


def events(log):
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []


def make_pool(tmp_path, script, **kw):
    log = tmp_path / "agy.log"
    behaviour = {"script": script, "log": str(log), **kw.pop("behaviour", {})}
    spawn = make_spawn(sys.executable, kw.pop("pin", "1.5.2"), (FAKE, json.dumps(behaviour)))
    return BranchPool(spawn, **kw), log


def swap_id(body, old, new):
    return json.loads(json.dumps(body).replace(old, new))


# ---- adapter -------------------------------------------------------------------------------------------------

def test_adapter_folds_claude_code_system_messages_and_keeps_tool_tail():
    rows, tools = to_openai(fixture("04-subagent-result"))
    roles = [r["role"] for r in rows]
    assert roles == ["system", "user", "assistant", "tool"]
    assert any("<system-message>" in p["text"] for p in rows[1]["content"])
    assert any("<system-message>" in p["text"] for p in rows[3]["content"])
    assert rows[2]["tool_calls"][0]["id"] == "toolu_cap_read" and rows[3]["tool_call_id"] == "toolu_cap_read"
    assert "Agent" in [t["function"]["name"] for t in tools]


def test_adapter_is_deterministic_across_consecutive_requests():
    first, _ = to_openai(fixture("02-subagent-first"))
    later, _ = to_openai(fixture("04-subagent-result"))
    assert later[:2] == first[:2]


def test_adapter_tool_result_with_text_and_image_blocks_and_error():
    body = {"messages": [
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "Read", "input": {"p": 1}},
                                          {"type": "tool_use", "id": "t2", "name": "Bash", "input": {}}]},
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": [{"type": "text", "text": "A"}, {
                "type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "QUFB"}}]},
            {"type": "tool_result", "tool_use_id": "t2", "is_error": True, "content": "boom"},
            {"type": "text", "text": "<system-reminder>r</system-reminder>"}]},
        {"role": "assistant", "content": [{"type": "thinking", "thinking": "x"}, {"type": "text", "text": "ok"}]}]}
    rows, _ = to_openai(body)
    assert [r["role"] for r in rows] == ["user", "assistant", "tool", "tool", "assistant"]
    assert rows[2]["content"][1]["image_url"]["url"] == "data:image/png;base64,QUFB"
    assert [p["text"] for p in rows[3]["content"]] == ["[tool error]", "boom", "<system-reminder>r</system-reminder>"]
    assert rows[4] == {"role": "assistant", "content": "ok"}


def test_sse_frames_cannot_be_injected_by_model_text():
    class Call:
        id, name, arguments = "call_1", "Read", {"file_path": "x"}
    evil = "hi\n\nevent: content_block_start\ndata: {\"type\": \"content_block_start\"}\n\n"
    msg = to_message({"text": evil, "tool_calls": [Call()], "finish_reason": "tool_calls"}, "gemini-4-hydrogen", 5)
    frames = [f for f in sse(msg).decode().split("\n\n") if f]
    names = [f.split("\n")[0] for f in frames]
    assert names == ["event: message_start", "event: content_block_start", "event: content_block_delta",
                     "event: content_block_stop", "event: content_block_start", "event: content_block_delta",
                     "event: content_block_stop", "event: message_delta", "event: message_stop"]
    for f in frames:
        json.loads(f.split("\n", 1)[1][len("data: "):])
    assert msg["stop_reason"] == "tool_use"


def test_only_gemini_models_reach_agy():
    assert pick_model("gemini-4-hydrogen-medium[1m]", "d") == "gemini-4-hydrogen-medium"
    assert pick_model("acp-gemini-4-hydrogen-medium[1m]", "d") == "gemini-4-hydrogen-medium"
    assert pick_model("acp-gemini-4-hydrogen[1m]", "d") == "gemini-4-hydrogen"
    exact_128 = "gemini-4-" + ("a" * 119)
    assert len(exact_128) == 128
    assert pick_model(exact_128, "d") == exact_128
    over_129 = "gemini-4-" + ("a" * 120)
    assert len(over_129) == 129
    assert pick_model(over_129, "d") == "d"
    for bad in (
        "claude-opus-5-5",
        "gpt-oss-120b-medium",
        "acp-claude-opus-5-5",
        {"a": 1},
        ["gemini-4-neon"],
        123,
        None,
        "gemini-4-абв",
        "gemini-4-hydrogen\n",
        "gemini-4-hydrogen\x00",
        "gemini-4-hydrogen[1m]\n",
        "gemini-4-hydrogen[\x00]",
        " gemini-4-hydrogen ",
        "gemini-4-hydrogen[" + ("x" * 20) + "]",
    ):
        assert pick_model(bad, "d") == "d", repr(bad)


@pytest.mark.parametrize(("body", "expected"), [
    ({"output_config": {"effort": "none"}}, "low"),
    ({"output_config": {"effort": "minimal"}}, "low"),
    ({"output_config": {"effort": "medium"}}, "medium"),
    ({"output_config": {"effort": "high"}}, "high"),
    ({"output_config": {"effort": "xhigh"}}, "xhigh"),
    ({"output_config": {"effort": "max"}}, "xhigh"),
    ({"output_config": {"effort": "ultra"}}, "xhigh"),
    ({"thinking": {"type": "disabled"}}, "low"),
    ({}, None),
])
def test_pick_thinking_mapping(monkeypatch, body, expected):
    monkeypatch.delenv("ACP_GATEWAY_THINKING_LEVEL", raising=False)
    assert pick_thinking(body) == expected


def test_pick_thinking_non_dict_fields_do_not_raise(monkeypatch):
    monkeypatch.delenv("ACP_GATEWAY_THINKING_LEVEL", raising=False)
    for body in (
        {"thinking": True},
        {"thinking": "disabled"},
        {"thinking": ["disabled"]},
        {"output_config": "high"},
        {"output_config": True},
        {"output_config": 123},
        {"thinking": True, "output_config": "xhigh"},
    ):
        assert pick_thinking(body) is None, body


def test_pick_thinking_env_override(monkeypatch):
    monkeypatch.setenv("ACP_GATEWAY_THINKING_LEVEL", "low")
    assert pick_thinking({"output_config": {"effort": "high"}}) == "low"


# ---- SEC-4: make_spawn explicit child env ---------------------------------------------------------------------

def test_make_spawn_passes_explicit_home_without_mutating_os_environ(monkeypatch, tmp_path):
    """SEC-4: make_spawn passes profile_home/gemini_home/force_file_storage directly to AcpConnection."""
    orig_home = os.environ.get("HOME")
    monkeypatch.delenv("GEMINI_HOME", raising=False)
    monkeypatch.delenv("AGY_ACP_FORCE_FILE_STORAGE", raising=False)
    prof = tmp_path / "gw-home"
    prof.mkdir()
    gem = prof / ".gemini"
    spawn = make_spawn(
        sys.executable,
        "1.5.2",
        (FAKE, json.dumps({})),
        profile_home=str(prof),
        gemini_home=str(gem),
        force_file_storage=True,
    )
    conn = spawn("k", str(tmp_path))
    try:
        dumped = conn.request("x/dump_env", {}, timeout=10)
        assert dumped == {
            "HOME": str(prof),
            "GEMINI_HOME": str(gem),
            "AGY_ACP_FORCE_FILE_STORAGE": "1",
        }
        assert os.environ.get("HOME") == orig_home
        assert "GEMINI_HOME" not in os.environ
        assert "AGY_ACP_FORCE_FILE_STORAGE" not in os.environ
    finally:
        conn.close()


# ---- branch pool ----------------------------------------------------------------------------------------------

def test_real_subagent_sequence_is_one_prompt_with_resume_held(tmp_path):
    pool, log = make_pool(tmp_path, [[{"call": {"name": "Read", "arguments": {"file_path": "notes.txt"}}},
                                      {"text": "first line read"}]])
    try:
        rows, tools = to_openai(fixture("02-subagent-first"))
        r1 = pool.serve("g", rows, tools, "m", None, threading.Event())
        assert [c.name for c in r1["tool_calls"]] == ["Read"]
        rows4, _ = to_openai(swap_id(fixture("04-subagent-result"), "toolu_cap_read", r1["tool_calls"][0].id))
        r2 = pool.serve("g", rows4, tools, "m", None, threading.Event())
        assert r2["text"] == "first line read"
        assert [e["n"] for e in events(log) if e["ev"] == "prompt"] == [0]
    finally:
        pool.close_all()


def _turn(rows, reply, user):
    return [*rows, {"role": "assistant", "content": reply}, {"role": "user", "content": [{"type": "text", "text": user}]}]


def test_fork_while_live_gets_its_own_branch_and_thread_resumes(tmp_path, caplog):
    pool, log = make_pool(tmp_path, [[{"call": {"name": "Read", "arguments": {}}}, {"text": "thread done"}],
                                     [{"text": "fork answer"}]])
    caplog.set_level(logging.INFO)
    try:
        rows, tools = to_openai(fixture("02-subagent-first"))
        r1 = pool.serve("g", rows, tools, "m", None, threading.Event())
        fork = [*rows, {"role": "user", "content": [{"type": "text", "text": "side question"}]}]
        assert pool.serve("g", fork, tools, "m", None, threading.Event())["text"] == "fork answer"
        cid = r1["tool_calls"][0].id
        done = [*rows, {"role": "assistant", "content": "", "tool_calls": [
            {"id": cid, "type": "function", "function": {"name": "Read", "arguments": "{}"}}]},
                {"role": "tool", "tool_call_id": cid, "content": [{"type": "text", "text": "R"}]}]
        assert pool.serve("g", done, tools, "m", None, threading.Event())["text"] == "thread done"
        assert "superseded" not in caplog.text
    finally:
        pool.close_all()


def test_fork_while_idle_may_take_the_branch_thread_replays_never_cancels(tmp_path, caplog):
    pool, log = make_pool(tmp_path, [[{"text": "one"}], [{"text": "fork"}], [{"text": "thread two"}]])
    caplog.set_level(logging.INFO)
    try:
        rows, tools = to_openai(fixture("02-subagent-first"))
        pool.serve("g", rows, tools, "m", None, threading.Event())
        assert pool.serve("g", _turn(rows, "one", "fork q"), tools, "m", None, threading.Event())["text"] == "fork"
        assert pool.serve("g", _turn(rows, "one", "real next"), tools, "m", None,
                          threading.Event())["text"] == "thread two"
        turns = [r.getMessage() for r in caplog.records if r.getMessage().startswith("acp-gateway turn:")]
        assert turns == ["acp-gateway turn: replay", "acp-gateway turn: continue", "acp-gateway turn: replay"]
        assert len([e for e in events(log) if e["ev"] == "new"]) == 2
        assert "superseded" not in caplog.text
    finally:
        pool.close_all()


def test_simultaneous_fork_and_thread_on_one_idle_branch_never_supersede(tmp_path, caplog):
    pool, _ = make_pool(tmp_path, [[{"text": "one"}], [{"silent": 0.5}, {"text": "a"}], [{"text": "b"}]])
    caplog.set_level(logging.INFO)
    try:
        rows, tools = to_openai(fixture("02-subagent-first"))
        pool.serve("g", rows, tools, "m", None, threading.Event())
        out = []
        ts = [threading.Thread(target=lambda u=u: out.append(pool.serve("g", _turn(rows, "one", u), tools, "m", None,
                                                                         threading.Event())["text"]))
              for u in ("thread next", "fork q")]
        [t.start() for t in ts]
        [t.join(30) for t in ts]
        assert sorted(out) == ["a", "b"]
        assert "superseded" not in caplog.text
    finally:
        pool.close_all()


def test_cap_evicts_idle_branch_and_full_pool_raises(tmp_path):
    pool, _ = make_pool(tmp_path, [[{"text": "x"}]] * 3 + [[{"call": {"name": "Read", "arguments": {}}}]] * 2,
                        max_children=2, wait_s=0.5)
    try:
        rows, tools = to_openai(fixture("02-subagent-first"))
        for g in ("g1", "g2", "g3"):
            pool.serve(g, rows, tools, "m", None, threading.Event())
        assert pool.children() == 2
        pool.serve("g4", rows, tools, "m", None, threading.Event())
        pool.serve("g5", rows, tools, "m", None, threading.Event())
        with pytest.raises(PoolFull):
            pool.serve("g6", rows, tools, "m", None, threading.Event())
    finally:
        pool.close_all()


def test_version_pin_refuses_other_agy_versions(tmp_path):
    pool, _ = make_pool(tmp_path, [[{"text": "x"}]], behaviour={"version": "1.5.15"})
    try:
        rows, tools = to_openai(fixture("02-subagent-first"))
        with pytest.raises(Exception, match="not the verified 1.5.2"):
            pool.serve("g", rows, tools, "m", None, threading.Event())
    finally:
        pool.close_all()


@pytest.mark.parametrize("stateless", [False, True])
def test_pool_handoff_rechecks_dead_standby_inside_lock(tmp_path, stateless):
    """If standby exits between _reserve() and the handoff lock, keep _opening reserved and spawn fresh."""
    pool, _ = make_pool(tmp_path, [[{"text": "recovered"}]], max_children=2, warm_standby=1)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and pool.standby() < 1:
            time.sleep(0.05)
        orig_reserve = pool._reserve

        def reserve_then_kill():
            item = orig_reserve()
            assert item is not None
            item[0].close()  # dies AFTER _reserve() popped it and BEFORE handoff lock
            return item

        pool._reserve = reserve_then_kill  # type: ignore[method-assign]
        rows, tools = to_openai(fixture("02-subagent-first"))
        res = pool.serve("g-race", rows, tools, "m", None, threading.Event(), stateless=stateless)
        assert res["text"] == "recovered"
        with pool._lock:
            assert pool._opening == 0
    finally:
        pool.close_all()


# ---- HTTP front end ---------------------------------------------------------------------------------------------

@pytest.fixture
def gateway(tmp_path):
    made = []

    def start(script, **kw):
        max_connections = kw.pop("max_connections", None)
        pool, log = make_pool(tmp_path, script, **kw)
        srv = make_server(pool, 0, "gemini-4-hydrogen-medium", max_connections=max_connections)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        made.append((srv, pool))
        return srv.server_address[1], pool, log

    yield start
    for srv, pool in made:
        srv.shutdown()
        pool.close_all()


def post(port, path, body, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    c.request("POST", path, json.dumps(body), {"Content-Type": "application/json", **(headers or {})})
    r = c.getresponse()
    return r.status, dict(r.getheaders()), r.read()


def test_http_streams_tool_use_then_end_turn(gateway):
    port, _, log = gateway([[{"call": {"name": "Read", "arguments": {"file_path": "n"}}}, {"text": "done"}]])
    hdr = {"x-claude-code-session-id": "s1"}
    st, h, raw = post(port, "/v1/messages?beta=true", fixture("02-subagent-first"), hdr)
    assert st == 200 and h["Content-Type"] == "text/event-stream"
    frames = [json.loads(f.split("\n", 1)[1][6:]) for f in raw.decode().split("\n\n") if f]
    tool = [f["content_block"] for f in frames if f["type"] == "content_block_start"][0]
    assert tool["type"] == "tool_use" and tool["name"] == "Read"
    assert frames[-2]["delta"]["stop_reason"] == "tool_use"
    st, _, raw = post(port, "/v1/messages?beta=true", swap_id(fixture("04-subagent-result"), "toolu_cap_read",
                                                              tool["id"]), hdr)
    assert st == 200 and b'"text_delta", "text": "done"' in raw and b'"end_turn"' in raw
    assert len([e for e in events(log) if e["ev"] == "prompt"]) == 1


def test_health_ping_never_spawns(gateway):
    port, pool, log = gateway([[{"text": "x"}]])
    st, _, raw = post(port, "/v1/messages", {"model": "gemini-4-x", "max_tokens": 1,
                                             "messages": [{"role": "user", "content": "hi"}]})
    assert st == 200 and json.loads(raw)["type"] == "message"
    assert pool.children() == 0 and events(log) == []


def test_rate_limit_is_429_without_retry_and_one_prompt(gateway):
    port, _, log = gateway([[{"stderr": SAMPLE_429}, {"silent": 5}]])
    st, h, raw = post(port, "/v1/messages", fixture("02-subagent-first"), {"x-claude-code-session-id": "s"})
    assert st == 429 and h.get("x-should-retry") == "false" and json.loads(raw)["error"]["type"] == "rate_limit_error"
    assert len([e for e in events(log) if e["ev"] == "prompt"]) == 1


def test_version_mismatch_is_529_without_retry(gateway):
    port, _, _ = gateway([[{"text": "x"}]], behaviour={"version": "9.9"})
    st, h, _ = post(port, "/v1/messages", fixture("02-subagent-first"), {"x-claude-code-session-id": "s"})
    assert st == 529 and h.get("x-should-retry") == "false"


def test_non_loopback_host_browser_origin_and_sec_fetch_site_are_refused(gateway):
    """SEC-13: reject non-loopback Host, any Origin, and cross-site/same-site Sec-Fetch-Site."""
    port, _, _ = gateway([[{"text": "x"}]])
    assert post(port, "/v1/messages", {}, {"Host": "evil.example"})[0] == 403
    assert post(port, "/v1/messages", {}, {"Origin": "http://127.0.0.1:1"})[0] == 403
    for bad_sfs in ("cross-site", "same-site", "Cross-Site", "other"):
        st, _, raw = post(port, "/v1/messages", {}, {"Sec-Fetch-Site": bad_sfs})
        assert st == 403 and json.loads(raw)["error"] == {
            "type": "permission_error",
            "message": "loopback clients only",
        }
    # Allowed Sec-Fetch-Site values (none, same-origin, or absent) pass _guard
    for ok_headers in ({}, {"Sec-Fetch-Site": "none"}, {"Sec-Fetch-Site": "same-origin"}):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        c.request("GET", "/health", headers=ok_headers)
        assert c.getresponse().status == 200


def test_missing_and_oversized_content_length(gateway):
    port, _, _ = gateway([[{"text": "x"}]])
    for head, want in ((b"", b"411"), (b"Content-Length: \xb2\r\n", b"411"),
                       (b"Content-Length: 99999999999\r\n", b"413")):
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n" + head + b"\r\n")
        assert s.recv(64).split(b" ")[1] == want
        s.close()


def test_count_tokens_estimates_without_agy(gateway):
    port, pool, _ = gateway([[{"text": "x"}]])
    st, _, raw = post(port, "/v1/messages/count_tokens?beta=true", fixture("01-main-first"))
    assert st == 200 and json.loads(raw)["input_tokens"] > 100 and pool.children() == 0


def test_declined_probe_does_not_refresh_last_used(tmp_path):
    pool, _ = make_pool(tmp_path, [[{"text": "x"}], [{"text": "y"}]], idle_ttl=0.5)
    try:
        rows, tools = to_openai(fixture("02-subagent-first"))
        pool.serve("g", rows, tools, "m", None, threading.Event())
        (first,) = pool._groups["g"]
        stamp = first.last_used
        other = [*rows, {"role": "user", "content": [{"type": "text", "text": "unrelated"}]}]
        other[1] = {"role": "user", "content": [{"type": "text", "text": "different history"}]}
        pool.serve("g", other, tools, "m", None, threading.Event())
        assert first.last_used == stamp
        time.sleep(0.6)
        pool.reap()
        assert first not in pool._groups.get("g", [])
    finally:
        pool.close_all()


def test_duplicate_resume_does_not_share_the_step(tmp_path):
    pool, log = make_pool(tmp_path, [[{"call": {"name": "Read", "arguments": {}}}, {"silent": 0.3}, {"text": "done"}],
                                     [{"text": "replayed"}]])
    try:
        rows, tools = to_openai(fixture("02-subagent-first"))
        r1 = pool.serve("g", rows, tools, "m", None, threading.Event())
        cid = r1["tool_calls"][0].id
        done = [*rows, {"role": "assistant", "content": "", "tool_calls": [
            {"id": cid, "type": "function", "function": {"name": "Read", "arguments": "{}"}}]},
                {"role": "tool", "tool_call_id": cid, "content": [{"type": "text", "text": "R"}]}]
        out = []
        t = threading.Thread(target=lambda: out.append(pool.serve("g", done, tools, "m", None, threading.Event())))
        t.start()
        time.sleep(0.1)
        dup = pool.serve("g", done, tools, "m", None, threading.Event())
        t.join(30)
        assert out[0]["text"] == "done" and dup["text"] == "replayed"
    finally:
        pool.close_all()


def test_concurrent_new_branches_respect_the_cap(tmp_path):
    pool, _ = make_pool(tmp_path, [[{"silent": 1.0}, {"text": "a"}], [{"text": "b"}]], max_children=1, wait_s=0.2,
                        behaviour={"new_delay": 0.3})
    try:
        rows, tools = to_openai(fixture("02-subagent-first"))
        res = []

        def go(g):
            try:
                res.append(pool.serve(g, rows, tools, "m", None, threading.Event())["text"])
            except PoolFull:
                res.append("full")

        ts = [threading.Thread(target=go, args=(g,)) for g in ("g1", "g2")]
        [t.start() for t in ts]
        [t.join(30) for t in ts]
        assert sorted(res) == ["a", "full"]
    finally:
        pool.close_all()


def test_malformed_bodies_are_400_and_never_prompt(gateway):
    port, _, log = gateway([[{"text": "x"}]])
    hdr = {"x-claude-code-session-id": "s"}
    bad = [[], None, "x", 5, {"max_tokens": 1, "messages": "x"}, {"messages": []},
           {"messages": [{"role": "user", "content": "hi"}], "thinking": True},
           {"messages": [{"role": "user", "content": "hi"}], "output_config": "high"},
           {"messages": [{"role": "user", "content": "hi"}], "output_config": True}]
    for body in bad:
        st, _, raw = post(port, "/v1/messages", body, hdr)
        assert st == 400 and json.loads(raw)["error"]["type"] == "invalid_request_error", body
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    lone = b'{"messages": [{"role": "user", "content": "\\ud83d"}]}'
    deep = b"[" * 1000 + b"]" * 1000
    for payload in (lone, deep):
        for path in ("/v1/messages", "/v1/messages/count_tokens"):
            c.request("POST", path, payload, {"Content-Type": "application/json", **hdr})
            r = c.getresponse()
            assert r.status == 400, (path, len(payload))
            r.read()
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    assert not [e for e in events(log) if e["ev"] == "prompt"]


def test_ipv6_loopback_host_is_accepted(gateway):
    port, _, _ = gateway([[{"text": "x"}]])
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("GET", "/health", headers={"Host": f"[::1]:{port}"})
    assert c.getresponse().status == 200


def test_client_disconnect_cancels_the_prompt(gateway):
    port, _, log = gateway([[{"silent": 30}]])
    body = json.dumps(fixture("02-subagent-first")).encode()
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
              b"x-claude-code-session-id: s\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and not any(e["ev"] == "prompt" for e in events(log)):
        time.sleep(0.1)
    s.close()
    while time.monotonic() < deadline and not any(e["ev"] == "cancel" for e in events(log)):
        time.sleep(0.1)
    assert any(e["ev"] == "cancel" for e in events(log))


def test_billing_header_checksum_does_not_split_a_thread(tmp_path):
    pool, log = make_pool(tmp_path, [[{"call": {"name": "Read", "arguments": {}}}, {"text": "done"}]])
    try:
        def with_cch(body, cch):
            body = json.loads(json.dumps(body))
            body["system"][0]["text"] = f"x-anthropic-billing-header: cc_version=2.1.325.6be; cc_entrypoint=cli; cch={cch};"
            return body

        rows, tools = to_openai(with_cch(fixture("02-subagent-first"), "aaaa1"))
        assert "x-anthropic-billing-header" not in rows[0]["content"]
        r1 = pool.serve("g", rows, tools, "m", None, threading.Event())
        b4 = with_cch(swap_id(fixture("04-subagent-result"), "toolu_cap_read", r1["tool_calls"][0].id), "bbbb2")
        rows4, _ = to_openai(b4)
        assert rows4[0] == rows[0]
        assert group_key("s", rows, tools) == group_key("s", rows4, tools)
        assert pool.serve("g", rows4, tools, "m", None, threading.Event())["text"] == "done"
        assert len([e for e in events(log) if e["ev"] == "prompt"]) == 1
    finally:
        pool.close_all()


def test_every_response_has_its_own_message_id():
    ids = {to_message({"text": "x", "finish_reason": "stop"}, "m", 1)["id"] for _ in range(5)}
    assert len(ids) == 5


def test_disconnect_after_reply_does_not_cancel_live_branch(gateway, caplog):
    port, _, log = gateway([[{"call": {"name": "Read", "arguments": {"file_path": "n"}}}, {"text": "done"}]])
    hdr = {"x-claude-code-session-id": "s-close", "Connection": "close"}
    caplog.set_level(logging.INFO)
    st, _, raw = post(port, "/v1/messages", fixture("02-subagent-first"), hdr)
    assert st == 200
    frames = [json.loads(f.split("\n", 1)[1][6:]) for f in raw.decode().split("\n\n") if f]
    tool = [f["content_block"] for f in frames if f["type"] == "content_block_start"][0]
    time.sleep(0.6)
    assert "client disconnected" not in caplog.text
    assert not any(e["ev"] == "cancel" for e in events(log))
    st2, _, raw2 = post(port, "/v1/messages", swap_id(fixture("04-subagent-result"), "toolu_cap_read", tool["id"]),
                        {"x-claude-code-session-id": "s-close"})
    assert st2 == 200 and b'"done"' in raw2
    assert len([e for e in events(log) if e["ev"] == "prompt"]) == 1


def test_terminal_tool_retires_immediately_and_frees_slot(tmp_path):
    pool, log = make_pool(tmp_path, [[{"call": {"name": "SubagentHandback", "arguments": {"message": "ok"}}},
                                      {"silent": 30}],
                                     [{"text": "second"}]], max_children=1, wait_s=0.5)
    try:
        rows, tools = to_openai(fixture("02-subagent-first"))
        tools = [*tools, {"type": "function", "function": {"name": "SubagentHandback", "description": "",
                                                           "parameters": {"type": "object"}}}]
        r1 = pool.serve("g1", rows, tools, "m", None, threading.Event())
        assert [c.name for c in r1["tool_calls"]] == ["SubagentHandback"]
        (branch,) = pool._groups["g1"]
        assert not branch.live and branch.retire_reason == "terminal-handout"
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not any(e["ev"] == "cancel" for e in events(log)):
            time.sleep(0.05)
        assert any(e["ev"] == "cancel" for e in events(log))
        r2 = pool.serve("g2", rows, tools, "m", None, threading.Event())
        assert r2["text"] == "second"
    finally:
        pool.close_all()


def test_provider_error_log_omits_untrusted_rpc_message(gateway, caplog):
    """SEC-10: ProviderError logs record class name only, never str(exc) / untrusted rpc_message."""
    sentinel = "UNTRUSTED-RPC-SECRET-SENTINEL-999"
    port, _, _ = gateway([[{"rpc_error": {"code": -32000, "message": sentinel}}]])
    caplog.set_level(logging.INFO)
    st, h, raw = post(port, "/v1/messages", fixture("02-subagent-first"), {"x-claude-code-session-id": "s-err"})
    assert st == 529 and h.get("x-should-retry") == "false"
    assert "acp-gateway: request failed (ProviderError)" in caplog.text
    assert sentinel not in caplog.text
    assert sentinel not in raw.decode("utf-8", "replace")


def test_http_connection_cap_returns_529_and_recovers(gateway):
    """SEC-11: Server.max_connections bounds concurrency via BoundedSemaphore returning 529."""
    port, _, log = gateway([[{"silent": 1.2}, {"text": "a"}], [{"silent": 1.2}, {"text": "b"}]],
                           max_connections=1, max_children=2)
    out = {}

    def first():
        out["first"] = post(port, "/v1/messages", fixture("02-subagent-first"),
                            {"x-claude-code-session-id": "s-cap-1"})

    t = threading.Thread(target=first)
    t.start()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not any(e["ev"] == "prompt" for e in events(log)):
        time.sleep(0.05)
    # While the 1 allowed connection is busy in pool.serve, a second request gets 529 immediately
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", "/health")
    r = c.getresponse()
    body = json.loads(r.read())
    assert r.status == 529
    assert r.getheader("x-should-retry") == "false"
    assert (r.getheader("Connection") or "").lower() == "close"
    assert body["error"]["type"] == "overloaded_error"
    t.join(15)
    assert out["first"][0] == 200
    # After completion, semaphore is released and /health succeeds again
    c2 = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c2.request("GET", "/health")
    assert c2.getresponse().status == 200


def test_handler_timeout_bounds_slow_read_but_not_pool_serve(gateway, monkeypatch):
    """SEC-11: Handler.timeout=30.0 bounds body read, disabled during pool.serve and restored in finally."""
    assert Handler.timeout == 30.0
    monkeypatch.setattr(Handler, "timeout", 0.4)
    port, _, _ = gateway([[{"silent": 0.9}, {"text": "slow-ok"}]])
    # 1) Slow client declaring Content-Length 100 but sending nothing times out promptly
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 100\r\n\r\n")
    t0 = time.monotonic()
    data = s.recv(1024)
    elapsed = time.monotonic() - t0
    s.close()
    assert data == b"" and elapsed < 3.0
    # 2) Backend taking 0.9s (> Handler.timeout=0.4s) succeeds because timeout is cleared around pool.serve
    st, _, raw = post(port, "/v1/messages", fixture("02-subagent-first"), {"x-claude-code-session-id": "s-slow"})
    assert st == 200 and b"slow-ok" in raw


def test_duplicate_system_messages_deduped_without_breaking_matcher(tmp_path):
    big_sys = "Available agent types:\n" + ("- worker: does work cleanly\n" * 20)
    assert len(big_sys) > 300
    pool, log = make_pool(tmp_path, [[
        {"call": {"name": "Read", "arguments": {"file_path": "a"}}},
        {"call": {"name": "Read", "arguments": {"file_path": "b"}}},
        {"text": "all done"},
    ]])
    try:
        base_body = {"system": "sys", "tools": [{"name": "Read", "input_schema": {"type": "object"}}],
                     "messages": [{"role": "user", "content": "start"}, {"role": "system", "content": big_sys}]}
        rows1, tools = to_openai(base_body)
        r1 = pool.serve("g", rows1, tools, "m", None, threading.Event())
        c1 = r1["tool_calls"][0].id
        body2 = {**base_body, "messages": [
            *base_body["messages"],
            {"role": "assistant", "content": [{"type": "tool_use", "id": c1, "name": "Read", "input": {"file_path": "a"}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": c1, "content": "file A"}]},
            {"role": "system", "content": big_sys},
        ]}
        rows2, _ = to_openai(body2)
        r2 = pool.serve("g", rows2, tools, "m", None, threading.Event())
        c2 = r2["tool_calls"][0].id
        body3 = {**body2, "messages": [
            *body2["messages"],
            {"role": "assistant", "content": [{"type": "tool_use", "id": c2, "name": "Read", "input": {"file_path": "b"}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": c2, "content": "file B"}]},
            {"role": "system", "content": big_sys},
        ]}
        rows3, _ = to_openai(body3)
        r3 = pool.serve("g", rows3, tools, "m", None, threading.Event())
        assert r3["text"] == "all done"
        evs = events(log)
        assert len([e for e in evs if e["ev"] == "prompt"]) == 1
        answers = [e for e in evs if e["ev"] == "answer"]
        assert len(answers) == 2
        assert "Available agent types:" not in answers[0]["text"]
        assert "unchanged from earlier in this session" in answers[0]["text"]
        assert "Available agent types:" not in answers[1]["text"]
        assert "unchanged from earlier in this session" in answers[1]["text"]
    finally:
        pool.close_all()


def test_warm_standby_reused_respects_cap_and_closes_cleanly(tmp_path):
    pool, log = make_pool(tmp_path, [[{"text": "first"}], [{"text": "second"}]],
                          max_children=2, warm_standby=1, behaviour={"log_init": True})
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and pool.standby() < 1:
            time.sleep(0.05)
        assert pool.standby() == 1 and pool.children() == 1
        assert len([e for e in events(log) if e["ev"] == "init"]) == 1
        rows, tools = to_openai(fixture("02-subagent-first"))
        r1 = pool.serve("g1", rows, tools, "m", None, threading.Event())
        assert r1["text"] == "first"
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and pool.standby() < 1:
            time.sleep(0.05)
        assert pool.children() == 2 and pool.standby() == 1
        assert len([e for e in events(log) if e["ev"] == "init"]) == 2
        r2 = pool.serve("g2", rows, tools, "m", None, threading.Event())
        assert r2["text"] == "second"
        assert pool.children() <= 2
    finally:
        pool.close_all()
    assert pool.children() == 0 and pool.standby() == 0


def test_dead_standby_is_discarded_and_replaced(tmp_path):
    pool, _ = make_pool(tmp_path, [[{"text": "ok"}]], max_children=2, warm_standby=1)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and pool.standby() < 1:
            time.sleep(0.05)
        with pool._lock:
            dead_conn = pool._standby[0][0]
        dead_conn.close()
        rows, tools = to_openai(fixture("02-subagent-first"))
        assert pool.serve("g1", rows, tools, "m", None, threading.Event())["text"] == "ok"
    finally:
        pool.close_all()


def test_usage_update_overrides_estimated_tokens(gateway):
    port, _, _ = gateway([[{"usage": {"used": 4321, "size": 1000000, "outputTokens": 77}}, {"text": "counted"}]])
    st, _, raw = post(port, "/v1/messages",
                      {"model": "gemini-4-hydrogen-medium", "messages": [{"role": "user", "content": "hi"}],
                       "tools": [{"name": "Read", "input_schema": {"type": "object"}}]},
                      {"x-claude-code-session-id": "s-usage"})
    assert st == 200
    body = json.loads(raw)
    assert body["usage"] == {"input_tokens": 4321, "output_tokens": 77}
    msg = to_message({"text": "hello world", "finish_reason": "stop",
                      "usage": {"input_tokens": True, "used": 99, "output_tokens": True}}, "m", 50)
    assert msg["usage"]["input_tokens"] == 99 and type(msg["usage"]["output_tokens"]) is int
    assert msg["usage"]["output_tokens"] > 1


def test_gateway_sends_honest_client_info_and_session_close(tmp_path):
    pool, log = make_pool(tmp_path, [[{"call": {"name": "SubagentHandback", "arguments": {"message": "done"}}},
                                      {"silent": 10}]],
                          behaviour={"log_init": True, "session_close": True, "session_close_error": -32002,
                                     "load_session": True, "session_resume": True})
    try:
        rows, tools = to_openai(fixture("02-subagent-first"))
        tools = [*tools, {"type": "function", "function": {"name": "SubagentHandback", "description": "",
                                                           "parameters": {"type": "object"}}}]
        pool.serve("g1", rows, tools, "m", None, threading.Event())
        (branch,) = pool._groups["g1"]
        assert branch.conn is not None
        assert branch.conn.supports_session_close and branch.conn.supports_load_session
        assert branch.conn.supports_session_resume and branch.conn.supports_http_mcp
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not any(e["ev"] == "close_session" for e in events(log)):
            time.sleep(0.05)
        evs = events(log)
        init_ev = next(e for e in evs if e["ev"] == "init")
        assert init_ev["client"]["name"] == "acp-gateway"
        assert init_ev["caps"] == {"fs": {"readTextFile": False, "writeTextFile": False}, "terminal": False}
        assert any(e["ev"] == "close_session" for e in evs)
    finally:
        pool.close_all()


def test_session_close_skipped_when_not_advertised(tmp_path):
    pool, log = make_pool(tmp_path, [[{"call": {"name": "SubagentHandback", "arguments": {}}}, {"silent": 10}]],
                          behaviour={"log_init": True, "session_close": False})
    try:
        rows, tools = to_openai(fixture("02-subagent-first"))
        tools = [*tools, {"type": "function", "function": {"name": "SubagentHandback", "description": "",
                                                           "parameters": {"type": "object"}}}]
        pool.serve("g1", rows, tools, "m", None, threading.Event())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not any(e["ev"] == "cancel" for e in events(log)):
            time.sleep(0.05)
        time.sleep(0.2)
        assert not any(e["ev"] == "close_session" for e in events(log))
    finally:
        pool.close_all()


def test_acp_client_handlers_capabilities_and_cancel_request(tmp_path):
    log = tmp_path / "agy.log"
    behaviour = {
        "log": str(log),
        "log_init": True,
        "script": [[
            {"client_req": {"method": "fs/read_text_file", "params": {"path": "/ok.txt"}}},
            {"client_req": {"method": "fs/read_text_file", "params": {"path": "/missing.txt"}}},
            {"client_req": {"method": "fs/write_text_file", "params": {"path": "/x"}}},
            {"client_req": {"method": "terminal/wait_for_exit", "params": {"terminalId": "t1"}, "cancel_after": 0.1}},
            {"text": "handled"},
        ]],
    }

    def read_file(p):
        if p.get("path") == "/missing.txt":
            raise AcpRpcError(-32002, "file not found")
        return {"content": "hello from client"}

    def wait_exit(p):
        time.sleep(1.0)
        return {"exitCode": 0}

    handlers = {
        "fs/read_text_file": read_file,
        "terminal/create": lambda p: {"terminalId": "t1"},
        "terminal/output": lambda p: {"output": "", "truncated": False},
        "terminal/wait_for_exit": wait_exit,
        "terminal/kill": lambda p: {},
        "terminal/release": lambda p: {},
    }
    conn = AcpConnection(sys.executable, [FAKE, json.dumps(behaviour)], str(tmp_path),
                         client_info={"name": "full-acp-test", "version": "1.0.0"},
                         client_handlers=handlers)
    try:
        conn.start()
        conn.initialize()
        sess = new_session(conn, mcp_server={"name": "m", "type": "http", "url": "http://127.0.0.1:1/m"},
                           gate=PermissionGate("m", frozenset()))
        res = sess.prompt("go", timeout=15.0)
        assert res.stop_reason == "end_turn"
        evs = events(log)
        init_ev = next(e for e in evs if e["ev"] == "init")
        assert init_ev["client"]["name"] == "full-acp-test"
        assert init_ev["caps"] == {"fs": {"readTextFile": True, "writeTextFile": False}, "terminal": True}
        resps = [e for e in evs if e["ev"] == "client_resp"]
        assert resps[0]["resp"]["result"] == {"content": "hello from client"}
        assert resps[1]["resp"]["error"] == {"code": -32002, "message": "file not found"}
        assert resps[2]["resp"]["error"]["code"] == -32601
        assert resps[3]["resp"]["error"]["code"] == -32800
    finally:
        conn.close()
