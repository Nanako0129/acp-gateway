"""Core AcpConnection tests plus SEC-4, SEC-5, and SEC-11 hardening checks."""

from __future__ import annotations

import contextlib
import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

from acp_gateway.core import acp_connection
from acp_gateway.core.acp_connection import (
    MAX_UNATTACHED_SESSIONS,
    MAX_UNATTACHED_UPDATES,
    AcpConnection,
    AcpProcessExit,
    AcpRpcError,
)
from acp_gateway.core.permission import PermissionGate
from acp_gateway.core.session import new_session

from .conftest import dump

FAKE_AGY = str(Path(__file__).with_name("fake_agy.py"))


def _events(log: Path) -> list[dict]:
    return [json.loads(ln) for ln in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []


def test_early_update_before_session_new_reply_is_buffered_and_flushed(connect):
    conn = connect({"early_update": True})
    sid = conn.request("session/new", {"cwd": conn.cwd, "mcpServers": []}, timeout=10)["sessionId"]
    got = []
    conn.attach_session(sid, got.append, lambda p: None)
    assert [u["content"]["text"] for u in got] == ["early"]  # delivered in order, on attach


def test_stderr_flood_of_a_megabyte_does_not_block_child(connect):
    conn = connect({"flood_stderr": 1_200_000})  # initialize reply only comes after the flood
    assert conn.request("x/dump", {}, timeout=10)["cwd"] == conn.cwd
    assert len(conn._stderr) == 200  # 12000 lines were flooded; only the bounded tail is kept


def test_child_exit_surfaces_status_and_diagnostic_but_never_stderr_bytes(connect):
    secret_lines = ["boot ok", "token " + "ya29" + ".SECRET1234567", "Authorization: Bearer SECRET"]
    conn = connect({"exit_on": "session/new", "exit_code": 7, "stderr_lines": secret_lines})
    with pytest.raises(AcpProcessExit) as raised:
        conn.request("session/new", {"cwd": conn.cwd, "mcpServers": []}, timeout=10)
    text = str(raised.value)
    assert "status 7" in text and "server stderr suppressed" in text
    assert "google-access-token-prefix" in text and "bearer-token" in text
    for planted in ("SECRET1234567", "Bearer SECRET", "boot ok"):
        assert planted not in text and planted not in repr(raised.value)
    assert raised.value.exit_status == 7
    with pytest.raises(AcpProcessExit):  # later requests fail the same typed way
        conn.request("x/dump", {}, timeout=10)


def test_rate_limit_stderr_sets_fixed_retry_class(connect):
    conn = connect({"exit_on": "session/new", "stderr_lines": ["Error 429, RESOURCE_EXHAUSTED"]})
    with pytest.raises(AcpProcessExit) as raised:
        conn.request("session/new", {}, timeout=10)
    assert raised.value.retry_class == "rate-limit" == conn.stderr_retry_class
    assert "RESOURCE_EXHAUSTED" not in str(raised.value)


def test_child_env_has_no_secrets_but_gets_explicit_mux_vars(connect, planted_secrets):
    conn = connect(mux_env={"ACP_MUX_AFFINITY": "conv-1", "ACP_MUX_AFFINITY_PIN": "1"})
    info = dump(conn)
    for name in (*planted_secrets, "HERMES_HOME", "HERMES_REAL_HOME"):
        assert name not in info["env_names"], name
    assert info["mux"] == {"ACP_MUX_AFFINITY": "conv-1", "ACP_MUX_AFFINITY_PIN": "1"}
    assert info["cwd"] == conn.cwd


def test_explicit_profile_and_gemini_home_without_mutating_os_environ(connect, monkeypatch, tmp_path):
    """SEC-4: AcpConnection receives profile_home/gemini_home/force_file_storage explicitly."""
    orig_home = os.environ.get("HOME")
    monkeypatch.delenv("GEMINI_HOME", raising=False)
    monkeypatch.delenv("AGY_ACP_FORCE_FILE_STORAGE", raising=False)
    prof = tmp_path / "isolated-home"
    prof.mkdir()
    gem = prof / ".gemini"
    conn = connect(profile_home=str(prof), gemini_home=str(gem), force_file_storage=True)
    info = dump(conn)
    assert info["env_selected"]["HOME"] == str(prof)
    assert info["env_selected"]["GEMINI_HOME"] == str(gem)
    assert info["env_selected"]["AGY_ACP_FORCE_FILE_STORAGE"] == "1"
    assert os.environ.get("HOME") == orig_home
    assert "GEMINI_HOME" not in os.environ
    assert "AGY_ACP_FORCE_FILE_STORAGE" not in os.environ


def test_unlisted_mux_variable_is_refused():
    with pytest.raises(ValueError):
        AcpConnection("x", [], "/tmp", mux_env={"ACP_MUX_PAR": "/evil"})


def test_initialize_is_honest_and_unknown_agent_requests_get_32601(connect):
    conn = connect({"agent_request": "fs/read_text_file", "permission": None})
    sid = conn.request("session/new", {"cwd": conn.cwd, "mcpServers": []}, timeout=10)["sessionId"]
    conn.attach_session(sid, lambda u: None, lambda p: None)
    meta = conn.request("session/prompt", {"sessionId": sid, "prompt": []}, timeout=10)["_meta"]
    assert meta["agentRequestResponse"]["error"]["code"] == -32601
    init = dump(conn)["log"][0]["params"]
    assert init["clientInfo"]["name"] == "acp-gateway"
    assert init["clientCapabilities"] == {"fs": {"readTextFile": False, "writeTextFile": False}, "terminal": False}


def test_rpc_error_is_typed(connect):
    conn = connect()
    with pytest.raises(AcpRpcError) as raised:
        conn.request("x/error", {}, timeout=10)
    assert raised.value.code == -32000


def test_cancel_answers_pending_permissions_cancelled_then_notifies(connect):
    conn = connect({"permission": {"toolCall": {"toolCallId": "t1"}, "options": []}, "wait_cancel": True})
    sid = conn.request("session/new", {"cwd": conn.cwd, "mcpServers": []}, timeout=10)["sessionId"]
    seen = threading.Event()
    conn.attach_session(sid, lambda u: None, lambda p: seen.set())  # returns None: stays pending
    result = {}
    t = threading.Thread(target=lambda: result.update(conn.request("session/prompt", {"sessionId": sid, "prompt": []})))
    t.start()
    assert seen.wait(10)
    conn.cancel_session(sid)
    t.join(10)
    assert result["stopReason"] == "cancelled"
    log = dump(conn)["log"]
    answers = [m for m in log if m.get("id") == 900]
    assert answers[0]["result"] == {"outcome": {"outcome": "cancelled"}}
    methods = [m.get("method") for m in log]
    assert methods.index("session/cancel") > log.index(answers[0])


def test_close_reaps_the_child(connect):
    conn = connect()
    conn.close()
    assert conn._proc.poll() is not None


# ---- SEC-5 & SEC-11 hardening tests ------------------------------------------

def test_partial_terminal_handlers_rejected():
    """SEC-5: registering a subset of terminal/* handlers must fail closed."""
    with pytest.raises(ValueError, match="partial terminal/\\*"):
        AcpConnection("x", [], "/tmp", client_handlers={"terminal/create": lambda p: {}})


def test_client_capabilities_override_for_fs_or_terminal_rejected():
    """SEC-5: fs and terminal capabilities are derived strictly from client_handlers."""
    with pytest.raises(ValueError, match="fs and terminal capabilities"):
        AcpConnection("x", [], "/tmp", client_capabilities={"fs": {"readTextFile": True}})
    with pytest.raises(ValueError, match="fs and terminal capabilities"):
        AcpConnection("x", [], "/tmp", client_capabilities={"terminal": True})
    # Non-fs/non-terminal override is permitted and preserves derived fs/terminal
    conn = AcpConnection("x", [], "/tmp", client_capabilities={"elicitation": {"form": {}}})
    caps = conn._build_client_capabilities()
    assert caps["elicitation"] == {"form": {}}
    assert caps["fs"] == {"readTextFile": False, "writeTextFile": False}
    assert caps["terminal"] is False


def test_session_scoped_client_handlers_require_active_session_id(tmp_path):
    """SEC-5: fs/*, terminal/*, elicitation/*, or any request with sessionId must match an active session."""
    log = tmp_path / "agy.log"
    behaviour = {
        "log": str(log),
        "script": [[
            # Missing sessionId on fs/read_text_file -> -32002
            {"client_req": {"method": "fs/read_text_file", "params": {"path": "/a"}, "omit_session_id": True}},
            # Unknown sessionId -> -32002 with data.sessionId
            {"client_req": {"method": "fs/read_text_file", "params": {"sessionId": "bogus", "path": "/a"}}},
            # Non-string sessionId -> -32002
            {"client_req": {"method": "terminal/create", "params": {"sessionId": 123, "command": "echo"}}},
            # Custom method with unknown sessionId in params -> -32002
            {"client_req": {"method": "x/custom", "params": {"sessionId": "unknown"}}},
            # Valid active sessionId -> succeeds
            {"client_req": {"method": "fs/read_text_file", "params": {"path": "/ok"}}},
            {"text": "done"},
        ]],
    }
    handlers = {
        "fs/read_text_file": lambda p: {"content": "ok"},
        "terminal/create": lambda p: {"terminalId": "t1"},
        "terminal/output": lambda p: {"output": "", "truncated": False},
        "terminal/wait_for_exit": lambda p: {"exitCode": 0},
        "terminal/kill": lambda p: {},
        "terminal/release": lambda p: {},
        "x/custom": lambda p: {"ok": True},
    }
    conn = AcpConnection(sys.executable, [FAKE_AGY, json.dumps(behaviour)], str(tmp_path), client_handlers=handlers)
    try:
        conn.start()
        conn.initialize()
        sess = new_session(conn, mcp_server={"name": "m", "type": "http", "url": "http://127.0.0.1:1/m"},
                           gate=PermissionGate("m", frozenset()))
        assert sess.prompt("go", timeout=15.0).stop_reason == "end_turn"
        resps = [e["resp"] for e in _events(log) if e["ev"] == "client_resp"]
        assert resps[0]["error"]["code"] == -32002 and resps[0]["error"]["data"] == {"sessionId": None}
        assert resps[1]["error"]["code"] == -32002 and resps[1]["error"]["data"] == {"sessionId": "bogus"}
        assert resps[2]["error"]["code"] == -32002 and resps[2]["error"]["data"] == {"sessionId": 123}
        assert resps[3]["error"]["code"] == -32002 and resps[3]["error"]["data"] == {"sessionId": "unknown"}
        assert resps[4]["result"] == {"content": "ok"}
    finally:
        conn.close()


def test_invalid_unhashable_rpc_ids_and_malformed_frames_do_not_crash_reader(connect):
    """SEC-5: unhashable/bool JSON-RPC ids in responses, requests, and $/cancel_request never kill _read_stdout."""
    bad_frames = [
        {"jsonrpc": "2.0", "id": {"bad": 1}, "result": {}},
        {"jsonrpc": "2.0", "id": [1, 2], "method": "fs/read_text_file", "params": {}},
        {"jsonrpc": "2.0", "id": True, "method": "fs/read_text_file", "params": {}},
        {"jsonrpc": "2.0", "id": False, "result": {}},
        {"jsonrpc": "2.0", "method": "$/cancel_request", "params": {"requestId": {"unhashable": 1}}},
        {"jsonrpc": "2.0", "method": "$/cancel_request", "params": {"requestId": True}},
        {"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": ["bad"], "update": {}}},
    ]
    conn = connect({"raw_frames_on_prompt": bad_frames})
    sid = conn.request("session/new", {"cwd": conn.cwd, "mcpServers": []}, timeout=10)["sessionId"]
    conn.attach_session(sid, lambda u: None, lambda p: None)
    res = conn.request("session/prompt", {"sessionId": sid, "prompt": []}, timeout=10)
    assert res["stopReason"] == "end_turn"
    assert not conn.exited
    # Subsequent RPC still works cleanly
    assert dump(conn)["cwd"] == conn.cwd


def test_duplicate_inflight_request_id_rejected_with_32600(tmp_path):
    """SEC-5: duplicate in-flight request_id returns JSON-RPC -32600."""
    log = tmp_path / "agy.log"
    entered = threading.Event()
    release = threading.Event()

    def slow_read(p):
        entered.set()
        release.wait(5.0)
        return {"content": "done"}

    behaviour = {
        "log": str(log),
        "script": [[
            {"client_reqs_parallel": [
                {"method": "fs/read_text_file", "rid": "dup-1", "params": {"path": "/a"}, "stagger": 0.15},
                {"method": "fs/read_text_file", "rid": "dup-1", "params": {"path": "/b"}},
            ]},
            {"text": "ok"},
        ]],
    }
    conn = AcpConnection(sys.executable, [FAKE_AGY, json.dumps(behaviour)], str(tmp_path),
                         client_handlers={"fs/read_text_file": slow_read})
    try:
        conn.start()
        conn.initialize()
        sess = new_session(conn, mcp_server={"name": "m", "type": "http", "url": "http://127.0.0.1:1/m"},
                           gate=PermissionGate("m", frozenset()))
        th = threading.Thread(target=lambda: (entered.wait(5.0), time.sleep(0.35), release.set()), daemon=True)
        th.start()
        assert sess.prompt("go", timeout=15.0).stop_reason == "end_turn"
        resps = [e["resp"] for e in _events(log) if e["ev"] == "client_resp"]
        errors = [r for r in resps if r and "error" in r]
        assert any(r["error"]["code"] == -32600 for r in errors)
    finally:
        release.set()
        conn.close()


def test_bounded_client_handler_pool_rejects_excess_with_32001(tmp_path):
    """SEC-11: bounded ThreadPoolExecutor(16); 17th concurrent request immediately gets -32001."""
    log = tmp_path / "agy.log"
    release = threading.Event()
    count_lock = threading.Lock()
    active_seen = 0
    all_16_running = threading.Event()

    def block_handler(params, cancel_event):
        nonlocal active_seen
        with count_lock:
            active_seen += 1
            if active_seen >= 16:
                all_16_running.set()
        while not release.is_set() and not cancel_event.is_set():
            release.wait(0.05)
        return {"content": "ok"}

    reqs = [{"method": "fs/read_text_file", "rid": f"r-{i}", "params": {"path": f"/{i}"}} for i in range(16)]
    reqs[-1]["stagger"] = 0.25
    reqs.append({"method": "fs/read_text_file", "rid": "r-overflow", "params": {"path": "/17"}})
    behaviour = {"log": str(log), "script": [[{"client_reqs_parallel": reqs}, {"text": "done"}]]}
    conn = AcpConnection(sys.executable, [FAKE_AGY, json.dumps(behaviour)], str(tmp_path),
                         client_handlers={"fs/read_text_file": block_handler})
    try:
        conn.start()
        conn.initialize()
        sess = new_session(conn, mcp_server={"name": "m", "type": "http", "url": "http://127.0.0.1:1/m"},
                           gate=PermissionGate("m", frozenset()))
        releaser = threading.Thread(target=lambda: (all_16_running.wait(5.0), time.sleep(0.4), release.set()),
                                    daemon=True)
        releaser.start()
        assert sess.prompt("go", timeout=15.0).stop_reason == "end_turn"
        resps = {e["rid"]: e["resp"] for e in _events(log) if e["ev"] == "client_resp"}
        assert resps["r-overflow"]["error"]["code"] == -32001
        assert sum(1 for k, r in resps.items() if k != "r-overflow" and r and "result" in r) == 16
    finally:
        release.set()
        conn.close()


def test_cancel_event_propagates_on_detach_and_close(tmp_path):
    """SEC-5/SEC-11: cancel_event passed to 2-arg/kwarg handlers and set on detach_session/close."""
    for action in ("detach", "close"):
        started = threading.Event()
        saw_cancel = threading.Event()

        def kw_handler(params, *, cancel_event, _started=started, _saw=saw_cancel):
            _started.set()
            if cancel_event.wait(5.0):
                _saw.set()
            return {"content": "late"}

        log = tmp_path / f"agy-{action}.log"
        behaviour = {
            "log": str(log),
            "script": [[
                {"client_req": {"method": "fs/read_text_file", "rid": "c1", "params": {"path": "/a"}}},
                {"text": "done"},
            ]],
        }
        conn = AcpConnection(sys.executable, [FAKE_AGY, json.dumps(behaviour)], str(tmp_path),
                             client_handlers={"fs/read_text_file": kw_handler})
        th = None
        try:
            conn.start()
            conn.initialize()
            sess = new_session(conn, mcp_server={"name": "m", "type": "http", "url": "http://127.0.0.1:1/m"},
                               gate=PermissionGate("m", frozenset()))

            def run_prompt(_sess=sess):
                with contextlib.suppress(AcpProcessExit, TimeoutError):
                    _sess.prompt("go", timeout=10.0)

            th = threading.Thread(target=run_prompt, daemon=True)
            th.start()
            assert started.wait(5.0)
            if action == "detach":
                conn.detach_session(sess.session_id)
            else:
                conn.close()
            assert saw_cancel.wait(5.0)
        finally:
            conn.close()
            if th is not None:
                th.join(5.0)


def test_respond_permission_is_race_free_against_cancel_request(connect):
    """SEC-5: respond_permission returns False if $/cancel_request already cancelled the permission."""
    conn = connect({
        "permission": {"toolCall": {"toolCallId": "t1"}, "options": [{"optionId": "ao", "kind": "allow_once"}]},
        "cancel_perm_after": 0.15,
    })
    sid = conn.request("session/new", {"cwd": conn.cwd, "mcpServers": []}, timeout=10)["sessionId"]
    seen = threading.Event()
    conn.attach_session(sid, lambda u: None, lambda p: (seen.set(), None)[1])
    res = conn.request("session/prompt", {"sessionId": sid, "prompt": []}, timeout=10)
    assert seen.is_set()
    # $/cancel_request already answered id 900 with cancelled
    assert res["_meta"]["permissionResponse"]["result"] == {"outcome": {"outcome": "cancelled"}}
    assert conn.respond_permission(900, {"outcome": {"outcome": "selected", "optionId": "ao"}}) is False


def test_respond_permission_succeeds_once_when_pending(connect):
    """SEC-5: respond_permission atomically answers once and returns False on a second attempt."""
    conn = connect({
        "permission": {"toolCall": {"toolCallId": "t1"}, "options": [{"optionId": "ao", "kind": "allow_once"}]},
    })
    sid = conn.request("session/new", {"cwd": conn.cwd, "mcpServers": []}, timeout=10)["sessionId"]
    seen = threading.Event()
    conn.attach_session(sid, lambda u: None, lambda p: (seen.set(), None)[1])
    out = {}
    t = threading.Thread(
        target=lambda: out.update(conn.request("session/prompt", {"sessionId": sid, "prompt": []}, timeout=10))
    )
    t.start()
    assert seen.wait(5.0)
    outcome = {"outcome": {"outcome": "selected", "optionId": "ao"}}
    assert conn.respond_permission(900, outcome) is True
    assert conn.respond_permission(900, outcome) is False
    t.join(10.0)
    assert out["_meta"]["permissionResponse"]["result"] == outcome


def test_oversized_stdout_frame_closes_connection_cleanly(connect, monkeypatch):
    """SEC-11: single stdout line > MAX_FRAME_BYTES aborts cleanly without OOM."""
    monkeypatch.setattr(acp_connection, "MAX_FRAME_BYTES", 1024)
    conn = connect({"oversized_frame_bytes": 4096})
    sid = conn.request("session/new", {"cwd": conn.cwd, "mcpServers": []}, timeout=10)["sessionId"]
    conn.attach_session(sid, lambda u: None, lambda p: None)
    with pytest.raises(AcpProcessExit):
        conn.request("session/prompt", {"sessionId": sid, "prompt": []}, timeout=10)
    assert conn.exited


def test_unattached_updates_buffer_is_strictly_capped():
    """SEC-11: unattached self._updates bounded at 64 sessions and 1024 total updates."""
    conn = AcpConnection("x", [], "/tmp")
    # Flood 100 distinct sessions with 20 updates each (2000 total)
    for s in range(100):
        for i in range(20):
            conn._handle_update({"sessionId": f"s-{s}", "update": {"seq": i}})
    assert len(conn._updates) <= MAX_UNATTACHED_SESSIONS
    total = sum(len(q) for q in conn._updates.values())
    assert total == conn._unattached_update_count <= MAX_UNATTACHED_UPDATES
    # Newest session retained
    assert "s-99" in conn._updates
    # Attaching decrements total cleanly
    got = []
    conn.attach_session("s-99", got.append, lambda p: None)
    assert len(got) == 20
    assert conn._unattached_update_count == sum(len(q) for q in conn._updates.values())
