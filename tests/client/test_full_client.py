"""End-to-end tests for FullAcpClient, FullAcpSession, and Mode B CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from acp_gateway.client import FullAcpClient, PolicyPermissionGate
from acp_gateway.client.__main__ import main as cli_main
from acp_gateway.core.acp_connection import AcpError, AcpRpcError

FAKE_AGENT = str(Path(__file__).with_name("fake_full_agent.py"))


def test_capability_derivation_and_protocol_version_validation(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()

    # Default FullAcpClient advertises all fs/* and terminal capabilities as False (SEC-5)
    with FullAcpClient(sys.executable, [FAKE_AGENT, json.dumps({})], workspace_roots=[ws]) as client:
        log = client.conn.request("x/dump", {}, timeout=10.0)["log"]
        init_caps = log[0]["params"]["clientCapabilities"]
        assert init_caps == {
            "fs": {"readTextFile": False, "writeTextFile": False},
            "terminal": False,
        }

    # Enabling read + write + terminal advertises exact corresponding capabilities
    with FullAcpClient(
        sys.executable,
        [FAKE_AGENT, json.dumps({})],
        workspace_roots=[ws],
        enable_fs_read=True,
        enable_fs_write=True,
        enable_terminal=True,
    ) as client:
        log = client.conn.request("x/dump", {}, timeout=10.0)["log"]
        init_caps = log[0]["params"]["clientCapabilities"]
        assert init_caps == {
            "fs": {"readTextFile": True, "writeTextFile": True},
            "terminal": True,
        }

    # Protocol version mismatch rejected and child reaped
    for bad_ver in (2, "1", True, None):
        client = FullAcpClient(
            sys.executable,
            [FAKE_AGENT, json.dumps({"protocol_version": bad_ver})],
            workspace_roots=[ws],
        )
        with pytest.raises(AcpError, match="protocolVersion"):
            client.start(timeout=10.0)
        assert client.conn._proc is not None and client.conn._proc.poll() is not None


def test_end_to_end_fs_terminal_and_permission_flow(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    real_ws = os.path.realpath(ws)
    target = os.path.join(real_ws, "notes.txt")

    behaviour = {
        "agent_capabilities": {
            "sessionCapabilities": {"close": {}},
        },
        "prompt_steps": [
            {
                "kind": "client_req",
                "method": "fs/write_text_file",
                "params": {"path": target, "content": "alpha\nbeta\n"},
            },
            {
                "kind": "client_req",
                "method": "fs/read_text_file",
                "params": {"path": target, "line": 2, "limit": 1},
            },
            {
                "kind": "client_req",
                "method": "terminal/create",
                "params": {
                    "command": sys.executable,
                    "args": ["-c", "print('hello-from-term')"],
                },
                "save_terminal_id": "tid",
            },
            {
                "kind": "client_req",
                "method": "terminal/wait_for_exit",
                "params": {"terminalId": "$tid"},
            },
            {
                "kind": "client_req",
                "method": "terminal/output",
                "params": {"terminalId": "$tid"},
            },
            {
                "kind": "client_req",
                "method": "terminal/release",
                "params": {"terminalId": "$tid"},
            },
            {
                "kind": "permission",
                "params": {
                    "toolCall": {"toolCallId": "tc1", "title": "run"},
                    "options": [
                        {"optionId": "ao", "name": "Allow", "kind": "allow_once"},
                        {"optionId": "ro", "name": "Reject", "kind": "reject_once"},
                    ],
                },
            },
            {
                "kind": "permission",
                "params": {
                    "options": [{"optionId": "bad", "name": "Bad", "kind": "not_a_real_kind"}]
                },
            },
            {"kind": "text", "text": "all-done"},
        ],
    }
    gate = PolicyPermissionGate(
        allow_fs_read=True,
        allow_fs_write=True,
        allow_terminal=True,
        allow_agent_permissions=False,
    )
    with FullAcpClient(
        sys.executable,
        [FAKE_AGENT, json.dumps(behaviour)],
        workspace_roots=[ws],
        gate=gate,
        enable_fs_read=True,
        enable_fs_write=True,
        enable_terminal=True,
    ) as client:
        with client.new_session() as sess:
            res = sess.prompt("execute flow", timeout=15.0)
            assert res.stop_reason == "end_turn"
            assert res.finish_reason == "stop"
            results = res.result["_meta"]["results"]
            assert results[0]["resp"]["result"] == {}
            assert results[1]["resp"]["result"] == {"content": "beta\n"}
            assert results[2]["resp"]["result"]["terminalId"].startswith("term-")
            assert results[3]["resp"]["result"] == {"exitCode": 0, "signal": None}
            assert results[4]["resp"]["result"]["output"].strip() == "hello-from-term"
            assert results[5]["resp"]["result"] == {}
            # PolicyPermissionGate denied agent permission -> reject_once
            assert results[6]["resp"]["result"] == {
                "outcome": {"outcome": "selected", "optionId": "ro"}
            }
            # Invalid permission kind -> -32602
            assert results[7]["resp"]["error"]["code"] == -32602

        # session/close was sent because agent advertised close capability
        log = client.conn.request("x/dump", {}, timeout=10.0)["log"]
        assert any(m.get("method") == "session/close" for m in log)


def test_session_load_replay_gating_and_error_cleanup(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()

    # 1. Refused when agent does not advertise loadSession
    with FullAcpClient(
        sys.executable,
        [FAKE_AGENT, json.dumps({"agent_capabilities": {"loadSession": False}})],
        workspace_roots=[ws],
    ) as client:
        with pytest.raises(AcpError, match="loadSession"):
            client.load_session("s-old")

    # 2. Captures replay updates emitted BEFORE session/load response in order
    replay_behaviour = {
        "agent_capabilities": {"loadSession": True},
        "load_replay_updates": [
            {"sessionUpdate": "user_message_chunk", "content": {"type": "text", "text": "past-q"}},
            {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "past-a"}},
        ],
        "config_options": [{"id": "mode", "category": "mode", "currentValue": "ask"}],
    }
    with FullAcpClient(
        sys.executable,
        [FAKE_AGENT, json.dumps(replay_behaviour)],
        workspace_roots=[ws],
    ) as client:
        sess = client.load_session("s-replayed")
        assert [u["content"]["text"] for u in sess.replay_updates] == ["past-q", "past-a"]
        assert sess.uses_config_options is True
        sess.close()

    # 3. Error during session/load detaches cleanly so session is not left attached
    err_behaviour = {
        "agent_capabilities": {"loadSession": True},
        "load_replay_updates": [
            {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "partial"}}
        ],
        "load_error": {"code": -32002, "message": "Session not found"},
    }
    with FullAcpClient(
        sys.executable,
        [FAKE_AGENT, json.dumps(err_behaviour)],
        workspace_roots=[ws],
    ) as client:
        with pytest.raises(AcpRpcError) as exc:
            client.load_session("s-missing")
        assert exc.value.code == -32002
        assert "s-missing" not in client.conn._sessions


def test_capability_gating_and_config_options_superseding_modes(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    extra = tmp_path / "extra"
    extra.mkdir()

    # Without capabilities advertised, resume/list/delete/additionalDirectories/http MCP are refused
    with FullAcpClient(
        sys.executable,
        [FAKE_AGENT, json.dumps({"agent_capabilities": {}})],
        workspace_roots=[ws],
    ) as client:
        with pytest.raises(AcpError, match="session/resume"):
            client.resume_session("s1")
        with pytest.raises(AcpError, match="session/list"):
            client.list_sessions()
        with pytest.raises(AcpError, match="session/delete"):
            client.delete_session("s1")
        with pytest.raises(AcpError, match="additionalDirectories"):
            client.new_session(additional_directories=[extra])
        with pytest.raises(AcpError, match="HTTP MCP"):
            client.new_session(mcp_servers=[{"name": "m", "type": "http", "url": "http://127.0.0.1:9/m"}])

        # session/close is NOT sent when unsupported
        sess = client.new_session()
        sess.close()
        log = client.conn.request("x/dump", {}, timeout=10.0)["log"]
        assert not any(m.get("method") == "session/close" for m in log)

    # With configOptions + modes present, set_mode prefers session/set_config_option over legacy session/set_mode
    beh_both = {
        "agent_capabilities": {
            "mcpCapabilities": {"http": True},
            "sessionCapabilities": {
                "resume": {},
                "list": {},
                "delete": {},
                "additionalDirectories": {},
            },
        },
        "config_options": [
            {
                "id": "mode",
                "category": "mode",
                "currentValue": "ask",
                "options": [{"value": "ask"}, {"value": "code"}],
            }
        ],
        "modes": {"currentModeId": "ask", "availableModes": [{"id": "ask"}, {"id": "code"}]},
        "sessions_list": [{"sessionId": "s-1"}],
    }
    with FullAcpClient(
        sys.executable,
        [FAKE_AGENT, json.dumps(beh_both)],
        workspace_roots=[ws],
    ) as client:
        assert client.list_sessions()["sessions"] == [{"sessionId": "s-1"}]
        sess = client.new_session(
            additional_directories=[extra],
            mcp_servers=[{"name": "m", "type": "http", "url": "http://127.0.0.1:9/m"}],
        )
        sess.set_mode("code")
        resumed = client.resume_session("s-resumed")
        resumed.close()
        client.delete_session("s-resumed")

        log = client.conn.request("x/dump", {}, timeout=10.0)["log"]
        methods = [m.get("method") for m in log]
        assert "session/set_config_option" in methods
        assert "session/set_mode" not in methods
        assert "session/resume" in methods
        assert "session/delete" in methods

    # Legacy fallback: when configOptions has no mode option, set_mode falls back to session/set_mode
    beh_legacy = {
        "modes": {"currentModeId": "ask", "availableModes": [{"id": "ask"}, {"id": "architect"}]},
    }
    with FullAcpClient(
        sys.executable,
        [FAKE_AGENT, json.dumps(beh_legacy)],
        workspace_roots=[ws],
    ) as client:
        sess = client.new_session()
        assert sess.uses_config_options is False
        sess.set_mode("architect")
        assert sess.current_mode_id == "architect"
        log = client.conn.request("x/dump", {}, timeout=10.0)["log"]
        assert any(m.get("method") == "session/set_mode" for m in log)


def test_cancel_session_cancel_request_and_close_cleanup(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    pid_file = ws / "term.pid"

    # 1. $/cancel_request cancels in-flight terminal/wait_for_exit with -32800
    beh_cancel_req = {
        "prompt_steps": [
            {
                "kind": "client_req",
                "method": "terminal/create",
                "params": {
                    "command": sys.executable,
                    "args": [
                        "-c",
                        f"import os, pathlib, time; pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid())); time.sleep(30)",
                    ],
                },
                "save_terminal_id": "tid",
            },
            {
                "kind": "client_req",
                "method": "terminal/wait_for_exit",
                "params": {"terminalId": "$tid"},
                "cancel_after": 0.2,
            },
        ]
    }
    gate = PolicyPermissionGate(allow_terminal=True)
    client = FullAcpClient(
        sys.executable,
        [FAKE_AGENT, json.dumps(beh_cancel_req)],
        workspace_roots=[ws],
        gate=gate,
        enable_terminal=True,
    )
    try:
        client.start(timeout=10.0)
        sess = client.new_session()
        res = sess.prompt("wait then cancel", timeout=15.0)
        assert res.result["_meta"]["results"][1]["resp"]["error"]["code"] == -32800
        # Wait briefly for pid_file to appear, then close() must reap the unreleased terminal process
        deadline = time.monotonic() + 3.0
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert pid_file.exists()
        child_pid = int(pid_file.read_text(encoding="utf-8").strip())
    finally:
        client.close()

    dead = False
    for _ in range(40):
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            dead = True
            break
        time.sleep(0.05)
    assert dead, "close() did not reap active terminal process"

    # 2. session/cancel cancels an active prompt turn
    beh_wait_cancel = {"prompt_steps": [{"kind": "wait_cancel"}]}
    with FullAcpClient(
        sys.executable,
        [FAKE_AGENT, json.dumps(beh_wait_cancel)],
        workspace_roots=[ws],
    ) as client2:
        sess2 = client2.new_session()
        got: list = []
        th = threading.Thread(target=lambda: got.append(sess2.prompt("hang", timeout=10.0)))
        th.start()
        time.sleep(0.15)
        sess2.cancel()
        th.join(10.0)
        assert got[0].stop_reason == "cancelled"
        assert got[0].finish_reason == "cancelled"


def test_cli_probe_only_and_sanitized_prompt_output(tmp_path: Path, capsys):
    ws = tmp_path / "ws"
    ws.mkdir()

    # Probe-only via direct main() sanitizes ANSI/BiDi in agentInfo and defaults to fail-closed caps
    beh_probe = {
        "agent_info": {"name": "\x1b[31mfake\x1b[0m\u202eagent", "version": "1.0"},
        "agent_capabilities": {"loadSession": True},
        "auth_methods": [{"id": "none", "name": "None"}],
    }
    rc = cli_main(
        [
            "--command",
            sys.executable,
            "--arg",
            FAKE_AGENT,
            "--arg",
            json.dumps(beh_probe),
            "--workspace",
            str(ws),
            "--non-interactive",
            "--probe-only",
        ]
    )
    assert rc == 0
    probe_out = json.loads(capsys.readouterr().out)
    assert probe_out["protocolVersion"] == 1
    assert probe_out["agentInfo"]["name"] == "fakeagent"
    assert probe_out["clientCapabilities"] == {
        "fs": {"readTextFile": False, "writeTextFile": False},
        "terminal": False,
    }

    # Subprocess execution via `python -m acp_gateway.client --prompt` sanitizes streamed text
    beh_prompt = {"prompt_steps": [{"kind": "text", "text": "\x1b[32mhello\x1b[0m\u202eworld"}]}
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src")}
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "acp_gateway.client",
            "--command",
            sys.executable,
            "--arg",
            FAKE_AGENT,
            "--arg",
            json.dumps(beh_prompt),
            "--workspace",
            str(ws),
            "--non-interactive",
            "--prompt",
            "hi",
        ],
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
    assert proc.stdout.strip() == "helloworld"
