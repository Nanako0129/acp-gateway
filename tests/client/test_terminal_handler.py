"""Unit and adversarial security tests for WorkspaceTerminalHandler (SEC-1, SEC-3, SEC-8)."""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

from acp_gateway.client.permission_policy import PolicyPermissionGate
from acp_gateway.client.terminal_handler import WorkspaceTerminalHandler
from acp_gateway.core.acp_connection import AcpRpcError


def _allow_term_gate(*, allowed_commands: set[str] | None = None) -> PolicyPermissionGate:
    return PolicyPermissionGate(allow_terminal=True, allowed_commands=allowed_commands)


def test_terminal_lifecycle_and_private_tmpdir_cleanup(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()

    with WorkspaceTerminalHandler([ws], _allow_term_gate()) as term:
        created = term.create(
            {
                "sessionId": "s1",
                "command": sys.executable,
                "args": [
                    "-c",
                    "import json, os, stat; d=os.environ['TMPDIR']; "
                    "print(json.dumps({'cwd': os.getcwd(), 'tmpdir': d, "
                    "'mode': stat.S_IMODE(os.stat(d).st_mode)}))",
                ],
                "env": [{"name": "CUSTOM_APP_FLAG", "value": "enabled"}],
            }
        )
        tid = created["terminalId"]
        assert tid.startswith("term-") and len(tid) >= 20

        exited = term.wait_for_exit({"sessionId": "s1", "terminalId": tid})
        assert exited == {"exitCode": 0, "signal": None}

        out = term.output({"sessionId": "s1", "terminalId": tid})
        assert out["truncated"] is False
        assert out["exitStatus"] == {"exitCode": 0, "signal": None}
        info = json.loads(out["output"].strip())
        assert info["cwd"] == os.path.realpath(ws)
        assert info["mode"] == 0o700
        tmp_dir = Path(info["tmpdir"])
        assert tmp_dir.is_dir()

        assert term.release({"sessionId": "s1", "terminalId": tid}) == {}
        assert not tmp_dir.exists()

        # Accessing after release -> -32002 with data.terminalId
        with pytest.raises(AcpRpcError) as exc:
            term.output({"sessionId": "s1", "terminalId": tid})
        assert exc.value.code == -32002
        assert exc.value.data == {"terminalId": tid}


def test_ambient_secrets_never_inherited_and_safe_env_passed(tmp_path: Path, monkeypatch):
    """SEC-3: zero ambient os.environ inheritance."""
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "planted-aws-secret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "planted-anthropic-key")
    monkeypatch.setenv("GEMINI_API_KEY", "planted-gemini-key")
    monkeypatch.setenv("HOME", "/tmp/planted-ambient-home")

    with WorkspaceTerminalHandler([ws], _allow_term_gate()) as term:
        tid = term.create(
            {
                "sessionId": "s1",
                "command": sys.executable,
                "args": ["-c", "import json, os; print(json.dumps(dict(os.environ)))"],
                "env": [{"name": "SAFE_VAR", "value": "ok123"}],
            }
        )["terminalId"]
        assert term.wait_for_exit({"sessionId": "s1", "terminalId": tid})["exitCode"] == 0
        env = json.loads(term.output({"sessionId": "s1", "terminalId": tid})["output"].strip())
        for secret_name in ("AWS_SECRET_ACCESS_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "HOME"):
            assert secret_name not in env, f"{secret_name} leaked into terminal child"
        assert env["SAFE_VAR"] == "ok123"
        assert env["NO_COLOR"] == "1"
        assert env["TERM"] == "dumb"
        term.release({"sessionId": "s1", "terminalId": tid})


def test_dangerous_agent_env_vars_rejected_with_32602(tmp_path: Path):
    """SEC-3: dangerous env vars rejected case-insensitively before spawning."""
    ws = tmp_path / "ws"
    ws.mkdir()

    blocked_names = [
        "DYLD_INSERT_LIBRARIES",
        "dyld_framework_path",
        "LD_PRELOAD",
        "ld_library_path",
        "BASH_ENV",
        "ENV",
        "ZDOTDIR",
        "PROMPT_COMMAND",
        "IFS",
        "PYTHONPATH",
        "pythonstartup",
        "NODE_OPTIONS",
        "PERL5OPT",
        "PERL5LIB",
        "RUBYOPT",
        "RUBYLIB",
        "GIT_SSH_COMMAND",
        "GIT_EXEC_PATH",
        "GIT_TEMPLATE_DIR",
        "GIT_CONFIG_PARAMETERS",
        "git_config_global",
        "PATH",
        "HOME",
        "SHELL",
        "CLASSPATH",
        "JAVA_TOOL_OPTIONS",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "",
        "BAD=NAME",
        "BAD\x00NAME",
    ]
    with WorkspaceTerminalHandler([ws], _allow_term_gate()) as term:
        for name in blocked_names:
            with pytest.raises(AcpRpcError) as exc:
                term.create(
                    {
                        "sessionId": "s1",
                        "command": sys.executable,
                        "args": ["-c", "pass"],
                        "env": [{"name": name, "value": "evil"}],
                    }
                )
            assert exc.value.code == -32602, f"expected -32602 for env {name!r}"


def test_cwd_validation_rejects_outside_and_symlink_and_symlink_parent(tmp_path: Path):
    """SEC-3: outside-root, symlink cwd, and symlink parent dir in cwd -> -32002 on macOS."""
    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_sub = outside / "deep"
    outside_sub.mkdir()

    sym_cwd = ws / "sym_cwd"
    os.symlink(outside, sym_cwd)
    real_ws = os.path.realpath(ws)

    with WorkspaceTerminalHandler([ws], _allow_term_gate()) as term:
        # Outside canonical root -> -32002
        with pytest.raises(AcpRpcError) as exc:
            term.create({"sessionId": "s1", "command": sys.executable, "cwd": os.path.realpath(outside)})
        assert exc.value.code == -32002

        # Direct symlink cwd -> -32002
        with pytest.raises(AcpRpcError) as exc:
            term.create(
                {"sessionId": "s1", "command": sys.executable, "cwd": os.path.join(real_ws, "sym_cwd")}
            )
        assert exc.value.code == -32002

        # Symlink parent dir inside cwd -> -32002 (explicit macOS ENOTDIR check)
        with pytest.raises(AcpRpcError) as exc:
            term.create(
                {
                    "sessionId": "s1",
                    "command": sys.executable,
                    "cwd": os.path.join(real_ws, "sym_cwd", "deep"),
                }
            )
        assert exc.value.code == -32002

        # Relative and traversal cwd -> -32602
        for bad_cwd in ("sub", f"{real_ws}/../outside", f"{real_ws}/./sub", f"{real_ws}/bad\x00dir"):
            with pytest.raises(AcpRpcError) as exc:
                term.create({"sessionId": "s1", "command": sys.executable, "cwd": bad_cwd})
            assert exc.value.code == -32602


def test_shell_false_treats_metacharacters_as_literal_args(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    marker = ws / "must-not-exist"

    with WorkspaceTerminalHandler([ws], _allow_term_gate()) as term:
        literal = f"hello; touch {marker}; $(echo pwn) `id`"
        tid = term.create(
            {
                "sessionId": "s1",
                "command": sys.executable,
                "args": ["-c", "import sys; print(sys.argv[1])", literal],
            }
        )["terminalId"]
        assert term.wait_for_exit({"sessionId": "s1", "terminalId": tid})["exitCode"] == 0
        out = term.output({"sessionId": "s1", "terminalId": tid})["output"].strip()
        assert out == literal
        assert not marker.exists()


def test_output_byte_limit_multibyte_utf8_truncation(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()

    with WorkspaceTerminalHandler([ws], _allow_term_gate()) as term:
        # 4-byte UTF-8 character repeated many times with a non-multiple-of-4 byte limit (25 bytes)
        tid = term.create(
            {
                "sessionId": "s1",
                "command": sys.executable,
                "args": ["-c", "import sys; sys.stdout.buffer.write(('😀' * 500).encode('utf-8'))"],
                "outputByteLimit": 25,
            }
        )["terminalId"]
        assert term.wait_for_exit({"sessionId": "s1", "terminalId": tid})["exitCode"] == 0
        out = term.output({"sessionId": "s1", "terminalId": tid})
        assert out["truncated"] is True
        assert "\ufffd" not in out["output"]
        encoded = out["output"].encode("utf-8")
        assert len(encoded) <= 25
        assert out["output"] == "😀" * 6  # 24 bytes (leading split continuation bytes cleanly skipped)


def test_killpg_reaps_grandchild_and_keeps_output_until_release(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    pid_file = ws / "grandchild.pid"

    child_code = (
        "import pathlib, subprocess, sys, time; "
        f"p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
        f"pathlib.Path({str(pid_file)!r}).write_text(str(p.pid)); "
        "print('child-started', flush=True); "
        "time.sleep(60)"
    )

    with WorkspaceTerminalHandler([ws], _allow_term_gate()) as term:
        tid = term.create(
            {"sessionId": "s1", "command": sys.executable, "args": ["-c", child_code]}
        )["terminalId"]
        deadline = time.monotonic() + 5.0
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert pid_file.exists()
        grandchild_pid = int(pid_file.read_text(encoding="utf-8").strip())

        # Kill terminates both child and grandchild process group
        assert term.kill({"sessionId": "s1", "terminalId": tid}) == {}
        exited = term.wait_for_exit({"sessionId": "s1", "terminalId": tid})
        assert exited["signal"] is not None

        # Output remains readable after kill until release
        out = term.output({"sessionId": "s1", "terminalId": tid})
        assert "child-started" in out["output"]
        assert out["exitStatus"]["signal"] is not None

        # Verify grandchild PID is dead
        dead = False
        for _ in range(40):
            try:
                os.kill(grandchild_pid, 0)
            except ProcessLookupError:
                dead = True
                break
            time.sleep(0.05)
        assert dead, f"grandchild pid {grandchild_pid} survived killpg"

        assert term.release({"sessionId": "s1", "terminalId": tid}) == {}


def test_max_terminals_watchdog_cross_session_cancel_and_gate_denial(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()

    # 1. Fail-closed gate denies terminal creation
    with WorkspaceTerminalHandler([ws], PolicyPermissionGate()) as denied_term:
        with pytest.raises(AcpRpcError) as exc:
            denied_term.create({"sessionId": "s1", "command": sys.executable, "args": ["-c", "pass"]})
        assert exc.value.code == -32001

    # 2. allowed_commands allowlist blocks unlisted commands
    with WorkspaceTerminalHandler([ws], _allow_term_gate(allowed_commands={"/bin/echo"})) as restricted:
        with pytest.raises(AcpRpcError) as exc:
            restricted.create({"sessionId": "s1", "command": sys.executable, "args": ["-c", "pass"]})
        assert exc.value.code == -32001

    # 3. max_terminals cap, cross-session denial, cancel_event unblocking wait_for_exit, release_session
    with WorkspaceTerminalHandler([ws], _allow_term_gate(), max_terminals=1) as term:
        tid = term.create(
            {"sessionId": "s1", "command": sys.executable, "args": ["-c", "import time; time.sleep(30)"]}
        )["terminalId"]

        # 2nd terminal exceeds cap -> -32001
        with pytest.raises(AcpRpcError) as exc:
            term.create({"sessionId": "s1", "command": sys.executable, "args": ["-c", "pass"]})
        assert exc.value.code == -32001

        # Cross-session access rejected with -32002 + data.terminalId
        for fn in (term.output, term.wait_for_exit, term.kill, term.release):
            with pytest.raises(AcpRpcError) as exc:
                fn({"sessionId": "s2", "terminalId": tid})
            assert exc.value.code == -32002
            assert exc.value.data == {"terminalId": tid}

        # cancel_event promptly unblocks wait_for_exit with -32800
        cancel = threading.Event()
        timer = threading.Timer(0.15, cancel.set)
        timer.start()
        t0 = time.monotonic()
        try:
            with pytest.raises(AcpRpcError) as exc:
                term.wait_for_exit({"sessionId": "s1", "terminalId": tid}, cancel_event=cancel)
            assert exc.value.code == -32800
            assert time.monotonic() - t0 < 1.5
        finally:
            timer.cancel()

        # release_session cleans up s1 terminals
        term.release_session("s1")
        with pytest.raises(AcpRpcError) as exc:
            term.output({"sessionId": "s1", "terminalId": tid})
        assert exc.value.code == -32002

    # 4. Watchdog timer automatically reaps runaway command
    with WorkspaceTerminalHandler([ws], _allow_term_gate(), max_runtime_seconds=0.25) as wd_term:
        tid = wd_term.create(
            {"sessionId": "s1", "command": sys.executable, "args": ["-c", "import time; time.sleep(30)"]}
        )["terminalId"]
        t0 = time.monotonic()
        exited = wd_term.wait_for_exit({"sessionId": "s1", "terminalId": tid})
        assert time.monotonic() - t0 < 3.0
        assert exited["signal"] is not None
        wd_term.close_all()
