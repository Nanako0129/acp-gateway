"""Permission policy, interactive gate, display sanitization, and Mode A/B isolation tests."""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from acp_gateway.client.permission_policy import (
    ActionRequest,
    InteractivePermissionGate,
    PolicyPermissionGate,
    sanitize_terminal_text,
    validate_permission_params,
)
from acp_gateway.core.acp_connection import CANCELLED_OUTCOME, AcpConnection, AcpRpcError

FAKE_FULL_AGENT = str(Path(__file__).with_name("fake_full_agent.py"))
SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "acp_gateway"


def _collect_imports(directory: Path) -> set[str]:
    imported: set[str] = set()
    for path in sorted(directory.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if node.level > 0:
                    # Resolve relative imports from package directory
                    rel_parts = path.relative_to(SRC_ROOT.parent).with_suffix("").parts
                    pkg_parts = rel_parts[:-node.level]
                    full = ".".join((*pkg_parts, mod)) if mod else ".".join(pkg_parts)
                else:
                    full = mod
                imported.add(full)
                for alias in node.names:
                    if alias.name != "*":
                        imported.add(f"{full}.{alias.name}" if full else alias.name)
    return imported


def test_mode_a_and_mode_b_ast_and_runtime_import_isolation():
    """Mode A (relay) never imports client; Mode B (client) never imports relay or core.permission."""
    relay_imports = _collect_imports(SRC_ROOT / "relay")
    client_imports = _collect_imports(SRC_ROOT / "client")

    assert not any(
        m == "acp_gateway.client" or m.startswith("acp_gateway.client.") for m in relay_imports
    ), f"Mode A imported Mode B: {sorted(relay_imports)}"

    forbidden_for_client = ("acp_gateway.relay", "acp_gateway.core.permission")
    for bad in forbidden_for_client:
        assert not any(
            m == bad or m.startswith(bad + ".") for m in client_imports
        ), f"Mode B imported forbidden module {bad}: {sorted(client_imports)}"

    # Runtime check in a fresh subprocess: importing acp_gateway.client loads neither relay nor core.permission
    env = {**os.environ, "PYTHONPATH": str(SRC_ROOT.parent)}
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import json, sys, acp_gateway.client, acp_gateway.client.__main__; "
            "print(json.dumps(sorted(m for m in sys.modules if m.startswith('acp_gateway'))))",
        ],
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
    loaded = set(json.loads(proc.stdout.strip()))
    assert "acp_gateway.relay" not in loaded
    assert "acp_gateway.core.permission" not in loaded
    assert not any(m.startswith("acp_gateway.relay.") for m in loaded)


def test_sanitize_terminal_text_strips_ansi_osc_dcs_ctrl_and_bidi():
    """SEC-8: CSI, OSC, DCS, ESC, unsafe C0/C1, and Unicode BiDi controls are stripped."""
    payload = (
        "\x1b[31;1mRED\x1b[0m"
        "\x1b]8;;https://evil.example\x07LINK\x1b]8;;\x07"
        "\x1b]0;WindowTitle\x1b\\"
        "\x1bP+q544e\x1b\\"
        "\x1b(B"
        "safe\revil"
        "\x00\x07\x08\x7f\x85\x9b31m"
        "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f\u061c"
        "\tkeep\nline2"
    )
    cleaned = sanitize_terminal_text(payload)
    assert cleaned == "REDLINKsafeevil\tkeep\nline2"
    # Unterminated OSC does not leak escape or payload
    assert sanitize_terminal_text("ok\x1b]0;unterminated") == "ok"


def test_validate_permission_params_rejects_malformed_and_invalid_kinds():
    """SEC-9: invalid option kind or malformed options -> AcpRpcError(-32602)."""
    bad_payloads = [
        None,
        {},
        {"options": []},
        {"options": "not-a-list"},
        {"options": ["not-a-dict"]},
        {"options": [{"optionId": "", "name": "Allow", "kind": "allow_once"}]},
        {"options": [{"optionId": "o1", "name": 123, "kind": "allow_once"}]},
        {"options": [{"optionId": "o1", "name": "Allow", "kind": "allow_all"}]},
        {"options": [{"optionId": "o1", "name": "Allow", "kind": "auto"}]},
        {"options": [{"optionId": "o1", "name": "Allow"}]},
    ]
    for bad in bad_payloads:
        with pytest.raises(AcpRpcError) as exc:
            validate_permission_params(bad)  # type: ignore[arg-type]
        assert exc.value.code == -32602

    valid = {
        "options": [
            {"optionId": "a1", "name": "Allow once", "kind": "allow_once"},
            {"optionId": "r1", "name": "Reject once", "kind": "reject_once"},
        ]
    }
    assert len(validate_permission_params(valid)) == 2


def test_policy_gate_fail_closed_defaults_no_title_allow_and_no_auto_allow_always():
    """SEC-1/SEC-9: fail-closed defaults, never matches title, never auto-selects allow_always."""
    gate = PolicyPermissionGate()
    assert gate.authorize_action(ActionRequest(kind="fs_read", session_id="s1", root="/w", relpath="a.txt")) is False
    assert gate.authorize_action(ActionRequest(kind="fs_write", session_id="s1", root="/w", relpath="a.txt")) is False
    assert gate.authorize_action(
        ActionRequest(kind="terminal_create", session_id="s1", command="/bin/echo")
    ) is False

    # Agent permission with reject_once offered -> selects reject_once even with spoofed title/name
    params = {
        "toolCall": {"toolCallId": "tc1", "title": "SAFE READONLY ALLOW_ONCE"},
        "options": [
            {"optionId": "ao", "name": "Always safe allow", "kind": "allow_once"},
            {"optionId": "ro", "name": "Reject", "kind": "reject_once"},
        ],
    }
    assert gate.decide_permission(params) == {"outcome": {"outcome": "selected", "optionId": "ro"}}

    # Without reject_once offered -> CANCELLED_OUTCOME
    params_no_reject = {
        "toolCall": {"toolCallId": "tc2", "title": "safe"},
        "options": [{"optionId": "aa", "name": "Allow always", "kind": "allow_always"}],
    }
    assert gate.decide_permission(params_no_reject) == CANCELLED_OUTCOME

    # Even with allow_agent_permissions=True (and allow_always_enabled=True), NEVER auto-selects allow_always
    permissive = PolicyPermissionGate(allow_agent_permissions=True, allow_always_enabled=True)
    params_only_always_and_reject = {
        "options": [
            {"optionId": "aa", "name": "Allow always", "kind": "allow_always"},
            {"optionId": "ro", "name": "Reject once", "kind": "reject_once"},
        ]
    }
    assert permissive.decide_permission(params_only_always_and_reject) == {
        "outcome": {"outcome": "selected", "optionId": "ro"}
    }

    # With allow_once offered and allow_agent_permissions=True -> picks allow_once
    assert permissive.decide_permission(params) == {"outcome": {"outcome": "selected", "optionId": "ao"}}

    # Callback trying to pick allow_always is blocked when allow_always_enabled=False
    cb_blocked = PolicyPermissionGate(
        allow_agent_permissions=True,
        allow_always_enabled=False,
        agent_permission_callback=lambda p, opts: "aa",
    )
    assert cb_blocked.decide_permission(params_only_always_and_reject) == {
        "outcome": {"outcome": "selected", "optionId": "ro"}
    }


def test_interactive_gate_action_prompt_sanitization_and_fail_closed():
    prompts: list[str] = []

    def capture_yes(text: str) -> str:
        prompts.append(text)
        return "y\n"

    with InteractivePermissionGate(prompt_fn=capture_yes) as gate:
        act = ActionRequest(
            kind="terminal_create",
            session_id="s1",
            command="echo",
            args=("\x1b[31mhi\x1b[0m", "safe\u202eevil"),
            cwd="/ws",
            env_keys=("FOO",),
        )
        assert gate.authorize_action(act) is True
        assert "\x1b[" not in prompts[-1]
        assert "\u202e" not in prompts[-1]
        assert "command: echo" in prompts[-1]
        assert "FOO" in prompts[-1]

        sens = ActionRequest(
            kind="fs_read",
            session_id="s1",
            root="/ws",
            relpath=".env",
            sensitive=True,
        )
        assert gate.authorize_action(sens) is True
        assert "SENSITIVE PATH" in prompts[-1]

        # Pre-cancelled event fails closed without prompting
        count_before = len(prompts)
        ev = threading.Event()
        ev.set()
        assert gate.authorize_action(sens, cancel_event=ev) is False
        assert len(prompts) == count_before

    # EOF / exception fails closed
    with InteractivePermissionGate(prompt_fn=lambda _: "") as eof_gate:
        assert eof_gate.authorize_action(sens) is False

    def boom(_: str) -> str:
        raise EOFError("closed")

    with InteractivePermissionGate(prompt_fn=boom) as err_gate:
        assert err_gate.authorize_action(sens) is False


def test_interactive_gate_async_permission_nonblocking_and_cancel_race(tmp_path: Path):
    """InteractivePermissionGate returns None immediately so stdout reader stays live & $/cancel_request wins."""
    # Case 1: Invalid option kind -> synchronous -32602 error
    beh_bad = {
        "prompt_steps": [
            {
                "kind": "permission",
                "id": 700,
                "params": {"options": [{"optionId": "x", "name": "Bad", "kind": "bogus_kind"}]},
            }
        ]
    }
    with InteractivePermissionGate(prompt_fn=lambda _: "1\n") as gate:
        conn = AcpConnection(sys.executable, [FAKE_FULL_AGENT, json.dumps(beh_bad)], str(tmp_path))
        try:
            conn.start()
            conn.initialize(timeout=10.0)
            sid = conn.request("session/new", {"cwd": conn.cwd, "mcpServers": []}, timeout=10.0)["sessionId"]
            conn.attach_session(sid, lambda u: None, gate.make_permission_handler(conn))
            res = conn.request("session/prompt", {"sessionId": sid, "prompt": []}, timeout=10.0)
            assert res["_meta"]["results"][0]["resp"]["error"]["code"] == -32602
        finally:
            conn.close()

    # Case 2: Non-blocking prompt receives live session/update while waiting, then resolves via respond_permission
    prompt_started = threading.Event()
    release_prompt = threading.Event()
    seen_updates: list[dict] = []
    captured_prompt: list[str] = []

    def slow_prompt(text: str) -> str:
        captured_prompt.append(text)
        prompt_started.set()
        release_prompt.wait(5.0)
        return "1\n"

    beh_live = {
        "prompt_steps": [
            {
                "kind": "permission",
                "id": 701,
                "emit_update_while_pending": "live-chunk-while-prompting",
                "params": {
                    "toolCall": {"toolCallId": "tc-1", "title": "\x1b[31mEvilTitle\x1b[0m"},
                    "options": [
                        {"optionId": "ao", "name": "Allow once", "kind": "allow_once"},
                        {"optionId": "ro", "name": "Reject once", "kind": "reject_once"},
                    ],
                },
            }
        ]
    }
    with InteractivePermissionGate(prompt_fn=slow_prompt) as gate:
        conn = AcpConnection(sys.executable, [FAKE_FULL_AGENT, json.dumps(beh_live)], str(tmp_path))
        try:
            conn.start()
            conn.initialize(timeout=10.0)
            sid = conn.request("session/new", {"cwd": conn.cwd, "mcpServers": []}, timeout=10.0)["sessionId"]
            conn.attach_session(sid, seen_updates.append, gate.make_permission_handler(conn))
            out: dict = {}
            th = threading.Thread(
                target=lambda: out.update(
                    conn.request("session/prompt", {"sessionId": sid, "prompt": []}, timeout=10.0)
                )
            )
            th.start()
            assert prompt_started.wait(5.0)
            # Because _read_stdout was NOT blocked, the live update already arrived!
            deadline = time.monotonic() + 3.0
            while not seen_updates and time.monotonic() < deadline:
                time.sleep(0.02)
            assert any(
                u.get("content", {}).get("text") == "live-chunk-while-prompting" for u in seen_updates
            )
            release_prompt.set()
            th.join(10.0)
            assert out["_meta"]["results"][0]["resp"]["result"] == {
                "outcome": {"outcome": "selected", "optionId": "ao"}
            }
            assert "\x1b[31m" not in captured_prompt[0]
        finally:
            release_prompt.set()
            conn.close()

    # Case 3: $/cancel_request arrives while user is prompted -> single cancelled response only
    cancel_started = threading.Event()
    release_late = threading.Event()

    def blocked_prompt(_: str) -> str:
        cancel_started.set()
        release_late.wait(5.0)
        return "1\n"

    beh_cancel = {
        "prompt_steps": [
            {
                "kind": "permission",
                "id": 702,
                "cancel_after": 0.15,
                "params": {
                    "options": [
                        {"optionId": "ao", "name": "Allow once", "kind": "allow_once"},
                        {"optionId": "ro", "name": "Reject once", "kind": "reject_once"},
                    ]
                },
            }
        ]
    }
    with InteractivePermissionGate(prompt_fn=blocked_prompt) as gate:
        conn = AcpConnection(sys.executable, [FAKE_FULL_AGENT, json.dumps(beh_cancel)], str(tmp_path))
        try:
            conn.start()
            conn.initialize(timeout=10.0)
            sid = conn.request("session/new", {"cwd": conn.cwd, "mcpServers": []}, timeout=10.0)["sessionId"]
            conn.attach_session(sid, lambda u: None, gate.make_permission_handler(conn))
            res = conn.request("session/prompt", {"sessionId": sid, "prompt": []}, timeout=10.0)
            assert cancel_started.is_set()
            assert res["_meta"]["results"][0]["resp"]["result"] == CANCELLED_OUTCOME
            # Release late user response and verify agent received ONLY ONE answer for id 702
            release_late.set()
            time.sleep(0.15)
            log = conn.request("x/dump", {}, timeout=10.0)["log"]
            answers = [m for m in log if m.get("id") == 702 and "method" not in m]
            assert len(answers) == 1
            assert answers[0]["result"] == CANCELLED_OUTCOME
        finally:
            release_late.set()
            conn.close()


def test_interactive_gate_non_ascii_digit_fails_closed_and_worker_stays_alive(tmp_path: Path):
    """Finding 6: non-ASCII digit input like '²\\n' fails closed without killing prompt worker."""
    answers = iter(["²\n", "1\n"])
    beh = {
        "prompt_steps": [
            {
                "kind": "permission",
                "id": 710,
                "params": {
                    "options": [
                        {"optionId": "ao", "name": "Allow once", "kind": "allow_once"},
                        {"optionId": "ro", "name": "Reject once", "kind": "reject_once"},
                    ]
                },
            },
            {
                "kind": "permission",
                "id": 711,
                "params": {
                    "options": [
                        {"optionId": "ao", "name": "Allow once", "kind": "allow_once"},
                        {"optionId": "ro", "name": "Reject once", "kind": "reject_once"},
                    ]
                },
            },
        ]
    }
    with InteractivePermissionGate(prompt_fn=lambda _: next(answers)) as gate:
        conn = AcpConnection(sys.executable, [FAKE_FULL_AGENT, json.dumps(beh)], str(tmp_path))
        try:
            conn.start()
            conn.initialize(timeout=10.0)
            sid = conn.request("session/new", {"cwd": conn.cwd, "mcpServers": []}, timeout=10.0)["sessionId"]
            conn.attach_session(sid, lambda u: None, gate.make_permission_handler(conn))
            res = conn.request("session/prompt", {"sessionId": sid, "prompt": []}, timeout=10.0)
            results = res["_meta"]["results"]
            # First request ("²\n") fails closed to reject_once
            assert results[0]["resp"]["result"] == {
                "outcome": {"outcome": "selected", "optionId": "ro"}
            }
            # Worker remained alive and handled second request ("1\n") cleanly
            assert results[1]["resp"]["result"] == {
                "outcome": {"outcome": "selected", "optionId": "ao"}
            }
        finally:
            conn.close()
