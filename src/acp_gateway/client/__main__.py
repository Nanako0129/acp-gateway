"""Minimal fail-closed CLI for Mode B (``python -m acp_gateway.client``)."""

from __future__ import annotations

import argparse
import json
import os
import queue
import sys
from collections.abc import Sequence
from typing import Any

from .full_client import FullAcpClient
from .permission_policy import (
    InteractivePermissionGate,
    PolicyPermissionGate,
    sanitize_terminal_text,
)


def _sanitize_json_value(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_terminal_text(value)
    if isinstance(value, list):
        return [_sanitize_json_value(v) for v in value]
    if isinstance(value, dict):
        return {sanitize_terminal_text(str(k)): _sanitize_json_value(v) for k, v in value.items()}
    return value


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m acp_gateway.client",
        description="Fail-closed Mode B ACP v1 full client CLI.",
    )
    parser.add_argument("--command", required=True, help="ACP agent executable to launch.")
    parser.add_argument(
        "--arg",
        action="append",
        default=[],
        help="Argument passed to the ACP agent executable (repeatable).",
    )
    parser.add_argument(
        "--workspace",
        action="append",
        default=None,
        help="Allowed workspace root directory (repeatable; defaults to current directory).",
    )
    parser.add_argument("--profile-home", default=None, help="Explicit HOME directory for the ACP child.")
    parser.add_argument("--gemini-home", default=None, help="Explicit GEMINI_HOME for the ACP child.")
    parser.add_argument("--prompt", default=None, help="Single prompt turn to send to a new session.")
    parser.add_argument(
        "--allow-fs-read",
        action="store_true",
        default=False,
        help="Register fs/read_text_file handler (disabled by default).",
    )
    parser.add_argument(
        "--allow-fs-write",
        action="store_true",
        default=False,
        help="Register fs/write_text_file handler (disabled by default).",
    )
    parser.add_argument(
        "--allow-terminal",
        action="store_true",
        default=False,
        help="Register terminal/* handlers (disabled by default; application-layer containment only).",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        default=False,
        help="Use PolicyPermissionGate instead of interactive human prompts.",
    )
    parser.add_argument(
        "--probe-only",
        action="store_true",
        default=False,
        help="Run initialize, print sanitized capabilities JSON, and exit.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    roots = args.workspace if args.workspace else [os.getcwd()]

    gate: PolicyPermissionGate | InteractivePermissionGate
    if args.non_interactive:
        gate = PolicyPermissionGate(
            allow_fs_read=args.allow_fs_read,
            allow_fs_write=args.allow_fs_write,
            allow_terminal=args.allow_terminal,
            allow_sensitive_paths=False,
            allow_agent_permissions=False,
            allow_always_enabled=False,
        )
    else:
        gate = InteractivePermissionGate(allow_always_enabled=False)

    try:
        with FullAcpClient(
            args.command,
            args.arg,
            workspace_roots=roots,
            gate=gate,
            enable_fs_read=args.allow_fs_read,
            enable_fs_write=args.allow_fs_write,
            enable_terminal=args.allow_terminal,
            profile_home=args.profile_home,
            gemini_home=args.gemini_home,
        ) as client:
            if args.probe_only or args.prompt is None:
                summary = {
                    "protocolVersion": client.conn.protocol_version,
                    "agentInfo": _sanitize_json_value(client.conn.agent_info),
                    "agentCapabilities": _sanitize_json_value(client.conn.agent_capabilities),
                    "authMethods": _sanitize_json_value(client.conn.agent_auth_methods),
                    "clientCapabilities": client.conn._build_client_capabilities(),
                }
                sys.stdout.write(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
                sys.stdout.flush()
                return 0

            with client.new_session() as session:
                result = session.prompt(args.prompt)
                chunks: list[str] = []
                while True:
                    try:
                        upd = session.updates.get_nowait()
                    except queue.Empty:
                        break
                    if upd.get("sessionUpdate") == "agent_message_chunk":
                        content = upd.get("content")
                        if isinstance(content, dict) and isinstance(content.get("text"), str):
                            chunks.append(sanitize_terminal_text(content["text"]))
                if chunks:
                    sys.stdout.write("".join(chunks) + "\n")
                else:
                    sys.stdout.write(
                        f"stopReason={sanitize_terminal_text(result.stop_reason)}\n"
                    )
                sys.stdout.flush()
                return 0
    finally:
        gate.close()


if __name__ == "__main__":
    raise SystemExit(main())
