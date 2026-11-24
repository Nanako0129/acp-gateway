"""Mode B full ACP v1 client facade (``FullAcpClient`` and ``FullAcpSession``).

Security posture (SEC-1, SEC-2, SEC-3, SEC-5, SEC-8, SEC-9):
- Completely decoupled from Mode A (never imports ``acp_gateway.relay`` or
  ``acp_gateway.core.permission``).
- Fail-closed by default: ``enable_fs_read``, ``enable_fs_write``, and ``enable_terminal``
  all default to ``False`` and the default permission gate denies every action and agent
  permission request.
- Registers ONLY handlers explicitly enabled by the caller so ``AcpConnection`` derives
  ``clientCapabilities`` strictly from registered handlers (SEC-5).
- Validates ``protocolVersion == 1`` after ``initialize`` and capability-gates
  ``session/load``, ``session/resume``, ``session/close``, ``session/list``,
  ``session/delete``, ``additionalDirectories``, and HTTP MCP servers.
- Attaches ``session/load`` sessions BEFORE sending the request so replay updates arriving
  prior to the response are captured in order, detaching cleanly on error.
- Prefers ACP ``configOptions`` over legacy ``modes``.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Self

from acp_gateway.core.acp_connection import AcpConnection, AcpError

from .fs_handler import WorkspaceFsHandler
from .permission_policy import ClientPermissionGate, PolicyPermissionGate
from .terminal_handler import DEFAULT_ALLOWED_PATH_ENV, WorkspaceTerminalHandler

logger = logging.getLogger(__name__)

# Matches ACP v1 stopReason semantics without importing Mode A session/permission modules.
STOP_REASON_FINISH: dict[str, str] = {
    "end_turn": "stop",
    "max_tokens": "length",
    "max_turn_requests": "length",
    "refusal": "content_filter",
    "cancelled": "cancelled",
}

DEFAULT_CLIENT_INFO: dict[str, str] = {
    "name": "acp-gateway-client",
    "title": "ACP Gateway Full Client",
    "version": "0.1.0",
}


@dataclass(frozen=True)
class PromptResult:
    stop_reason: str
    finish_reason: str
    result: dict[str, Any]


class FullAcpSession:
    """One active ACP v1 session managed by :class:`FullAcpClient`."""

    def __init__(
        self,
        client: FullAcpClient,
        session_id: str,
        *,
        initial_result: Mapping[str, Any] | None = None,
        replaying: bool = False,
    ) -> None:
        self.client = client
        self.conn = client.conn
        self.session_id = session_id
        self.updates: queue.Queue[dict[str, Any]] = queue.Queue()
        self.replay_updates: list[dict[str, Any]] = []
        self.config_options: list[dict[str, Any]] = []
        self.modes: dict[str, Any] | None = None
        self.current_mode_id: str | None = None
        self._state_lock = threading.Lock()
        self._replaying = replaying
        self._closed = False
        if initial_result:
            self._apply_session_result(initial_result)

    @property
    def uses_config_options(self) -> bool:
        with self._state_lock:
            return bool(self.config_options)

    def _apply_session_result(self, result: Mapping[str, Any]) -> None:
        with self._state_lock:
            raw_opts = result.get("configOptions")
            if isinstance(raw_opts, list):
                self.config_options = [o for o in raw_opts if isinstance(o, dict)]
            raw_modes = result.get("modes")
            if isinstance(raw_modes, dict):
                self.modes = dict(raw_modes)
                if isinstance(raw_modes.get("currentModeId"), str):
                    self.current_mode_id = raw_modes["currentModeId"]

    def _finish_replay(self, result: Mapping[str, Any]) -> None:
        with self._state_lock:
            self._replaying = False
        self._apply_session_result(result)

    def _on_update(self, update: dict[str, Any]) -> None:
        with self._state_lock:
            if self._replaying:
                self.replay_updates.append(update)
            kind = update.get("sessionUpdate")
            if kind == "config_option_update" and isinstance(update.get("configOptions"), list):
                self.config_options = [o for o in update["configOptions"] if isinstance(o, dict)]
            elif kind == "current_mode_update" and isinstance(update.get("currentModeId"), str):
                self.current_mode_id = update["currentModeId"]
        self.updates.put(update)

    def prompt(
        self,
        blocks: str | Sequence[dict[str, Any]],
        *,
        timeout: float | None = None,
    ) -> PromptResult:
        """Send a ``session/prompt`` turn and map ``stopReason``."""
        if isinstance(blocks, str):
            prompt_blocks: list[dict[str, Any]] = [{"type": "text", "text": blocks}]
        else:
            prompt_blocks = [dict(b) for b in blocks]

        if not self.conn.supports_images and any(b.get("type") == "image" for b in prompt_blocks):
            logger.warning("acp-gateway: agent did not declare image prompts; images dropped")
            prompt_blocks = [b for b in prompt_blocks if b.get("type") != "image"]

        result = self.conn.request(
            "session/prompt",
            {"sessionId": self.session_id, "prompt": prompt_blocks},
            timeout=timeout,
        )
        res = result if isinstance(result, dict) else {}
        stop = res.get("stopReason")
        if stop not in STOP_REASON_FINISH:
            raise AcpError(f"unknown ACP stopReason {stop!r}")
        return PromptResult(stop, STOP_REASON_FINISH[stop], res)

    def set_config_option(
        self,
        config_id: str,
        value: Any,
        *,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Call ``session/set_config_option`` and refresh cached ``configOptions``."""
        result = self.conn.request(
            "session/set_config_option",
            {"sessionId": self.session_id, "configId": config_id, "value": value},
            timeout=timeout,
        )
        res = result if isinstance(result, dict) else {}
        if isinstance(res.get("configOptions"), list):
            with self._state_lock:
                self.config_options = [o for o in res["configOptions"] if isinstance(o, dict)]
        return res

    def set_mode(self, mode_id: str, *, timeout: float = 30.0) -> dict[str, Any]:
        """Switch mode, preferring ACP ``configOptions`` over legacy ``session/set_mode``."""
        mode_config_id: str | None = None
        with self._state_lock:
            for opt in self.config_options:
                if opt.get("category") == "mode" or opt.get("id") == "mode":
                    mode_config_id = str(opt.get("id") or "mode")
                    break
        if mode_config_id is not None:
            return self.set_config_option(mode_config_id, mode_id, timeout=timeout)

        result = self.conn.request(
            "session/set_mode",
            {"sessionId": self.session_id, "modeId": mode_id},
            timeout=timeout,
        )
        with self._state_lock:
            self.current_mode_id = mode_id
        return result if isinstance(result, dict) else {}

    def cancel(self) -> None:
        """Cancel pending permissions and send ``session/cancel``."""
        self.conn.cancel_session(self.session_id)

    def close(self, *, timeout: float = 5.0) -> None:
        """Close this session and release any terminals bound to it."""
        if self._closed:
            return
        self._closed = True
        self.client.close_session(self.session_id, timeout=timeout)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class FullAcpClient:
    """Full ACP v1 client (Mode B) with opt-in workspace fs/* and terminal/* handlers."""

    def __init__(
        self,
        command: str,
        args: Sequence[str] = (),
        *,
        workspace_roots: Sequence[str | Path],
        gate: ClientPermissionGate | None = None,
        enable_fs_read: bool = False,
        enable_fs_write: bool = False,
        enable_terminal: bool = False,
        profile_home: str | Path | None = None,
        gemini_home: str | Path | None = None,
        force_file_storage: bool = False,
        mux_env: Mapping[str, str] | None = None,
        client_info: Mapping[str, str] | None = None,
        max_read_bytes: int = 2 * 1024 * 1024,
        max_write_bytes: int = 2 * 1024 * 1024,
        allow_create_dirs: bool = True,
        max_terminals: int = 8,
        default_output_byte_limit: int = 256 * 1024,
        max_output_byte_limit: int = 4 * 1024 * 1024,
        max_runtime_seconds: float = 300.0,
        allowed_path_env: str = DEFAULT_ALLOWED_PATH_ENV,
    ) -> None:
        if not workspace_roots:
            raise ValueError("at least one workspace root is required")
        canonical_roots = [os.path.realpath(os.fspath(r)) for r in workspace_roots]
        for root in canonical_roots:
            if not os.path.isdir(root):
                raise ValueError(f"workspace root is not a directory: {root}")

        self._roots = tuple(canonical_roots)
        self._primary_root = canonical_roots[0]
        self._owns_gate = gate is None
        self._gate: ClientPermissionGate = gate if gate is not None else PolicyPermissionGate()
        self._fs_handler: WorkspaceFsHandler | None = None
        self._terminal_handler: WorkspaceTerminalHandler | None = None
        self._sessions: dict[str, FullAcpSession] = {}
        self._lock = threading.RLock()
        self._closed = False
        self._started = False

        handlers: dict[str, Callable[..., Any]] = {}
        try:
            if enable_fs_read or enable_fs_write:
                self._fs_handler = WorkspaceFsHandler(
                    canonical_roots,
                    self._gate,
                    max_read_bytes=max_read_bytes,
                    max_write_bytes=max_write_bytes,
                    allow_create_dirs=allow_create_dirs,
                )
                if enable_fs_read:
                    handlers["fs/read_text_file"] = self._fs_handler.read_text_file
                if enable_fs_write:
                    handlers["fs/write_text_file"] = self._fs_handler.write_text_file

            if enable_terminal:
                self._terminal_handler = WorkspaceTerminalHandler(
                    canonical_roots,
                    self._gate,
                    max_terminals=max_terminals,
                    default_output_byte_limit=default_output_byte_limit,
                    max_output_byte_limit=max_output_byte_limit,
                    max_runtime_seconds=max_runtime_seconds,
                    allowed_path_env=allowed_path_env,
                )
                handlers["terminal/create"] = self._terminal_handler.create
                handlers["terminal/output"] = self._terminal_handler.output
                handlers["terminal/wait_for_exit"] = self._terminal_handler.wait_for_exit
                handlers["terminal/kill"] = self._terminal_handler.kill
                handlers["terminal/release"] = self._terminal_handler.release

            self.conn = AcpConnection(
                command,
                args,
                self._primary_root,
                mux_env=mux_env,
                profile_home=profile_home,
                gemini_home=gemini_home,
                force_file_storage=force_file_storage,
                client_info=client_info if client_info is not None else DEFAULT_CLIENT_INFO,
                client_handlers=handlers,
            )
        except BaseException:
            if self._terminal_handler is not None:
                self._terminal_handler.close()
            if self._fs_handler is not None:
                self._fs_handler.close()
            raise

    @property
    def workspace_roots(self) -> tuple[str, ...]:
        return self._roots

    def start(self, *, timeout: float | None = 30.0) -> dict[str, Any]:
        """Start the ACP agent process, run ``initialize``, and verify ``protocolVersion == 1``."""
        if self._closed:
            raise AcpError("FullAcpClient is closed")
        self.conn.start()
        self._started = True
        try:
            result = self.conn.initialize(timeout=timeout)
            pv = self.conn.protocol_version
            if isinstance(pv, bool) or pv != 1:
                raise AcpError(f"Unsupported ACP protocolVersion: {pv!r}")
            return result if isinstance(result, dict) else {}
        except BaseException:
            self.close()
            raise

    def _validate_mcp_servers(self, mcp_servers: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        servers = [dict(s) for s in mcp_servers]
        for srv in servers:
            if srv.get("type") == "http" and not self.conn.supports_http_mcp:
                raise AcpError("Agent does not advertise HTTP MCP server capability")
        return servers

    def _validate_additional_directories(
        self,
        additional_directories: Sequence[str | Path] | None,
    ) -> list[str] | None:
        if not additional_directories:
            return None
        if not self.conn.supports_additional_directories:
            raise AcpError("Agent does not advertise additionalDirectories capability")
        return [os.path.realpath(os.fspath(d)) for d in additional_directories]

    def _build_session_params(
        self,
        *,
        cwd: str | Path | None,
        mcp_servers: Sequence[Mapping[str, Any]],
        additional_directories: Sequence[str | Path] | None,
        meta: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "cwd": os.path.realpath(os.fspath(cwd)) if cwd is not None else self._primary_root,
            "mcpServers": self._validate_mcp_servers(mcp_servers),
        }
        dirs = self._validate_additional_directories(additional_directories)
        if dirs is not None:
            params["additionalDirectories"] = dirs
        if meta is not None:
            params["_meta"] = dict(meta)
        return params

    def new_session(
        self,
        *,
        cwd: str | Path | None = None,
        mcp_servers: Sequence[Mapping[str, Any]] = (),
        additional_directories: Sequence[str | Path] | None = None,
        meta: Mapping[str, Any] | None = None,
        timeout: float = 60.0,
    ) -> FullAcpSession:
        """Create and attach a new ACP session."""
        params = self._build_session_params(
            cwd=cwd,
            mcp_servers=mcp_servers,
            additional_directories=additional_directories,
            meta=meta,
        )
        result = self.conn.request("session/new", params, timeout=timeout)
        res = result if isinstance(result, dict) else {}
        sid = res.get("sessionId")
        if not isinstance(sid, str) or not sid:
            raise AcpError("Agent returned invalid sessionId from session/new")
        session = FullAcpSession(self, sid, initial_result=res)
        with self._lock:
            self._sessions[sid] = session
        self.conn.attach_session(
            sid,
            session._on_update,
            self._gate.make_permission_handler(self.conn),
        )
        return session

    def load_session(
        self,
        session_id: str,
        *,
        cwd: str | Path | None = None,
        mcp_servers: Sequence[Mapping[str, Any]] = (),
        additional_directories: Sequence[str | Path] | None = None,
        timeout: float = 60.0,
    ) -> FullAcpSession:
        """Load an existing session, capturing replay updates emitted prior to the response."""
        if not self.conn.supports_load_session:
            raise AcpError("Agent does not advertise loadSession capability")
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("session_id must be a non-empty string")
        params = self._build_session_params(
            cwd=cwd,
            mcp_servers=mcp_servers,
            additional_directories=additional_directories,
        )
        params["sessionId"] = session_id

        session = FullAcpSession(self, session_id, replaying=True)
        # Attach BEFORE sending session/load so all replay updates arrive in order.
        self.conn.attach_session(
            session_id,
            session._on_update,
            self._gate.make_permission_handler(self.conn),
        )
        try:
            result = self.conn.request("session/load", params, timeout=timeout)
        except BaseException:
            self.conn.detach_session(session_id)
            while not session.updates.empty():
                try:
                    session.updates.get_nowait()
                except queue.Empty:
                    break
            raise
        res = result if isinstance(result, dict) else {}
        session._finish_replay(res)
        with self._lock:
            self._sessions[session_id] = session
        return session

    def resume_session(
        self,
        session_id: str,
        *,
        cwd: str | Path | None = None,
        mcp_servers: Sequence[Mapping[str, Any]] = (),
        additional_directories: Sequence[str | Path] | None = None,
        timeout: float = 60.0,
    ) -> FullAcpSession:
        """Resume an existing session when ``sessionCapabilities.resume`` is advertised."""
        if not self.conn.supports_session_resume:
            raise AcpError("Agent does not advertise session/resume capability")
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("session_id must be a non-empty string")
        params = self._build_session_params(
            cwd=cwd,
            mcp_servers=mcp_servers,
            additional_directories=additional_directories,
        )
        params["sessionId"] = session_id

        session = FullAcpSession(self, session_id, replaying=True)
        self.conn.attach_session(
            session_id,
            session._on_update,
            self._gate.make_permission_handler(self.conn),
        )
        try:
            result = self.conn.request("session/resume", params, timeout=timeout)
        except BaseException:
            self.conn.detach_session(session_id)
            raise
        res = result if isinstance(result, dict) else {}
        session._finish_replay(res)
        with self._lock:
            self._sessions[session_id] = session
        return session

    def list_sessions(
        self,
        *,
        cwd: str | Path | None = None,
        cursor: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Call ``session/list`` when ``sessionCapabilities.list`` is advertised."""
        if not self.conn.supports_session_list:
            raise AcpError("Agent does not advertise session/list capability")
        params: dict[str, Any] = {}
        if cwd is not None:
            params["cwd"] = os.path.realpath(os.fspath(cwd))
        if cursor is not None:
            params["cursor"] = cursor
        res = self.conn.request("session/list", params, timeout=timeout)
        return res if isinstance(res, dict) else {}

    def delete_session(self, session_id: str, *, timeout: float = 30.0) -> dict[str, Any]:
        """Call ``session/delete`` when ``sessionCapabilities.delete`` is advertised."""
        if not self.conn.supports_session_delete:
            raise AcpError("Agent does not advertise session/delete capability")
        res = self.conn.request("session/delete", {"sessionId": session_id}, timeout=timeout)
        return res if isinstance(res, dict) else {}

    def close_session(self, session_id: str, *, timeout: float = 5.0) -> None:
        """Close a session (gating ``session/close`` on capability) and release its terminals."""
        with self._lock:
            self._sessions.pop(session_id, None)
        if self._terminal_handler is not None:
            self._terminal_handler.release_session(session_id)
        self.conn.close_session(session_id, timeout=timeout)

    def close(self) -> None:
        """Release all terminals, close connection, close pinned FDs, and clean up."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            sessions = list(self._sessions.values())
            self._sessions.clear()

        for sess in sessions:
            sess._closed = True
            self.conn.detach_session(sess.session_id)

        if self._terminal_handler is not None:
            self._terminal_handler.close()
        self.conn.close()
        if self._fs_handler is not None:
            self._fs_handler.close()
        if self._owns_gate:
            self._gate.close()

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
