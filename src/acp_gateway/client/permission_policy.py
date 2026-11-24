"""Mode B (full ACP client) permission policy, interactive gate, and display sanitization.

Security posture (SEC-1, SEC-8, SEC-9):
- Completely decoupled from Mode A (never imports ``acp_gateway.relay`` or
  ``acp_gateway.core.permission``).
- Policy decisions inspect ONLY structured ``ActionRequest`` fields and validated ACP
  option kinds — never untrusted agent ``title`` or ``name`` strings.
- Fail-closed defaults: all filesystem reads/writes, sensitive paths, terminal creation,
  agent permission approvals, and ``allow_always`` selections default to denied.
- ``InteractivePermissionGate`` validates ``session/request_permission`` synchronously
  (raising ``AcpRpcError(-32602, ...)`` on malformed options) and dispatches prompts to
  a dedicated worker thread, returning ``None`` immediately so the connection stdout
  reader never deadlocks and ``$/cancel_request`` resolves cleanly without double-answers.
- ``sanitize_terminal_text`` strips ANSI CSI/OSC/DCS/ESC sequences, C0/C1 control
  characters (preserving safe ``\\n`` and ``\\t``), and Unicode BiDi override/isolate
  controls before displaying untrusted agent text on a human terminal.
"""

from __future__ import annotations

import logging
import queue
import re
import sys
import threading
from collections.abc import Callable, Collection
from dataclasses import dataclass
from typing import Any, Literal, Protocol, Self, TextIO

from acp_gateway.core.acp_connection import CANCELLED_OUTCOME, AcpConnection, AcpRpcError

log = logging.getLogger(__name__)

ActionKind = Literal["fs_read", "fs_write", "terminal_create"]

VALID_OPTION_KINDS: frozenset[str] = frozenset(
    {
        "allow_once",
        "allow_always",
        "reject_once",
        "reject_always",
    }
)

# Order matters: strip full multi-byte escape sequences before stripping bare controls.
_OSC_RE = re.compile(r"(?:\x1b\]|\x9d)[^\x07\x1b\x9c]*(?:\x07|\x1b\\|\x9c|$)")
_DCS_RE = re.compile(r"(?:\x1b[PX^_]|[\x90\x98\x9e\x9f])[^\x1b\x9c]*(?:\x1b\\|\x9c|$)")
_CSI_RE = re.compile(r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]")
_ESC_RE = re.compile(r"\x1b[ -/]*[@-~]|\x1b")
# Strip C0 (except \t=0x09, \n=0x0a), DEL (0x7f), C1 (0x80-0x9f), and Unicode BiDi controls.
_CTRL_AND_BIDI_RE = re.compile(
    r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]"
)


def sanitize_terminal_text(text: str) -> str:
    """Strip ANSI escape sequences, unsafe control chars, and Unicode BiDi controls."""
    if not isinstance(text, str):
        text = str(text)
    cleaned = _OSC_RE.sub("", text)
    cleaned = _DCS_RE.sub("", cleaned)
    cleaned = _CSI_RE.sub("", cleaned)
    cleaned = _ESC_RE.sub("", cleaned)
    cleaned = _CTRL_AND_BIDI_RE.sub("", cleaned)
    return cleaned


@dataclass(frozen=True)
class ActionRequest:
    """Structured authorization request for client-side fs/* and terminal/* actions.

    Contains only validated client-side fields; never carries untrusted agent titles.
    """

    kind: ActionKind
    session_id: str
    root: str | None = None
    relpath: str | None = None
    sensitive: bool = False
    byte_length: int | None = None
    command: str | None = None
    args: tuple[str, ...] = ()
    cwd: str | None = None
    env_keys: tuple[str, ...] = ()


class ClientPermissionGate(Protocol):
    """Protocol implemented by Mode B permission gates."""

    def authorize_action(
        self,
        action: ActionRequest,
        cancel_event: threading.Event | None = None,
    ) -> bool: ...

    def make_permission_handler(
        self,
        conn: AcpConnection,
    ) -> Callable[..., dict[str, Any] | None]: ...

    def close(self) -> None: ...


def validate_permission_params(params: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate ``session/request_permission`` params per ACP v1 (SEC-9).

    Requires a non-empty list of option dicts, each carrying non-empty ``str`` ``optionId``,
    ``str`` ``name``, and ``kind`` in ``VALID_OPTION_KINDS``. Raises ``AcpRpcError(-32602)``
    on any violation.
    """
    if not isinstance(params, dict):
        raise AcpRpcError(-32602, "Invalid permission options")
    raw_options = params.get("options")
    if not isinstance(raw_options, list) or not raw_options:
        raise AcpRpcError(-32602, "Invalid permission options")
    validated: list[dict[str, Any]] = []
    for opt in raw_options:
        if not isinstance(opt, dict):
            raise AcpRpcError(-32602, "Invalid permission options")
        option_id = opt.get("optionId")
        name = opt.get("name")
        kind = opt.get("kind")
        if (
            not isinstance(option_id, str)
            or not option_id
            or not isinstance(name, str)
            or not isinstance(kind, str)
            or kind not in VALID_OPTION_KINDS
        ):
            raise AcpRpcError(-32602, "Invalid permission options")
        validated.append(opt)
    return validated


def _selected_outcome(option_id: str) -> dict[str, Any]:
    return {"outcome": {"outcome": "selected", "optionId": option_id}}


def _reject_or_cancel(options: list[dict[str, Any]]) -> dict[str, Any]:
    for opt in options:
        if opt["kind"] == "reject_once":
            return _selected_outcome(opt["optionId"])
    return CANCELLED_OUTCOME


class PolicyPermissionGate:
    """Fail-closed programmatic permission gate for Mode B clients (SEC-1, SEC-9)."""

    def __init__(
        self,
        *,
        allow_fs_read: bool = False,
        allow_fs_write: bool = False,
        allow_terminal: bool = False,
        allow_sensitive_paths: bool = False,
        allow_agent_permissions: bool = False,
        allow_always_enabled: bool = False,
        allowed_commands: Collection[str] | None = None,
        authorizer: Callable[[ActionRequest], bool] | None = None,
        agent_permission_callback: Callable[[dict[str, Any], list[dict[str, Any]]], str | None]
        | None = None,
    ) -> None:
        self.allow_fs_read = bool(allow_fs_read)
        self.allow_fs_write = bool(allow_fs_write)
        self.allow_terminal = bool(allow_terminal)
        self.allow_sensitive_paths = bool(allow_sensitive_paths)
        self.allow_agent_permissions = bool(allow_agent_permissions)
        self.allow_always_enabled = bool(allow_always_enabled)
        self.allowed_commands: frozenset[str] | None = (
            frozenset(allowed_commands) if allowed_commands is not None else None
        )
        self._authorizer = authorizer
        self._agent_permission_callback = agent_permission_callback

    def authorize_action(
        self,
        action: ActionRequest,
        cancel_event: threading.Event | None = None,
    ) -> bool:
        """Decide whether a structured client-side action is allowed."""
        if cancel_event is not None and cancel_event.is_set():
            return False
        if action.kind == "fs_read":
            if not self.allow_fs_read:
                return False
            if action.sensitive and not self.allow_sensitive_paths:
                return False
        elif action.kind == "fs_write":
            if not self.allow_fs_write:
                return False
            if action.sensitive and not self.allow_sensitive_paths:
                return False
        elif action.kind == "terminal_create":
            if not self.allow_terminal:
                return False
            if self.allowed_commands is not None and action.command not in self.allowed_commands:
                return False
        else:
            return False

        if self._authorizer is not None:
            try:
                return bool(self._authorizer(action))
            except Exception:  # noqa: BLE001 - fail closed on authorizer error
                log.exception("action authorizer raised; denying action")
                return False
        return True

    def decide_permission(
        self,
        params: dict[str, Any],
        request_id: Any = None,
    ) -> dict[str, Any]:
        """Synchronously decide an agent ``session/request_permission`` request.

        Never inspects untrusted ``title``/``name`` fields and never auto-selects
        ``allow_always``.
        """
        _ = request_id
        options = validate_permission_params(params)
        if not self.allow_agent_permissions:
            return _reject_or_cancel(options)

        if self._agent_permission_callback is not None:
            try:
                chosen_id = self._agent_permission_callback(params, options)
            except Exception:  # noqa: BLE001 - fail closed on callback error
                log.exception("agent permission callback raised; failing closed")
                return _reject_or_cancel(options)
            if isinstance(chosen_id, str) and chosen_id:
                for opt in options:
                    if opt["optionId"] == chosen_id:
                        if opt["kind"] == "allow_always" and not self.allow_always_enabled:
                            return _reject_or_cancel(options)
                        return _selected_outcome(opt["optionId"])
            return _reject_or_cancel(options)

        # Without an explicit callback, never auto-select allow_always.
        for opt in options:
            if opt["kind"] == "allow_once":
                return _selected_outcome(opt["optionId"])
        return _reject_or_cancel(options)

    def make_permission_handler(
        self,
        conn: AcpConnection,
    ) -> Callable[..., dict[str, Any] | None]:
        _ = conn

        def _handler(params: dict[str, Any], request_id: Any = None) -> dict[str, Any]:
            return self.decide_permission(params, request_id=request_id)

        return _handler

    def close(self) -> None:
        return None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _format_action_prompt(action: ActionRequest) -> str:
    """Format an ``ActionRequest`` with sanitized exact structured fields for human review."""
    lines = [f"[ACP Action Approval: {sanitize_terminal_text(action.kind)}]"]
    lines.append(f"  session: {sanitize_terminal_text(action.session_id)}")
    if action.kind in ("fs_read", "fs_write"):
        lines.append(f"  root:    {sanitize_terminal_text(action.root or '')}")
        lines.append(f"  path:    {sanitize_terminal_text(action.relpath or '')}")
        if action.sensitive:
            lines.append("  WARNING: SENSITIVE PATH (credentials / VCS / tool config)")
        if action.byte_length is not None:
            lines.append(f"  bytes:   {action.byte_length}")
    elif action.kind == "terminal_create":
        lines.append(f"  command: {sanitize_terminal_text(action.command or '')}")
        sanitized_args = [sanitize_terminal_text(a) for a in action.args]
        lines.append(f"  args:    {sanitized_args!r}")
        lines.append(f"  cwd:     {sanitize_terminal_text(action.cwd or '')}")
        sanitized_keys = [sanitize_terminal_text(k) for k in action.env_keys]
        lines.append(f"  envKeys: {sanitized_keys!r}")
    lines.append("Allow this action? [y/N]: ")
    return "\n".join(lines)


def _format_permission_prompt(
    params: dict[str, Any],
    options: list[dict[str, Any]],
    *,
    allow_always_enabled: bool,
) -> str:
    """Format an agent ``session/request_permission`` prompt with all untrusted fields sanitized."""
    sid = sanitize_terminal_text(str(params.get("sessionId") or ""))
    tc = params.get("toolCall") if isinstance(params.get("toolCall"), dict) else {}
    tc_id = sanitize_terminal_text(str(tc.get("toolCallId") or ""))
    tc_kind = sanitize_terminal_text(str(tc.get("kind") or ""))
    tc_title = sanitize_terminal_text(str(tc.get("title") or ""))

    lines = ["[ACP Agent Permission Request]"]
    lines.append(f"  session:    {sid}")
    if tc_id:
        lines.append(f"  toolCallId: {tc_id}")
    if tc_kind:
        lines.append(f"  kind:       {tc_kind}")
    if tc_title:
        lines.append(f"  agentTitle (untrusted): {tc_title}")
    lines.append("  Options:")
    for idx, opt in enumerate(options, start=1):
        opt_name = sanitize_terminal_text(opt["name"])
        opt_kind = opt["kind"]
        suffix = " [disabled by policy]" if opt_kind == "allow_always" and not allow_always_enabled else ""
        lines.append(f"    [{idx}] {opt_name} ({opt_kind}){suffix}")
    lines.append("Select option number (empty/other cancels): ")
    return "\n".join(lines)


@dataclass(frozen=True)
class _PermissionJob:
    conn: AcpConnection
    request_id: Any
    params: dict[str, Any]
    options: list[dict[str, Any]]


class InteractivePermissionGate:
    """Human-in-the-loop permission gate for Mode B clients (SEC-1, SEC-8, SEC-9).

    - ``session/request_permission`` validates options synchronously (raising
      ``AcpRpcError(-32602)`` on malformed options) and dispatches the prompt to a
      dedicated worker thread, returning ``None`` immediately so ``_read_stdout`` never
      blocks.
    - ``authorize_action`` prompts synchronously on the calling client-handler worker
      thread with sanitized exact structured fields and fails closed on cancel/EOF/error.
    """

    def __init__(
        self,
        *,
        allow_always_enabled: bool = False,
        prompt_fn: Callable[[str], str] | None = None,
        input_stream: TextIO | None = None,
        output_stream: TextIO | None = None,
    ) -> None:
        self.allow_always_enabled = bool(allow_always_enabled)
        self._prompt_fn = prompt_fn
        self._input_stream = input_stream
        self._output_stream = output_stream
        self._prompt_lock = threading.Lock()
        self._worker_lock = threading.Lock()
        self._queue: queue.Queue[_PermissionJob | None] = queue.Queue()
        self._worker: threading.Thread | None = None
        self._closed = False

    def _default_prompt(self, prompt_text: str) -> str:
        out = self._output_stream if self._output_stream is not None else sys.stderr
        inp = self._input_stream if self._input_stream is not None else sys.stdin
        if inp is None or getattr(inp, "closed", False):
            return ""
        out.write(prompt_text)
        out.flush()
        return inp.readline()

    def _ask(self, prompt_text: str) -> str:
        fn = self._prompt_fn if self._prompt_fn is not None else self._default_prompt
        try:
            answer = fn(prompt_text)
        except (EOFError, KeyboardInterrupt, OSError, ValueError):
            return ""
        except Exception:  # noqa: BLE001 - fail closed on prompt callback error
            log.exception("interactive prompt callback failed; failing closed")
            return ""
        return answer if isinstance(answer, str) else ""

    def _ensure_worker_locked(self) -> None:
        if self._worker is None and not self._closed:
            self._worker = threading.Thread(
                target=self._worker_loop,
                name="acp-perm-prompt",
                daemon=True,
            )
            self._worker.start()

    def _resolve_choice(self, answer: str, options: list[dict[str, Any]]) -> dict[str, Any]:
        choice = answer.strip()
        if not choice:
            return _reject_or_cancel(options)
        selected: dict[str, Any] | None = None
        if choice.isascii() and choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                selected = options[idx]
        else:
            for opt in options:
                if opt["optionId"] == choice:
                    selected = opt
                    break
        if selected is None:
            return _reject_or_cancel(options)
        if selected["kind"] == "allow_always" and not self.allow_always_enabled:
            return _reject_or_cancel(options)
        return _selected_outcome(selected["optionId"])

    def _worker_loop(self) -> None:
        while True:
            job = self._queue.get()
            if job is None:
                return
            try:
                if self._closed:
                    outcome = _reject_or_cancel(job.options)
                else:
                    prompt_text = _format_permission_prompt(
                        job.params,
                        job.options,
                        allow_always_enabled=self.allow_always_enabled,
                    )
                    with self._prompt_lock:
                        if self._closed:
                            outcome = _reject_or_cancel(job.options)
                        else:
                            answer = self._ask(prompt_text)
                            outcome = self._resolve_choice(answer, job.options)
            except Exception:  # noqa: BLE001 - worker must never die; fail closed
                log.exception("interactive permission worker failed; failing closed")
                outcome = _reject_or_cancel(job.options)
            job.conn.respond_permission(job.request_id, outcome)

    def authorize_action(
        self,
        action: ActionRequest,
        cancel_event: threading.Event | None = None,
    ) -> bool:
        """Synchronously ask the user to approve a structured fs/* or terminal/* action."""
        if self._closed or (cancel_event is not None and cancel_event.is_set()):
            return False
        prompt_text = _format_action_prompt(action)
        with self._prompt_lock:
            if self._closed or (cancel_event is not None and cancel_event.is_set()):
                return False
            answer = self._ask(prompt_text)
        if self._closed or (cancel_event is not None and cancel_event.is_set()):
            return False
        return answer.strip().lower() in ("y", "yes")

    def handle_permission(
        self,
        params: dict[str, Any],
        request_id: Any,
        conn: AcpConnection,
    ) -> dict[str, Any] | None:
        """Validate permission params synchronously and dispatch the prompt asynchronously."""
        options = validate_permission_params(params)
        with self._worker_lock:
            if self._closed:
                return _reject_or_cancel(options)
            self._ensure_worker_locked()
            self._queue.put(_PermissionJob(conn=conn, request_id=request_id, params=params, options=options))
        return None

    def make_permission_handler(
        self,
        conn: AcpConnection,
    ) -> Callable[..., dict[str, Any] | None]:
        def _handler(params: dict[str, Any], request_id: Any = None) -> dict[str, Any] | None:
            return self.handle_permission(params, request_id, conn)

        return _handler

    def close(self) -> None:
        """Stop the prompt worker thread cleanly and fail-close any queued permission requests."""
        with self._worker_lock:
            if self._closed:
                return
            self._closed = True
            worker = self._worker
            self._queue.put(None)
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=5.0)
        # Drain any remaining queued jobs fail-closed if worker exited early.
        while True:
            try:
                job = self._queue.get_nowait()
            except queue.Empty:
                break
            if job is not None:
                job.conn.respond_permission(job.request_id, _reject_or_cancel(job.options))

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
