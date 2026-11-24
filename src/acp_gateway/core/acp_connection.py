"""One ACP child process spoken to over NDJSON JSON-RPC 2.0 on stdio.

Security posture (SEC-4, SEC-5, SEC-11):
- Child env comes from ``build_acp_child_env(...)`` with explicit profile/Gemini homes and
  validated mux control vars (no ambient ``os.environ`` mutation).
- Stderr is untrusted: always drained, classified at capture time, summarised only by
  ``_acp_stderr_diagnostic`` -- raw stderr bytes never reach an exception or a log.
- Request params (``session/new`` carries the MCP bearer) are never logged.
- ``fs`` and ``terminal`` capabilities are derived strictly from registered ``client_handlers``.
- Incoming JSON-RPC IDs, frames, active ``sessionId`` bindings, client-handler concurrency,
  and unattached session update buffers are strictly validated and bounded.
"""

from __future__ import annotations

import collections
import concurrent.futures
import inspect
import itertools
import json
import logging
import subprocess
import threading
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .env_stderr import (
    MUX_ENV_KEYS,
    _acp_stderr_diagnostic,
    _acp_stderr_retry_class,
    build_acp_child_env,
)

log = logging.getLogger(__name__)

INITIALIZE_PARAMS = {
    "protocolVersion": 1,
    "clientCapabilities": {"fs": {"readTextFile": False, "writeTextFile": False}, "terminal": False},
    "clientInfo": {
        "name": "acp-gateway",
        "title": "ACP Gateway",
        "version": "0.1.0",
    },
}
CANCELLED_OUTCOME = {"outcome": {"outcome": "cancelled"}}

MAX_FRAME_BYTES = 64 * 1024 * 1024
MAX_CLIENT_HANDLER_WORKERS = 16
MAX_UNATTACHED_SESSIONS = 64
MAX_UNATTACHED_UPDATES = 1024

_STDERR_KEEP_LINES = 200
_STDERR_LINE_CHARS = 4096

# on_permission(params) or on_permission(params, request_id) -> response result, or None to leave
# the request pending until ``respond_permission``, ``cancel_session``, or ``$/cancel_request`` answers it.
PermissionHandler = Callable[..., dict[str, Any] | None]


class AcpError(RuntimeError):
    """Base class for ACP connection failures."""


class AcpProcessExit(AcpError):
    """The child exited. ``str()`` is the exit status plus the non-echoing stderr diagnostic."""

    def __init__(self, message: str, *, exit_status: int | None, retry_class: str | None) -> None:
        super().__init__(message)
        self.exit_status = exit_status
        self.retry_class = retry_class  # fixed class name or None, never child text


class AcpRpcError(AcpError):
    def __init__(self, code: Any, message: str, *, data: Any = None) -> None:
        super().__init__(f"ACP error {code}: {message}")
        self.code = code
        self.rpc_message = message
        self.data = data


class _Pending:
    __slots__ = ("error", "event", "result")

    def __init__(self) -> None:
        self.event = threading.Event()
        self.result: Any = None
        self.error: Exception | None = None


_TERMINAL_METHODS = frozenset(
    {
        "terminal/create",
        "terminal/output",
        "terminal/wait_for_exit",
        "terminal/kill",
        "terminal/release",
    }
)
_SESSION_SCOPED_PREFIXES = ("fs/", "terminal/", "elicitation/")

ClientHandler = Callable[..., Any]


def _is_valid_rpc_id(value: Any) -> bool:
    """JSON-RPC 2.0 request/response id must be int or str (never bool, list, dict, None)."""
    return isinstance(value, (int, str)) and not isinstance(value, bool)


def _classify_second_arg_mode(handler: Callable[..., Any], kw_name: str) -> str:
    """Determine how to pass ``kw_name`` to ``handler``: ``'kw'``, ``'pos'``, or ``'none'``."""
    try:
        sig = inspect.signature(handler)
    except (TypeError, ValueError):
        return "none"
    params = list(sig.parameters.values())
    positional = 0
    has_var_pos = False
    has_var_kw = False
    for p in params:
        if p.name == kw_name and p.kind in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        ):
            return "kw"
        if p.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        ):
            positional += 1
        elif p.kind == inspect.Parameter.VAR_POSITIONAL:
            has_var_pos = True
        elif p.kind == inspect.Parameter.VAR_KEYWORD:
            has_var_kw = True
    if positional >= 2 or has_var_pos:
        return "pos"
    if has_var_kw:
        return "kw"
    return "none"


def _classify_handler_cancel_mode(handler: ClientHandler) -> str:
    """Determine how to pass ``cancel_event`` to ``handler``: ``'kw'``, ``'pos'``, or ``'none'``."""
    return _classify_second_arg_mode(handler, "cancel_event")


def _classify_permission_mode(handler: PermissionHandler) -> str:
    """Determine how to pass ``request_id`` to ``on_permission``: ``'kw'``, ``'pos'``, or ``'none'``."""
    return _classify_second_arg_mode(handler, "request_id")


def _cap_enabled(value: Any) -> bool:
    """ACP capability objects may be advertised as a dict (even ``{}``) or boolean ``True``."""
    return isinstance(value, dict) or value is True


class AcpConnection:
    def __init__(
        self,
        command: str,
        args: Sequence[str],
        cwd: str,
        *,
        mux_env: Mapping[str, str] | None = None,
        profile_home: str | Path | None = None,
        gemini_home: str | Path | None = None,
        force_file_storage: bool = False,
        client_info: Mapping[str, str] | None = None,
        client_capabilities: Mapping[str, Any] | None = None,
        client_handlers: Mapping[str, ClientHandler] | None = None,
    ) -> None:
        unknown = set(mux_env or ()) - MUX_ENV_KEYS
        if unknown:
            raise ValueError(f"not a permitted mux control variable: {sorted(unknown)}")
        handlers = dict(client_handlers or {})
        terminal_registered = _TERMINAL_METHODS.intersection(handlers)
        if terminal_registered and terminal_registered != _TERMINAL_METHODS:
            raise ValueError("partial terminal/* handler registration is not allowed")
        cap_override = dict(client_capabilities) if client_capabilities is not None else None
        if cap_override is not None and ("fs" in cap_override or "terminal" in cap_override):
            raise ValueError("fs and terminal capabilities are derived strictly from client_handlers")

        self._argv = [command, *args]
        self._cwd = cwd
        self._mux_env = dict(mux_env or {})
        self._profile_home = profile_home
        self._gemini_home = gemini_home
        self._force_file_storage = bool(force_file_storage)
        self._client_info = (
            dict(client_info) if client_info is not None else dict(INITIALIZE_PARAMS["clientInfo"])
        )
        self._client_capabilities_override = cap_override
        self._client_handlers: dict[str, ClientHandler] = handlers
        self._client_handler_modes: dict[str, str] = {
            method: _classify_handler_cancel_mode(fn) for method, fn in handlers.items()
        }
        self._proc: subprocess.Popen[bytes] | None = None
        self._lock = threading.RLock()  # guards the maps below; never held while calling out
        # Serialises session-update callbacks (order of chunks) without holding _lock. Callbacks must not block:
        # the stdout reader runs them, so a callback waiting on another lock would stall every pending response.
        self._dispatch_lock = threading.Lock()
        self._saw_rate_limit = False
        self._write_lock = threading.Lock()  # one NDJSON line at a time on stdin
        self._ids = itertools.count(1)
        self._pending: dict[int, _Pending] = {}
        self._updates: collections.OrderedDict[str, collections.deque[dict[str, Any]]] = (
            collections.OrderedDict()
        )
        self._unattached_update_count = 0
        self._sessions: dict[str, tuple[Callable[[dict[str, Any]], None], PermissionHandler, str]] = {}
        self._pending_perms: dict[str, list[Any]] = {}
        # agent->client request_id -> (cancel_event, session_id | None)
        self._active_client_reqs: dict[Any, tuple[threading.Event, str | None]] = {}
        self._executor: concurrent.futures.ThreadPoolExecutor | None = None
        self._stderr: collections.deque[str] = collections.deque(maxlen=_STDERR_KEEP_LINES)
        self._stderr_class: str | None = None
        self._exit_error: AcpProcessExit | None = None
        self._exited = threading.Event()
        self._threads: list[threading.Thread] = []
        self.protocol_version: Any = None
        self.agent_info: dict[str, Any] = {}
        self.agent_capabilities: dict[str, Any] = {}
        self.agent_auth_methods: list[dict[str, Any]] = []
        self.supports_images = False
        self.supports_embedded_context = False
        self.supports_load_session = False
        self.supports_session_close = False
        self.supports_session_resume = False
        self.supports_session_list = False
        self.supports_session_delete = False
        self.supports_additional_directories = False
        self.supports_http_mcp = False

    # -- lifecycle -----------------------------------------------------------------

    def start(self) -> None:
        env = build_acp_child_env(
            profile_home=self._profile_home,
            gemini_home=self._gemini_home,
            force_file_storage=self._force_file_storage,
            mux_env=self._mux_env,
        )
        self._proc = subprocess.Popen(
            self._argv,
            cwd=self._cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._threads = [
            threading.Thread(target=self._read_stdout, name="acp-stdout", daemon=True),
            threading.Thread(target=self._read_stderr, name="acp-stderr", daemon=True),
        ]
        for t in self._threads:
            t.start()

    def _build_client_capabilities(self) -> dict[str, Any]:
        # Per ACP v1 spec (SEC-5), derive fs/* and terminal strictly from registered client_handlers.
        caps: dict[str, Any] = {}
        if self._client_capabilities_override is not None:
            for k, v in self._client_capabilities_override.items():
                if k not in ("fs", "terminal"):
                    caps[k] = v
        caps["fs"] = {
            "readTextFile": "fs/read_text_file" in self._client_handlers,
            "writeTextFile": "fs/write_text_file" in self._client_handlers,
        }
        caps["terminal"] = _TERMINAL_METHODS.issubset(self._client_handlers)
        return caps

    def initialize(self, timeout: float | None = 30.0) -> dict[str, Any]:
        params = {
            "protocolVersion": INITIALIZE_PARAMS["protocolVersion"],
            "clientCapabilities": self._build_client_capabilities(),
            "clientInfo": self._client_info,
        }
        result = self.request("initialize", params, timeout=timeout)
        res = result if isinstance(result, dict) else {}
        self.protocol_version = res.get("protocolVersion")
        self.agent_info = res.get("agentInfo") if isinstance(res.get("agentInfo"), dict) else {}
        raw_auth = res.get("authMethods")
        self.agent_auth_methods = (
            [m for m in raw_auth if isinstance(m, dict)] if isinstance(raw_auth, list) else []
        )
        caps = res.get("agentCapabilities") if isinstance(res.get("agentCapabilities"), dict) else {}
        self.agent_capabilities = caps
        pcaps = caps.get("promptCapabilities") if isinstance(caps.get("promptCapabilities"), dict) else {}
        mcaps = caps.get("mcpCapabilities") if isinstance(caps.get("mcpCapabilities"), dict) else {}
        scaps = caps.get("sessionCapabilities") if isinstance(caps.get("sessionCapabilities"), dict) else {}
        self.supports_images = bool(pcaps.get("image"))
        self.supports_embedded_context = bool(pcaps.get("embeddedContext"))
        self.supports_load_session = bool(caps.get("loadSession"))
        self.supports_session_close = _cap_enabled(scaps.get("close"))
        self.supports_session_resume = _cap_enabled(scaps.get("resume"))
        self.supports_session_list = _cap_enabled(scaps.get("list"))
        self.supports_session_delete = _cap_enabled(scaps.get("delete"))
        self.supports_additional_directories = _cap_enabled(
            scaps.get("additionalDirectories")
        ) or _cap_enabled(caps.get("additionalDirectories"))
        self.supports_http_mcp = bool(mcaps.get("http"))
        return result

    def close(self) -> None:
        """Cancel active handlers, shut down worker pool, and reap the child."""
        with self._lock:
            active = list(self._active_client_reqs.values())
            self._active_client_reqs.clear()
            executor, self._executor = self._executor, None
        for ev, _ in active:
            ev.set()
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)

        proc = self._proc
        if proc is None:
            return
        try:
            with self._write_lock:
                if proc.stdin and not proc.stdin.closed:
                    proc.stdin.close()
        except (OSError, ValueError):
            pass
        for stop in (None, proc.terminate, proc.kill):
            if stop:
                try:
                    stop()
                except OSError:
                    pass
            try:
                proc.wait(timeout=2.0)
                break
            except subprocess.TimeoutExpired:
                continue
        for t in self._threads:
            t.join(timeout=2.0)

    @property
    def cwd(self) -> str:
        return self._cwd

    @property
    def stderr_retry_class(self) -> str | None:
        return self._stderr_class

    @property
    def saw_rate_limit(self) -> bool:
        """Sticky per child: any stderr line classified rate-limit (not only the first classified line)."""
        return self._saw_rate_limit

    @property
    def exited(self) -> bool:
        return self._exited.is_set()

    # -- client -> agent -----------------------------------------------------------

    def request(self, method: str, params: dict[str, Any], timeout: float | None = None) -> Any:
        slot = _Pending()
        with self._lock:
            if self._exit_error is not None:
                raise self._exit_error
            rid = next(self._ids)
            self._pending[rid] = slot
        try:
            self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        except (OSError, ValueError):
            self._exited.wait(5.0)  # the reader builds the typed error
            with self._lock:
                self._pending.pop(rid, None)
            raise self._exit_error or AcpError("ACP child stdin closed") from None
        if not slot.event.wait(timeout):
            with self._lock:
                self._pending.pop(rid, None)
            raise TimeoutError(f"ACP request {method} timed out after {timeout}s")
        if slot.error is not None:
            raise slot.error
        return slot.result

    def notify(self, method: str, params: dict[str, Any]) -> None:
        try:
            self._send({"jsonrpc": "2.0", "method": method, "params": params})
        except (OSError, ValueError):
            pass  # child gone: pending requests already fail with the typed exit error

    def respond(self, request_id: Any, result: Any) -> None:
        try:
            self._send({"jsonrpc": "2.0", "id": request_id, "result": result})
        except (OSError, ValueError):
            pass

    def _consume_pending_perm(self, request_id: Any) -> bool:
        """Atomically pop ``request_id`` from ``_pending_perms`` iff still pending."""
        if not _is_valid_rpc_id(request_id):
            return False
        with self._lock:
            for sid, rids in list(self._pending_perms.items()):
                if request_id in rids:
                    rids.remove(request_id)
                    if not rids:
                        self._pending_perms.pop(sid, None)
                    return True
        return False

    def respond_permission(self, request_id: Any, outcome: dict[str, Any]) -> bool:
        """Atomically answer a pending permission request iff it has not already been cancelled."""
        if not self._consume_pending_perm(request_id):
            return False
        self.respond(request_id, outcome)
        return True

    def _send(self, message: dict[str, Any]) -> None:
        assert self._proc is not None and self._proc.stdin is not None
        line = (json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8")
        with self._write_lock:
            if self._proc.stdin.closed:
                raise OSError("ACP child stdin closed")
            self._proc.stdin.write(line)
            self._proc.stdin.flush()

    # -- sessions ------------------------------------------------------------------

    def attach_session(
        self,
        session_id: str,
        on_update: Callable[[dict[str, Any]], None],
        on_permission: PermissionHandler,
    ) -> None:
        """Route one session's updates and permission requests; flush updates buffered so far.

        ``on_update`` runs on the stdout reader thread (and here for the flush) under the dispatch lock, never
        under the connection lock, so order is preserved: it must not block.
        """
        perm_mode = _classify_permission_mode(on_permission)
        with self._dispatch_lock:
            with self._lock:
                self._sessions[session_id] = (on_update, on_permission, perm_mode)
                popped = self._updates.pop(session_id, None)
                if popped is not None:
                    self._unattached_update_count -= len(popped)
                    buffered = list(popped)
                else:
                    buffered = []
            for update in buffered:
                self._call_update(on_update, update)

    def detach_session(self, session_id: str) -> None:
        to_cancel: list[threading.Event] = []
        with self._lock:
            self._sessions.pop(session_id, None)
            popped = self._updates.pop(session_id, None)
            if popped is not None:
                self._unattached_update_count -= len(popped)
            self._pending_perms.pop(session_id, None)
            for rid, (ev, req_sid) in list(self._active_client_reqs.items()):
                if req_sid == session_id:
                    self._active_client_reqs.pop(rid, None)
                    to_cancel.append(ev)
        for ev in to_cancel:
            ev.set()

    def close_session(self, session_id: str, timeout: float = 5.0) -> None:
        """Close a session per ACP v1: call ``session/close`` only if advertised; treat -32002 as success."""
        try:
            if self.supports_session_close and not self.exited:
                try:
                    self.request("session/close", {"sessionId": session_id}, timeout=timeout)
                except AcpRpcError as exc:
                    if exc.code != -32002:  # ACP v1: unknown/already-closed session is idempotent success
                        log.debug("session/close returned error %s for %s", exc.code, session_id)
                except (AcpError, TimeoutError, OSError, ValueError):
                    pass
        finally:
            self.detach_session(session_id)

    def cancel_session(self, session_id: str) -> None:
        """Answer every pending permission request ``cancelled``, then send session/cancel."""
        with self._lock:
            pending = self._pending_perms.pop(session_id, [])
        for request_id in pending:
            self.respond(request_id, CANCELLED_OUTCOME)
        self.notify("session/cancel", {"sessionId": session_id})

    # -- reader threads ------------------------------------------------------------

    def _abort_child_on_framing_error(self) -> None:
        proc = self._proc
        if proc is None:
            return
        try:
            with self._write_lock:
                if proc.stdin and not proc.stdin.closed:
                    proc.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            proc.terminate()
        except OSError:
            pass

    def _read_stdout(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        stdout = self._proc.stdout
        try:
            while True:
                limit = MAX_FRAME_BYTES
                raw = stdout.readline(limit + 1)
                if not raw:
                    break
                if len(raw) > limit:
                    log.warning("ACP stdout frame exceeded %d bytes; closing connection", limit)
                    self._abort_child_on_framing_error()
                    break
                try:
                    msg = json.loads(raw)
                except ValueError:
                    continue
                if isinstance(msg, dict):
                    try:
                        self._dispatch(msg)
                    except Exception:  # noqa: BLE001 - malformed frame must never kill stdout reader
                        log.exception("ACP stdout message dispatch failed")
        finally:
            self._on_exit()

    def _read_stderr(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        # readline(limit) bounds a single huge line; the deque bounds the rest.
        for raw in iter(lambda: self._proc.stderr.readline(_STDERR_LINE_CHARS), b""):
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            self._stderr.append(line)
            cls = _acp_stderr_retry_class([line])
            if self._stderr_class is None:
                self._stderr_class = cls
            if cls == "rate-limit":
                self._saw_rate_limit = True

    def _dispatch(self, msg: dict[str, Any]) -> None:
        method = msg.get("method")
        if method is None:  # response to our request
            rid = msg.get("id")
            if not _is_valid_rpc_id(rid):
                return
            with self._lock:
                slot = self._pending.pop(rid, None)
            if slot is not None:
                if "error" in msg:
                    err = msg["error"] if isinstance(msg["error"], dict) else {}
                    slot.error = AcpRpcError(
                        err.get("code"),
                        str(err.get("message", "")),
                        data=err.get("data"),
                    )
                else:
                    slot.result = msg.get("result")
                slot.event.set()
        elif "id" in msg:
            rid = msg["id"]
            if not _is_valid_rpc_id(rid):
                log.warning("ignoring ACP agent request with invalid JSON-RPC id type %s", type(rid).__name__)
                return
            if not isinstance(method, str):
                self._send_error(rid, -32600, "Invalid Request")
                return
            raw_p = msg.get("params")
            self._handle_agent_request(rid, method, raw_p if isinstance(raw_p, dict) else {})
        elif method == "session/update":
            raw_p = msg.get("params")
            self._handle_update(raw_p if isinstance(raw_p, dict) else {})
        elif method == "$/cancel_request":
            raw_p = msg.get("params")
            self._handle_cancel_request(raw_p if isinstance(raw_p, dict) else {})

    def _handle_update(self, params: dict[str, Any]) -> None:
        sid = params.get("sessionId")
        update = params.get("update")
        if not isinstance(sid, str) or not sid or not isinstance(update, dict):
            return
        with self._dispatch_lock:
            with self._lock:
                entry = self._sessions.get(sid)
                if entry is None:  # may precede the session/new response; bounded (SEC-11)
                    if sid not in self._updates:
                        while len(self._updates) >= MAX_UNATTACHED_SESSIONS:
                            _, evicted = self._updates.popitem(last=False)
                            self._unattached_update_count -= len(evicted)
                        self._updates[sid] = collections.deque()
                    else:
                        self._updates.move_to_end(sid)
                    while self._unattached_update_count >= MAX_UNATTACHED_UPDATES and self._updates:
                        oldest_sid, oldest_q = next(iter(self._updates.items()))
                        oldest_q.popleft()
                        self._unattached_update_count -= 1
                        if not oldest_q:
                            self._updates.pop(oldest_sid, None)
                    if sid not in self._updates:
                        self._updates[sid] = collections.deque()
                    self._updates[sid].append(update)
                    self._unattached_update_count += 1
                    return
            self._call_update(entry[0], update)

    @staticmethod
    def _call_update(consumer: Callable[[dict[str, Any]], None], update: dict[str, Any]) -> None:
        try:
            consumer(update)
        except Exception:  # noqa: BLE001 - a consumer bug must not kill the reader thread
            log.exception("session update consumer failed")

    def _handle_cancel_request(self, params: dict[str, Any]) -> None:
        """Handle incoming ACP ``$/cancel_request`` notification for pending permissions or client requests."""
        req_id = params.get("requestId") if "requestId" in params else params.get("id")
        if not _is_valid_rpc_id(req_id):
            return
        cancel_perm = False
        cancel_client = False
        with self._lock:
            for sid, rids in list(self._pending_perms.items()):
                if req_id in rids:
                    rids.remove(req_id)
                    if not rids:
                        self._pending_perms.pop(sid, None)
                    cancel_perm = True
                    break
            active_entry = self._active_client_reqs.pop(req_id, None)
            if active_entry is not None:
                active_entry[0].set()
                cancel_client = True
        if cancel_perm:
            self.respond(req_id, CANCELLED_OUTCOME)
        if cancel_client:
            self._send_error(req_id, -32800, "Request cancelled")

    def _is_duplicate_inflight_id_locked(self, request_id: Any) -> bool:
        if request_id in self._active_client_reqs:
            return True
        return any(request_id in rids for rids in self._pending_perms.values())

    def _dispatch_client_handler(
        self,
        request_id: Any,
        method: str,
        handler: ClientHandler,
        params: dict[str, Any],
        sid: str | None,
    ) -> None:
        cancelled = threading.Event()
        mode = self._client_handler_modes.get(method, "none")
        err_out: tuple[int, str] | None = None
        executor: concurrent.futures.ThreadPoolExecutor | None = None
        with self._lock:
            if self._is_duplicate_inflight_id_locked(request_id):
                err_out = (-32600, "Duplicate request id")
            elif len(self._active_client_reqs) >= MAX_CLIENT_HANDLER_WORKERS:
                err_out = (-32001, "Client handler capacity exceeded")
            else:
                self._active_client_reqs[request_id] = (cancelled, sid)
                if self._executor is None:
                    self._executor = concurrent.futures.ThreadPoolExecutor(
                        max_workers=MAX_CLIENT_HANDLER_WORKERS,
                        thread_name_prefix="acp-client",
                    )
                executor = self._executor
        if err_out is not None:
            self._send_error(request_id, err_out[0], err_out[1])
            return

        def run() -> None:
            try:
                if mode == "kw":
                    res = handler(params, cancel_event=cancelled)
                elif mode == "pos":
                    res = handler(params, cancelled)
                else:
                    res = handler(params)
            except AcpRpcError as exc:
                code = exc.code if isinstance(exc.code, int) and not isinstance(exc.code, bool) else -32603
                err: tuple[int, str, Any] | None = (
                    code,
                    getattr(exc, "rpc_message", str(exc)),
                    exc.data,
                )
                res = None
            except Exception:  # noqa: BLE001 - never kill worker or leave agent hanging
                log.exception("ACP client handler %s failed", method)
                err = (-32603, f"Internal error in {method}", None)
                res = None
            else:
                err = None
            with self._lock:
                still_active = self._active_client_reqs.pop(request_id, None) is not None
            if not still_active or cancelled.is_set():
                return  # already answered -32800 by $/cancel_request or detached/closed
            if err is not None:
                self._send_error(request_id, err[0], err[1], data=err[2])
            else:
                self.respond(request_id, res if res is not None else {})

        assert executor is not None
        try:
            executor.submit(run)
        except RuntimeError:
            with self._lock:
                self._active_client_reqs.pop(request_id, None)
            cancelled.set()

    def _handle_agent_request(self, request_id: Any, method: str, params: dict[str, Any]) -> None:
        if method != "session/request_permission":
            handler = self._client_handlers.get(method)
            if handler is None:
                self._send_error(request_id, -32601, f"Method not found: {method}")
                return
            session_scoped = method.startswith(_SESSION_SCOPED_PREFIXES) or "sessionId" in params
            sid: str | None = None
            if session_scoped:
                raw_sid = params.get("sessionId")
                with self._lock:
                    active = isinstance(raw_sid, str) and bool(raw_sid) and raw_sid in self._sessions
                if not active:
                    self._send_error(
                        request_id,
                        -32002,
                        "Unknown or inactive session",
                        data={"sessionId": raw_sid},
                    )
                    return
                sid = raw_sid
            self._dispatch_client_handler(request_id, method, handler, params, sid)
            return

        raw_sid = params.get("sessionId")
        dup = False
        entry = None
        with self._lock:
            if isinstance(raw_sid, str) and raw_sid:
                entry = self._sessions.get(raw_sid)
            if entry is not None:
                if self._is_duplicate_inflight_id_locked(request_id):
                    dup = True
                else:
                    self._pending_perms.setdefault(raw_sid, []).append(request_id)
        if dup:
            self._send_error(request_id, -32600, "Duplicate request id")
            return
        if entry is None:
            self.respond(request_id, CANCELLED_OUTCOME)
            return
        perm_handler = entry[1]
        perm_mode = entry[2]
        try:
            if perm_mode == "kw":
                result = perm_handler(params, request_id=request_id)
            elif perm_mode == "pos":
                result = perm_handler(params, request_id)
            else:
                result = perm_handler(params)
        except AcpRpcError as exc:
            if self._consume_pending_perm(request_id):
                code = exc.code if isinstance(exc.code, int) and not isinstance(exc.code, bool) else -32603
                self._send_error(
                    request_id,
                    code,
                    getattr(exc, "rpc_message", str(exc)),
                    data=exc.data,
                )
            return
        except Exception:  # noqa: BLE001 - a broken gate must fail closed, not hang the child
            log.exception("permission handler failed; answering cancelled")
            result = CANCELLED_OUTCOME
        if result is not None:
            self.respond_permission(request_id, result)

    def _send_error(
        self,
        request_id: Any,
        code: int,
        message: str,
        *,
        data: Any = None,
    ) -> None:
        err: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        try:
            self._send({"jsonrpc": "2.0", "id": request_id, "error": err})
        except (OSError, ValueError):
            pass

    def _on_exit(self) -> None:
        proc = self._proc
        assert proc is not None
        try:
            status = proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            status = proc.wait()
        if len(self._threads) > 1:
            self._threads[1].join(timeout=2.0)  # let stderr finish so the diagnostic is complete
        error = AcpProcessExit(
            f"ACP child exited with status {status}; {_acp_stderr_diagnostic(list(self._stderr))}",
            exit_status=status,
            retry_class=self._stderr_class or _acp_stderr_retry_class(list(self._stderr)),
        )
        with self._lock:
            self._exit_error = error
            pending, self._pending = list(self._pending.values()), {}
            active = list(self._active_client_reqs.values())
            self._active_client_reqs.clear()
        for ev, _ in active:
            ev.set()
        for slot in pending:
            slot.error = error
            slot.event.set()
        self._exited.set()
