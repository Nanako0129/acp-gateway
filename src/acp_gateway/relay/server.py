"""Loopback HTTP front end: Anthropic ``/v1/messages`` for model-relay, served by ACP.

Security posture (SEC-10, SEC-11, SEC-13):
- Bound to 127.0.0.1 only; Host must be loopback; any request carrying ``Origin`` or a cross-site
  ``Sec-Fetch-Site`` header (not ``none`` or ``same-origin``) is rejected with 403.
- Handler socket timeout (30 s) bounds header/body reads; disabled only while ``pool.serve(...)``
  waits on the backend and restored in ``finally``.
- Concurrent requests are bounded by ``Server.max_connections = 32`` via a non-blocking
  ``BoundedSemaphore`` returning 529 (``overloaded_error``, ``x-should-retry: false``,
  ``Connection: close``) when saturated.
- ``ProviderError`` logs record exception class name only (never ``str(exc)``).
"""

from __future__ import annotations

import hashlib
import http.server
import json
import logging
import os
import re
import select
import socket
import socketserver
import sys
import threading
import time
from typing import Any

from acp_gateway.core.conversation import CancelledByUser, ProviderError, RateLimited

from .adapter import estimate_tokens, sse, to_message, to_openai
from .pool import BranchPool

logger = logging.getLogger(__name__)

MAX_BODY = 64 * 1024 * 1024
_LOOPBACK = {"127.0.0.1", "localhost", "::1"}
_AGY_REQUESTED = re.compile(r"\A(?:acp-)?(?P<name>gemini-[0-9][A-Za-z0-9._-]{0,120})(?:\[[A-Za-z0-9._-]{1,16}\])?\Z")
_EFFORT_TO_THINKING = {"none": "low", "minimal": "low", "low": "low", "medium": "medium", "high": "high",
                       "xhigh": "xhigh", "max": "xhigh", "ultra": "xhigh"}


def pick_model(requested: Any, default: str) -> str:
    """The request's model when it is a valid ASCII Gemini id agy offers, else the default. Never a non-Gemini id."""
    if not isinstance(requested, str):
        return default
    m = _AGY_REQUESTED.match(requested)
    return m.group("name") if m else default


def pick_thinking(body: dict[str, Any]) -> str | None:
    override = os.environ.get("ACP_GATEWAY_THINKING_LEVEL", "").strip().lower()
    if override:
        return _EFFORT_TO_THINKING.get(override)
    thinking = body.get("thinking")
    if isinstance(thinking, dict) and thinking.get("type") == "disabled":
        return "low"
    out_cfg = body.get("output_config")
    effort = out_cfg.get("effort") if isinstance(out_cfg, dict) else None
    return _EFFORT_TO_THINKING.get(str(effort or "").lower())


def group_key(session_id: str, rows: list[dict[str, Any]], tools: list[dict[str, Any]]) -> str:
    system = rows[0]["content"] if rows and rows[0]["role"] == "system" else ""
    raw = json.dumps([session_id, system, [t["function"]["name"] for t in tools]], ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def is_health_ping(body: dict[str, Any], session_id: str) -> bool:
    """model-relay's /__ping shape: max_tokens 1, one user message, no tools, no system, no session header."""
    msgs = body.get("messages") or []
    return (body.get("max_tokens") == 1 and not body.get("tools") and not body.get("system") and not session_id
            and len(msgs) == 1 and (msgs[0] or {}).get("role") == "user")


def request_problem(body: Any, *, count_only: bool = False) -> str:
    """Why a parsed body cannot be served (checked before anything reads it), or "" when it is fine."""
    if not isinstance(body, dict):
        return "body must be a JSON object"
    try:
        json.dumps(body, ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError:
        return "text contains an unpaired UTF-16 surrogate"
    if not count_only:
        msgs = body.get("messages")
        if not isinstance(msgs, list) or not msgs or not all(isinstance(m, dict) for m in msgs):
            return "messages must be a non-empty list of objects"
        if body.get("thinking") is not None and not isinstance(body.get("thinking"), dict):
            return "thinking must be an object"
        if body.get("output_config") is not None and not isinstance(body.get("output_config"), dict):
            return "output_config must be an object"
    return ""


def _error(kind: str, message: str) -> bytes:
    return json.dumps({"type": "error", "error": {"type": kind, "message": message}}).encode()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30.0
    pool: BranchPool
    default_model: str
    server: Server  # type: ignore[assignment]

    def log_message(self, *a: Any) -> None:
        return

    def _send(self, code: int, body: bytes, ctype: str = "application/json", no_retry: bool = False) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if no_retry:
            self.send_header("x-should-retry", "false")
        if code >= 400:  # the request body may be unread: never reuse this connection
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)

    def _guard(self) -> bool:
        host = (self.headers.get("Host") or "").strip().lower()
        if host.startswith("["):
            host = host[1:].split("]", 1)[0]  # [::1] or [::1]:port
        elif host.count(":") == 1:
            host = host.split(":", 1)[0]  # name:port; a bare IPv6 address keeps its colons
        sfs = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if (
            host not in _LOOPBACK
            or self.headers.get("Origin")
            or (sfs and sfs not in ("none", "same-origin"))
        ):
            self._send(403, _error("permission_error", "loopback clients only"))
            return False
        return True

    def do_GET(self) -> None:
        if not self.server._conn_sem.acquire(blocking=False):
            self._send(529, _error("overloaded_error", "too many concurrent connections"), no_retry=True)
            return
        try:
            self._do_GET()
        finally:
            self.server._conn_sem.release()

    def _do_GET(self) -> None:
        if not self._guard():
            return
        if self.path.split("?", 1)[0] == "/health":
            self._send(200, json.dumps({"ok": True, "children": self.pool.children(),
                                        "standby": self.pool.standby()}).encode())
        else:
            self._send(404, _error("not_found_error", "not found"))

    def do_POST(self) -> None:
        if not self.server._conn_sem.acquire(blocking=False):
            self._send(529, _error("overloaded_error", "too many concurrent connections"), no_retry=True)
            return
        try:
            self._do_POST()
        finally:
            self.server._conn_sem.release()

    def _do_POST(self) -> None:
        if not self._guard():
            return
        path = self.path.split("?", 1)[0]
        if path not in ("/v1/messages", "/v1/messages/count_tokens"):
            self._send(404, _error("not_found_error", "not found"))
            return
        length = self.headers.get("Content-Length")
        if length is None or not (length.isascii() and length.isdigit()):
            self._send(411, _error("invalid_request_error", "Content-Length required"))
            return
        if int(length) > MAX_BODY:
            self._send(413, _error("request_too_large", "body too large"))
            return
        try:
            raw_body = self.rfile.read(int(length))
        except TimeoutError:
            self.close_connection = True
            return
        try:
            body = json.loads(raw_body or b"{}")
            problem = request_problem(body, count_only=path.endswith("/count_tokens"))
        except (ValueError, RecursionError):
            problem = "invalid JSON"
        if problem:
            self._send(400, _error("invalid_request_error", problem))
            return
        if path.endswith("/count_tokens"):
            self._send(200, json.dumps({"input_tokens": estimate_tokens(body)}).encode())
            return
        session_id = str(self.headers.get("x-claude-code-session-id") or "")
        model = pick_model(body.get("model"), self.default_model)
        if is_health_ping(body, session_id):
            logger.info("acp-gateway: health-ping")
            msg = to_message({"text": "", "finish_reason": "stop"}, model, 0)
            msg["usage"] = {"input_tokens": 0, "output_tokens": 0}
            self._reply(body, msg)
            return
        try:
            rows, tools = to_openai(body)
            thinking = pick_thinking(body)
        except (TypeError, AttributeError, ValueError, KeyError):
            self._send(400, _error("invalid_request_error", "malformed Messages request"))
            return
        stateless = not tools and not session_id
        token = threading.Event()
        started = time.monotonic()
        done = threading.Event()
        threading.Thread(target=self._watch_disconnect, args=(token, done), daemon=True).start()
        try:
            self.connection.settimeout(None)
            try:
                result = self.pool.serve(group_key(session_id, rows, tools), rows, tools, model, thinking,
                                         token, stateless=stateless)
            finally:
                done.set()
                try:
                    self.connection.settimeout(self.timeout)
                except OSError:
                    pass
        except RateLimited:
            self._send(429, _error("rate_limit_error", "Antigravity reported 429 RESOURCE_EXHAUSTED"), no_retry=True)
            return
        except CancelledByUser:
            self._send(529, _error("overloaded_error", "request cancelled"), no_retry=True)
            return
        except ProviderError as exc:
            # SEC-10: never log str(exc), which may embed untrusted AcpRpcError.rpc_message
            logger.info("acp-gateway: request failed (%s)", type(exc).__name__)
            self._send(529, _error("overloaded_error", "Antigravity request failed"), no_retry=True)
            return
        thinking_cfg = body.get("thinking")
        include_thinking = not (isinstance(thinking_cfg, dict) and thinking_cfg.get("type") == "disabled")
        msg = to_message(result, model, estimate_tokens(body), include_thinking=include_thinking)
        logger.info("acp-gateway: served %s in %.1fs (%d messages in, %s)", msg["stop_reason"],
                    time.monotonic() - started, len(body.get("messages") or []),
                    ",".join(b["type"] for b in msg["content"]) or "empty")
        self._reply(body, msg)

    def _watch_disconnect(self, token: threading.Event, done: threading.Event) -> None:
        """Cancel the request when the client closes its socket while we wait on the backend (EOF is readable)."""
        sock = self.connection
        while not done.is_set():
            try:
                ready, _, _ = select.select([sock], [], [], 0.5)
                if done.is_set():
                    return
                if ready:
                    if not sock.recv(1, socket.MSG_PEEK):
                        if not done.is_set():
                            logger.info("acp-gateway: client disconnected; cancelling")
                            token.set()
                        return
                    done.wait(0.5)  # unread bytes pending (not EOF): keep polling without spinning
            except (OSError, ValueError):
                if not done.is_set():
                    token.set()
                return

    def _reply(self, body: dict[str, Any], msg: dict[str, Any]) -> None:
        try:
            if body.get("stream"):
                self._send(200, sse(msg), "text/event-stream")
            else:
                self._send(200, json.dumps(msg, ensure_ascii=False).encode("utf-8"))
        except OSError:
            pass  # client gone after commit; nothing left to report


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    max_connections = 32

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type[http.server.BaseHTTPRequestHandler],
        *,
        max_connections: int | None = None,
    ) -> None:
        if max_connections is not None:
            self.max_connections = max_connections
        self._conn_sem = threading.BoundedSemaphore(self.max_connections)
        super().__init__(server_address, RequestHandlerClass)

    def handle_error(self, request, client_address):  # noqa: ANN001 - socketserver signature
        if isinstance(sys.exc_info()[1], (ConnectionResetError, BrokenPipeError, TimeoutError)):
            return  # client went away or timed out; nothing to report
        logger.exception("acp-gateway: unhandled error in a request handler")


def make_server(
    pool: BranchPool,
    port: int,
    default_model: str,
    *,
    max_connections: int | None = None,
) -> Server:
    handler = type("BoundHandler", (Handler,), {"pool": pool, "default_model": default_model})
    return Server(("127.0.0.1", port), handler, max_connections=max_connections)
