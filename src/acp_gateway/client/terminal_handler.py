"""Workspace-scoped ACP terminal handler (SEC-1, SEC-3, SEC-8).

SECURITY BOUNDARY WARNING:
Root pinning, ``cwd`` traversal validation, minimal child environments, and dangerous
environment variable blocking provide application-layer containment ONLY — they are NOT
an OS sandbox. Once a command is authorized and spawned, it runs with the invoking OS
user's privileges and can access files outside workspace roots or the network unless
wrapped in an external OS sandbox (e.g., container, Seatbelt, or bubblewrap).
"""

from __future__ import annotations

import contextlib
import errno
import os
import secrets
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Self

from acp_gateway.core.acp_connection import AcpRpcError

from .permission_policy import ActionRequest, ClientPermissionGate

DEFAULT_ALLOWED_PATH_ENV = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin"

_BLOCKED_ENV_EXACT: frozenset[str] = frozenset(
    {
        "BASH_ENV",
        "ENV",
        "ZDOTDIR",
        "PROMPT_COMMAND",
        "IFS",
        "NODE_OPTIONS",
        "PERL5OPT",
        "PERL5LIB",
        "RUBYOPT",
        "RUBYLIB",
        "GIT_SSH_COMMAND",
        "GIT_EXEC_PATH",
        "GIT_TEMPLATE_DIR",
        "GIT_CONFIG",
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
        "TMPDIR",
    }
)
_BLOCKED_ENV_PREFIXES: tuple[str, ...] = (
    "DYLD_",
    "LD_",
    "PYTHON",
    "GIT_CONFIG_",
)


def _has_control_chars(value: str) -> bool:
    return any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)


def _is_blocked_env_name(name: str) -> bool:
    upper = name.upper()
    if upper in _BLOCKED_ENV_EXACT:
        return True
    return upper.startswith(_BLOCKED_ENV_PREFIXES)


def _signal_name(sig_num: int) -> str:
    try:
        return signal.Signals(sig_num).name
    except ValueError:
        return f"SIG{sig_num}"


def _decode_tail(raw: bytes, truncated: bool) -> str:
    """Decode tail bytes safely without splitting a leading multibyte UTF-8 character."""
    if truncated and raw:
        idx = 0
        while idx < len(raw) and 0x80 <= raw[idx] <= 0xBF:
            idx += 1
        raw = raw[idx:]
    return raw.decode("utf-8", errors="replace")


@dataclass
class _TerminalEntry:
    terminal_id: str
    session_id: str
    proc: subprocess.Popen[bytes]
    pgid: int
    byte_limit: int
    tmp_dir: str
    buf: bytearray = field(default_factory=bytearray)
    truncated: bool = False
    buf_lock: threading.Lock = field(default_factory=threading.Lock)
    done: threading.Event = field(default_factory=threading.Event)
    exit_code: int | None = None
    signal_name: str | None = None
    reader: threading.Thread | None = None
    watchdog: threading.Timer | None = None


class WorkspaceTerminalHandler:
    """ACP ``terminal/*`` handler with symlink-safe ``cwd``, minimal env, and process-group reaping.

    NOTE: This handler provides application-layer containment only, NOT an OS sandbox.
    """

    def __init__(
        self,
        roots: Sequence[str | Path],
        gate: ClientPermissionGate,
        *,
        max_terminals: int = 8,
        default_output_byte_limit: int = 256 * 1024,
        max_output_byte_limit: int = 4 * 1024 * 1024,
        max_runtime_seconds: float = 300.0,
        allowed_path_env: str = DEFAULT_ALLOWED_PATH_ENV,
    ) -> None:
        if not roots:
            raise ValueError("at least one workspace root is required")
        if not isinstance(max_terminals, int) or isinstance(max_terminals, bool) or max_terminals < 1:
            raise ValueError("max_terminals must be a positive integer")
        if (
            not isinstance(default_output_byte_limit, int)
            or isinstance(default_output_byte_limit, bool)
            or default_output_byte_limit < 1
        ):
            raise ValueError("default_output_byte_limit must be a positive integer")
        if (
            not isinstance(max_output_byte_limit, int)
            or isinstance(max_output_byte_limit, bool)
            or max_output_byte_limit < 1
        ):
            raise ValueError("max_output_byte_limit must be a positive integer")
        if (
            not isinstance(max_runtime_seconds, (int, float))
            or isinstance(max_runtime_seconds, bool)
            or max_runtime_seconds <= 0
        ):
            raise ValueError("max_runtime_seconds must be positive")
        if not isinstance(allowed_path_env, str) or "\x00" in allowed_path_env:
            raise ValueError("allowed_path_env must be a valid string")

        self._gate = gate
        self._max_terminals = max_terminals
        self._default_output_byte_limit = min(default_output_byte_limit, max_output_byte_limit)
        self._max_output_byte_limit = max_output_byte_limit
        self._max_runtime_seconds = float(max_runtime_seconds)
        self._allowed_path_env = allowed_path_env

        self._lock = threading.RLock()
        self._closed = False
        self._reserving = 0
        self._terminals: dict[str, _TerminalEntry] = {}

        pinned: dict[str, int] = {}
        first_root: str | None = None
        try:
            for raw_root in roots:
                real = os.path.realpath(os.fspath(raw_root))
                if first_root is None:
                    first_root = real
                if real in pinned:
                    continue
                fd = os.open(real, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    st = os.fstat(fd)
                    if not stat.S_ISDIR(st.st_mode):
                        raise ValueError(f"workspace root is not a directory: {real}")
                except BaseException:
                    os.close(fd)
                    raise
                pinned[real] = fd
        except BaseException:
            for fd in pinned.values():
                with contextlib.suppress(OSError):
                    os.close(fd)
            raise

        assert first_root is not None
        self._default_root: str = first_root
        self._roots: list[tuple[str, int]] = sorted(
            pinned.items(), key=lambda item: len(item[0]), reverse=True
        )
        self._root_fds: dict[str, int] = dict(self._roots)

    @property
    def roots(self) -> tuple[str, ...]:
        return tuple(r for r, _ in self._roots)

    def _dup_root_fd(self, root_path: str) -> int:
        with self._lock:
            if self._closed:
                raise AcpRpcError(-32001, "Terminal handler is closed")
            root_fd = self._root_fds.get(root_path)
            if root_fd is None:
                raise AcpRpcError(-32002, "Workspace root is no longer available")
            return os.dup(root_fd)

    def _resolve_cwd(
        self,
        raw_cwd: Any,
        cancel_event: threading.Event | None = None,
    ) -> tuple[str, str]:
        """Validate ``cwd`` beneath canonical roots by walking every component with ``O_NOFOLLOW``."""
        if raw_cwd is None:
            # Verify default root FD is still open/valid.
            fd = self._dup_root_fd(self._default_root)
            os.close(fd)
            return self._default_root, self._default_root

        if not isinstance(raw_cwd, str) or not raw_cwd:
            raise AcpRpcError(-32602, "Invalid cwd: must be a non-empty string")
        if _has_control_chars(raw_cwd):
            raise AcpRpcError(-32602, "Invalid cwd: control characters are not allowed")
        if not raw_cwd.startswith("/") or not os.path.isabs(raw_cwd):
            raise AcpRpcError(-32602, "Invalid cwd: must be absolute")

        raw_parts = raw_cwd.split("/")
        if any(part in (".", "..") for part in raw_parts):
            raise AcpRpcError(-32602, "Invalid cwd: '.' and '..' segments are not allowed")

        norm_cwd = raw_cwd.rstrip("/") or "/"
        matched_root: str | None = None
        rel_segments: list[str] = []
        for root_path, _ in self._roots:
            if norm_cwd == root_path:
                matched_root = root_path
                rel_segments = []
                break
            prefix = "/" if root_path == "/" else root_path + "/"
            if norm_cwd.startswith(prefix):
                matched_root = root_path
                rel_segments = [s for s in norm_cwd[len(prefix) :].split("/") if s]
                break

        if matched_root is None:
            raise AcpRpcError(-32002, "Working directory is outside allowed workspace roots")

        cur_fd = self._dup_root_fd(matched_root)
        try:
            for seg in rel_segments:
                if cancel_event is not None and cancel_event.is_set():
                    raise AcpRpcError(-32800, "Request cancelled")
                try:
                    next_fd = os.open(
                        seg,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=cur_fd,
                    )
                except OSError as exc:
                    if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK, errno.ENOENT):
                        raise AcpRpcError(
                            -32002,
                            "Working directory not found or symlink traversal denied",
                        ) from None
                    if exc.errno in (errno.EACCES, errno.EPERM):
                        raise AcpRpcError(-32001, "Permission denied") from None
                    raise AcpRpcError(-32603, f"Filesystem error: errno {exc.errno}") from None
                os.close(cur_fd)
                cur_fd = next_fd
        finally:
            os.close(cur_fd)

        resolved = matched_root if not rel_segments else os.path.join(matched_root, *rel_segments)
        return matched_root, resolved

    @staticmethod
    def _validate_agent_env(raw_env: Any) -> dict[str, str]:
        if raw_env is None:
            return {}
        if not isinstance(raw_env, list):
            raise AcpRpcError(-32602, "Invalid env: must be a list of {name, value} objects")
        validated: dict[str, str] = {}
        for item in raw_env:
            if not isinstance(item, dict):
                raise AcpRpcError(-32602, "Invalid env entry")
            name = item.get("name")
            value = item.get("value")
            if not isinstance(name, str) or not isinstance(value, str):
                raise AcpRpcError(-32602, "Invalid env entry: name and value must be strings")
            if not name or "=" in name or "\x00" in name or "\x00" in value:
                raise AcpRpcError(-32602, "Invalid env name or value")
            if _is_blocked_env_name(name):
                raise AcpRpcError(-32602, f"Environment variable is not permitted: {name}")
            validated[name] = value
        return validated

    @staticmethod
    def _kill_pg(entry: _TerminalEntry, *, grace: float = 0.5) -> None:
        if entry.done.is_set():
            return
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.killpg(entry.pgid, signal.SIGTERM)
        if not entry.done.wait(timeout=grace):
            with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                os.killpg(entry.pgid, signal.SIGKILL)

    def _on_watchdog(self, entry: _TerminalEntry) -> None:
        self._kill_pg(entry, grace=0.5)

    @staticmethod
    def _read_loop(entry: _TerminalEntry) -> None:
        stdout = entry.proc.stdout
        assert stdout is not None
        limit = entry.byte_limit
        try:
            while True:
                chunk = stdout.read(8192)
                if not chunk:
                    break
                with entry.buf_lock:
                    if len(chunk) >= limit:
                        entry.buf[:] = chunk[-limit:]
                        entry.truncated = True
                    else:
                        entry.buf.extend(chunk)
                        excess = len(entry.buf) - limit
                        if excess > 0:
                            del entry.buf[:excess]
                            entry.truncated = True
        except (OSError, ValueError):
            pass
        finally:
            with contextlib.suppress(OSError, ValueError):
                stdout.close()
            rc = entry.proc.wait()
            with entry.buf_lock:
                if rc >= 0:
                    entry.exit_code = rc
                    entry.signal_name = None
                else:
                    entry.exit_code = None
                    entry.signal_name = _signal_name(-rc)
            if entry.watchdog is not None:
                entry.watchdog.cancel()
            entry.done.set()

    def _cleanup_entry(self, entry: _TerminalEntry) -> None:
        if entry.watchdog is not None:
            entry.watchdog.cancel()
        self._kill_pg(entry, grace=0.5)
        if entry.reader is not None and entry.reader is not threading.current_thread():
            entry.reader.join(timeout=3.0)
        shutil.rmtree(entry.tmp_dir, ignore_errors=True)

    def _lookup_terminal(self, params: dict[str, Any]) -> tuple[str, _TerminalEntry]:
        if not isinstance(params, dict):
            raise AcpRpcError(-32602, "Invalid params")
        sid = params.get("sessionId")
        tid = params.get("terminalId")
        if not isinstance(sid, str) or not sid:
            raise AcpRpcError(-32602, "Missing or invalid sessionId")
        if not isinstance(tid, str) or not tid:
            raise AcpRpcError(-32602, "Missing or invalid terminalId")
        with self._lock:
            entry = self._terminals.get(tid)
        if entry is None or entry.session_id != sid:
            raise AcpRpcError(
                -32002,
                "Unknown terminal for session",
                data={"terminalId": tid},
            )
        return tid, entry

    # -- ACP terminal/* methods ----------------------------------------------------

    def create(
        self,
        params: dict[str, Any],
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        """Handle ACP ``terminal/create``."""
        if not isinstance(params, dict):
            raise AcpRpcError(-32602, "Invalid params")
        sid = params.get("sessionId")
        if not isinstance(sid, str) or not sid:
            raise AcpRpcError(-32602, "Missing or invalid sessionId")

        command = params.get("command")
        if not isinstance(command, str) or not command or "\x00" in command:
            raise AcpRpcError(-32602, "Invalid command")

        raw_args = params.get("args")
        if raw_args is None:
            args: list[str] = []
        elif isinstance(raw_args, list) and all(
            isinstance(a, str) and "\x00" not in a for a in raw_args
        ):
            args = list(raw_args)
        else:
            raise AcpRpcError(-32602, "Invalid args: must be a list of strings without NUL bytes")

        raw_limit = params.get("outputByteLimit")
        if raw_limit is None:
            byte_limit = self._default_output_byte_limit
        elif not isinstance(raw_limit, int) or isinstance(raw_limit, bool) or raw_limit < 1:
            raise AcpRpcError(-32602, "Invalid outputByteLimit")
        else:
            byte_limit = min(raw_limit, self._max_output_byte_limit)

        agent_env = self._validate_agent_env(params.get("env"))
        root_path, resolved_cwd = self._resolve_cwd(params.get("cwd"), cancel_event=cancel_event)

        action = ActionRequest(
            kind="terminal_create",
            session_id=sid,
            root=root_path,
            command=command,
            args=tuple(args),
            cwd=resolved_cwd,
            env_keys=tuple(sorted(agent_env)),
        )
        if not self._gate.authorize_action(action, cancel_event=cancel_event):
            raise AcpRpcError(-32001, "Terminal creation denied by permission policy")

        if cancel_event is not None and cancel_event.is_set():
            raise AcpRpcError(-32800, "Request cancelled")

        with self._lock:
            if self._closed:
                raise AcpRpcError(-32001, "Terminal handler is closed")
            if len(self._terminals) + self._reserving >= self._max_terminals:
                raise AcpRpcError(
                    -32001,
                    f"Maximum concurrent terminals ({self._max_terminals}) reached",
                )
            self._reserving += 1

        tmp_dir: str | None = None
        proc: subprocess.Popen[bytes] | None = None
        registered = False
        try:
            tmp_dir = tempfile.mkdtemp(prefix="acp-term-")
            os.chmod(tmp_dir, 0o700)
            # Zero ambient os.environ inheritance (SEC-3).
            child_env: dict[str, str] = {
                "PATH": self._allowed_path_env,
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "TERM": "dumb",
                "PAGER": "cat",
                "GIT_PAGER": "cat",
                "NO_COLOR": "1",
                "TMPDIR": tmp_dir,
            }
            child_env.update(agent_env)

            try:
                proc = subprocess.Popen(
                    [command, *args],
                    cwd=resolved_cwd,
                    env=child_env,
                    shell=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    close_fds=True,
                )
            except FileNotFoundError:
                raise AcpRpcError(-32002, "Command not found") from None
            except PermissionError:
                raise AcpRpcError(-32001, "Command is not executable") from None
            except OSError as exc:
                raise AcpRpcError(-32603, f"Failed to spawn command: errno {exc.errno}") from None

            tid = f"term-{secrets.token_hex(16)}"
            entry = _TerminalEntry(
                terminal_id=tid,
                session_id=sid,
                proc=proc,
                pgid=proc.pid,
                byte_limit=byte_limit,
                tmp_dir=tmp_dir,
            )

            reader = threading.Thread(
                target=self._read_loop,
                args=(entry,),
                name=f"acp-term-{tid[:12]}",
                daemon=True,
            )
            entry.reader = reader
            watchdog = threading.Timer(self._max_runtime_seconds, self._on_watchdog, args=(entry,))
            watchdog.daemon = True
            entry.watchdog = watchdog

            with self._lock:
                if self._closed:
                    raise AcpRpcError(-32001, "Terminal handler is closed")
                self._terminals[tid] = entry
                self._reserving -= 1
                registered = True
                reader.start()
                watchdog.start()
            return {"terminalId": tid}
        finally:
            if not registered:
                with self._lock:
                    self._reserving -= 1
                if proc is not None:
                    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                        os.killpg(proc.pid, signal.SIGKILL)
                    with contextlib.suppress(OSError, ValueError):
                        if proc.stdout:
                            proc.stdout.close()
                    with contextlib.suppress(OSError):
                        proc.wait(timeout=2.0)
                if tmp_dir is not None:
                    shutil.rmtree(tmp_dir, ignore_errors=True)

    def output(
        self,
        params: dict[str, Any],
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        """Handle ACP ``terminal/output``."""
        _ = cancel_event
        _, entry = self._lookup_terminal(params)
        with entry.buf_lock:
            raw = bytes(entry.buf)
            truncated = entry.truncated
            done = entry.done.is_set()
            exit_code = entry.exit_code
            sig_name = entry.signal_name
        result: dict[str, Any] = {
            "output": _decode_tail(raw, truncated),
            "truncated": truncated,
        }
        if done:
            result["exitStatus"] = {"exitCode": exit_code, "signal": sig_name}
        return result

    def wait_for_exit(
        self,
        params: dict[str, Any],
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        """Handle ACP ``terminal/wait_for_exit``, waking promptly on ``cancel_event``."""
        _, entry = self._lookup_terminal(params)
        while not entry.done.is_set():
            if cancel_event is not None and cancel_event.is_set():
                raise AcpRpcError(-32800, "Request cancelled")
            entry.done.wait(timeout=0.05)
        with entry.buf_lock:
            return {"exitCode": entry.exit_code, "signal": entry.signal_name}

    def kill(
        self,
        params: dict[str, Any],
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        """Handle ACP ``terminal/kill``: terminate process group while keeping output readable."""
        _ = cancel_event
        _, entry = self._lookup_terminal(params)
        self._kill_pg(entry, grace=0.5)
        return {}

    def release(
        self,
        params: dict[str, Any],
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        """Handle ACP ``terminal/release``: kill if active, join reader, and remove temp dir."""
        _ = cancel_event
        if not isinstance(params, dict):
            raise AcpRpcError(-32602, "Invalid params")
        sid = params.get("sessionId")
        tid = params.get("terminalId")
        if not isinstance(sid, str) or not sid:
            raise AcpRpcError(-32602, "Missing or invalid sessionId")
        if not isinstance(tid, str) or not tid:
            raise AcpRpcError(-32602, "Missing or invalid terminalId")
        with self._lock:
            entry = self._terminals.get(tid)
            if entry is None or entry.session_id != sid:
                raise AcpRpcError(
                    -32002,
                    "Unknown terminal for session",
                    data={"terminalId": tid},
                )
            self._terminals.pop(tid, None)
        self._cleanup_entry(entry)
        return {}

    # -- Lifecycle cleanup ---------------------------------------------------------

    def release_session(self, session_id: str) -> None:
        """Terminate and release all terminals bound to ``session_id``."""
        with self._lock:
            tids = [tid for tid, e in self._terminals.items() if e.session_id == session_id]
            entries = [self._terminals.pop(tid) for tid in tids]
        for entry in entries:
            self._cleanup_entry(entry)

    def close_all(self) -> None:
        """Terminate and release all active terminals across every session."""
        with self._lock:
            entries = list(self._terminals.values())
            self._terminals.clear()
        for entry in entries:
            self._cleanup_entry(entry)

    def close(self) -> None:
        """Shut down all terminals and close pinned workspace root descriptors."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            root_fds = list(self._root_fds.values())
            self._root_fds.clear()
        self.close_all()
        for fd in root_fds:
            with contextlib.suppress(OSError):
                os.close(fd)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
