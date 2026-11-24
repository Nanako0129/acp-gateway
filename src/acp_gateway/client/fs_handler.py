"""Workspace-scoped ACP filesystem handler (SEC-1, SEC-2).

Enforces:
- Canonical root pinning via open ``dir_fd`` descriptors (``O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC``).
- Strict rejection of non-absolute paths, NUL/control characters, ``.``/``..`` segments,
  and paths equal to or outside canonical workspace roots.
- NFC-normalized, case-insensitive sensitive-path classification on every relative segment
  and basename (``.git``, ``.claude``, ``.gemini``, ``.vscode``, ``.zed``, ``.mcp.json``,
  ``.env``, ``.env.*``, ``id_rsa*``, ``id_ed25519*``, ``*.pem``, ``*.key``, ``*.p12``,
  ``.npmrc``, ``.pypirc``, ``.netrc``).
- Permission gate authorization (``SEC-1``) BEFORE any directory creation or file open.
- Component-by-component ``dir_fd`` traversal with ``O_NOFOLLOW`` (handling macOS
  ``ENOTDIR`` as well as Linux ``ELOOP`` for symlink directories).
- Non-blocking open (``O_NONBLOCK``) + immediate ``fstat`` regular-file check on read so
  unopened FIFOs and device nodes never hang the worker thread.
- Atomic sibling temp write + ``fsync`` + POSIX ``renameat`` (``os.rename(..., src_dir_fd=...,
  dst_dir_fd=...)``) with symlink refusal and size caps.
"""

from __future__ import annotations

import contextlib
import errno
import os
import secrets
import stat
import threading
import unicodedata
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Self

from acp_gateway.core.acp_connection import AcpRpcError

from .permission_policy import ActionRequest, ClientPermissionGate

_SENSITIVE_EXACT: frozenset[str] = frozenset(
    {
        ".git",
        ".claude",
        ".gemini",
        ".vscode",
        ".zed",
        ".mcp.json",
        ".env",
        ".npmrc",
        ".pypirc",
        ".netrc",
    }
)
_SENSITIVE_PREFIXES: tuple[str, ...] = (".env.", "id_rsa", "id_ed25519")
_SENSITIVE_SUFFIXES: tuple[str, ...] = (".pem", ".key", ".p12")


def is_sensitive_relpath(segments: Sequence[str]) -> bool:
    """Return True if any path segment or basename matches sensitive credential/config rules."""
    for seg in segments:
        norm = unicodedata.normalize("NFC", seg).casefold()
        if norm in _SENSITIVE_EXACT:
            return True
        if norm.startswith(_SENSITIVE_PREFIXES):
            return True
        if norm.endswith(_SENSITIVE_SUFFIXES):
            return True
    return False


def _has_control_chars(value: str) -> bool:
    return any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)


def _validate_positive_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise AcpRpcError(-32602, f"Invalid {name} parameter")
    return value


class WorkspaceFsHandler:
    """ACP ``fs/read_text_file`` and ``fs/write_text_file`` handler pinned to workspace roots."""

    def __init__(
        self,
        roots: Sequence[str | Path],
        gate: ClientPermissionGate,
        *,
        max_read_bytes: int = 2 * 1024 * 1024,
        max_write_bytes: int = 2 * 1024 * 1024,
        allow_create_dirs: bool = True,
    ) -> None:
        if not roots:
            raise ValueError("at least one workspace root is required")
        if not isinstance(max_read_bytes, int) or isinstance(max_read_bytes, bool) or max_read_bytes < 1:
            raise ValueError("max_read_bytes must be a positive integer")
        if not isinstance(max_write_bytes, int) or isinstance(max_write_bytes, bool) or max_write_bytes < 1:
            raise ValueError("max_write_bytes must be a positive integer")

        self._gate = gate
        self._max_read_bytes = max_read_bytes
        self._max_write_bytes = max_write_bytes
        self._allow_create_dirs = bool(allow_create_dirs)
        self._lock = threading.RLock()
        self._closed = False

        pinned: dict[str, int] = {}
        try:
            for raw_root in roots:
                real = os.path.realpath(os.fspath(raw_root))
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

        # Match longest (most specific) canonical root first.
        self._roots: list[tuple[str, int]] = sorted(
            pinned.items(), key=lambda item: len(item[0]), reverse=True
        )
        self._root_fds: dict[str, int] = dict(self._roots)

    @property
    def roots(self) -> tuple[str, ...]:
        return tuple(r for r, _ in self._roots)

    def close(self) -> None:
        """Close all pinned root directory file descriptors."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            fds = list(self._root_fds.values())
            self._root_fds.clear()
        for fd in fds:
            with contextlib.suppress(OSError):
                os.close(fd)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _dup_root_fd(self, root_path: str) -> int:
        with self._lock:
            if self._closed:
                raise AcpRpcError(-32001, "Filesystem handler is closed")
            root_fd = self._root_fds.get(root_path)
            if root_fd is None:
                raise AcpRpcError(-32002, "Workspace root is no longer available")
            return os.dup(root_fd)

    def _resolve_file_target(self, raw_path: Any) -> tuple[str, list[str], str]:
        """Validate ``raw_path`` and decompose it into ``(canonical_root, segments, relpath)``."""
        if not isinstance(raw_path, str) or not raw_path:
            raise AcpRpcError(-32602, "Invalid path: must be a non-empty string")
        if _has_control_chars(raw_path):
            raise AcpRpcError(-32602, "Invalid path: control characters are not allowed")
        if not raw_path.startswith("/") or not os.path.isabs(raw_path):
            raise AcpRpcError(-32602, "Invalid path: must be absolute")
        if raw_path.endswith("/"):
            raise AcpRpcError(-32602, "Invalid path: file path must not end with '/'")

        raw_parts = raw_path.split("/")
        if any(part in (".", "..") for part in raw_parts):
            raise AcpRpcError(-32602, "Invalid path: '.' and '..' segments are not allowed")

        for root_path, _ in self._roots:
            if raw_path == root_path:
                raise AcpRpcError(-32602, "Path must be a file strictly beneath a workspace root")
            prefix = "/" if root_path == "/" else root_path + "/"
            if raw_path.startswith(prefix):
                rel = raw_path[len(prefix) :]
                segments = [s for s in rel.split("/") if s]
                if not segments:
                    raise AcpRpcError(-32602, "Path must be a file strictly beneath a workspace root")
                return root_path, segments, "/".join(segments)

        raise AcpRpcError(-32002, "Path is outside allowed workspace roots")

    @staticmethod
    def _map_walk_error(exc: OSError) -> AcpRpcError:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK, errno.ENOENT):
            return AcpRpcError(-32002, "Path not found or symlink traversal denied")
        if exc.errno in (errno.EACCES, errno.EPERM):
            return AcpRpcError(-32001, "Permission denied")
        return AcpRpcError(-32603, f"Filesystem error: errno {exc.errno}")

    def _walk_parent_dir(
        self,
        root_path: str,
        parent_segments: Sequence[str],
        *,
        create_missing: bool,
        cancel_event: threading.Event | None = None,
    ) -> int:
        """Walk ``parent_segments`` from the pinned root FD without following symlinks."""
        cur_fd = self._dup_root_fd(root_path)
        try:
            for seg in parent_segments:
                if cancel_event is not None and cancel_event.is_set():
                    raise AcpRpcError(-32800, "Request cancelled")
                try:
                    next_fd = os.open(
                        seg,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=cur_fd,
                    )
                except OSError as exc:
                    if create_missing and exc.errno == errno.ENOENT:
                        try:
                            os.mkdir(seg, 0o755, dir_fd=cur_fd)
                        except OSError as mk_exc:
                            if mk_exc.errno != errno.EEXIST:
                                raise self._map_walk_error(mk_exc) from None
                        try:
                            next_fd = os.open(
                                seg,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=cur_fd,
                            )
                        except OSError as reopen_exc:
                            raise self._map_walk_error(reopen_exc) from None
                    else:
                        raise self._map_walk_error(exc) from None
                os.close(cur_fd)
                cur_fd = next_fd
            return cur_fd
        except BaseException:
            os.close(cur_fd)
            raise

    def read_text_file(
        self,
        params: dict[str, Any],
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        """Handle ACP ``fs/read_text_file`` with symlink-safe, non-blocking, bounded reads."""
        if not isinstance(params, dict):
            raise AcpRpcError(-32602, "Invalid params")
        sid = params.get("sessionId")
        if not isinstance(sid, str) or not sid:
            raise AcpRpcError(-32602, "Missing or invalid sessionId")

        root_path, segments, relpath = self._resolve_file_target(params.get("path"))

        line: int | None = None
        if "line" in params and params["line"] is not None:
            line = _validate_positive_int(params["line"], "line")
        limit: int | None = None
        if "limit" in params and params["limit"] is not None:
            limit = _validate_positive_int(params["limit"], "limit")

        action = ActionRequest(
            kind="fs_read",
            session_id=sid,
            root=root_path,
            relpath=relpath,
            sensitive=is_sensitive_relpath(segments),
        )
        if not self._gate.authorize_action(action, cancel_event=cancel_event):
            raise AcpRpcError(-32001, "Filesystem read denied by permission policy")

        if cancel_event is not None and cancel_event.is_set():
            raise AcpRpcError(-32800, "Request cancelled")

        parent_fd = self._walk_parent_dir(
            root_path,
            segments[:-1],
            create_missing=False,
            cancel_event=cancel_event,
        )
        try:
            basename = segments[-1]
            try:
                # O_NONBLOCK prevents an unopened FIFO from blocking in open() before fstat().
                fd = os.open(
                    basename,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                    dir_fd=parent_fd,
                )
            except OSError as exc:
                if exc.errno in (errno.ENOENT, errno.ELOOP, errno.EMLINK, errno.ENOTDIR):
                    raise AcpRpcError(-32002, "File not found or symlink denied") from None
                if exc.errno == errno.EISDIR:
                    raise AcpRpcError(-32602, "Path is not a regular file") from None
                if exc.errno in (errno.EACCES, errno.EPERM):
                    raise AcpRpcError(-32001, "Permission denied") from None
                raise AcpRpcError(-32603, f"Unable to open file: errno {exc.errno}") from None

            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise AcpRpcError(-32602, "Path is not a regular file")
                buf = bytearray()
                cap = self._max_read_bytes + 1
                while len(buf) < cap:
                    if cancel_event is not None and cancel_event.is_set():
                        raise AcpRpcError(-32800, "Request cancelled")
                    chunk = os.read(fd, min(65536, cap - len(buf)))
                    if not chunk:
                        break
                    buf.extend(chunk)
                if len(buf) > self._max_read_bytes:
                    raise AcpRpcError(
                        -32602,
                        f"File exceeds maximum read size ({self._max_read_bytes} bytes)",
                    )
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)

        try:
            text = buf.decode("utf-8")
        except UnicodeDecodeError:
            raise AcpRpcError(-32602, "File is not valid UTF-8 text") from None

        if line is None and limit is None:
            return {"content": text}

        lines = text.splitlines(keepends=True)
        if line is not None:
            if not lines:
                if line > 1:
                    raise AcpRpcError(-32602, "Requested line is past end of file")
                start = 0
            else:
                if line > len(lines):
                    raise AcpRpcError(-32602, "Requested line is past end of file")
                start = line - 1
        else:
            start = 0

        selected = lines[start : start + limit] if limit is not None else lines[start:]
        return {"content": "".join(selected)}

    def write_text_file(
        self,
        params: dict[str, Any],
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        """Handle ACP ``fs/write_text_file`` with symlink-safe atomic sibling temp writes."""
        if not isinstance(params, dict):
            raise AcpRpcError(-32602, "Invalid params")
        sid = params.get("sessionId")
        if not isinstance(sid, str) or not sid:
            raise AcpRpcError(-32602, "Missing or invalid sessionId")

        root_path, segments, relpath = self._resolve_file_target(params.get("path"))

        content = params.get("content")
        if not isinstance(content, str):
            raise AcpRpcError(-32602, "Invalid content: must be a string")
        try:
            payload = content.encode("utf-8")
        except UnicodeEncodeError:
            raise AcpRpcError(-32602, "Invalid content: not valid UTF-8") from None
        if len(payload) > self._max_write_bytes:
            raise AcpRpcError(
                -32602,
                f"Content exceeds maximum write size ({self._max_write_bytes} bytes)",
            )

        action = ActionRequest(
            kind="fs_write",
            session_id=sid,
            root=root_path,
            relpath=relpath,
            sensitive=is_sensitive_relpath(segments),
            byte_length=len(payload),
        )
        if not self._gate.authorize_action(action, cancel_event=cancel_event):
            raise AcpRpcError(-32001, "Filesystem write denied by permission policy")

        if cancel_event is not None and cancel_event.is_set():
            raise AcpRpcError(-32800, "Request cancelled")

        parent_fd = self._walk_parent_dir(
            root_path,
            segments[:-1],
            create_missing=self._allow_create_dirs,
            cancel_event=cancel_event,
        )
        try:
            basename = segments[-1]
            mode = 0o600
            try:
                existing_st = os.stat(basename, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                existing_st = None
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
                    raise AcpRpcError(-32002, "Symlink traversal denied") from None
                if exc.errno in (errno.EACCES, errno.EPERM):
                    raise AcpRpcError(-32001, "Permission denied") from None
                raise AcpRpcError(-32603, f"Unable to stat target: errno {exc.errno}") from None

            if existing_st is not None:
                if stat.S_ISLNK(existing_st.st_mode):
                    raise AcpRpcError(-32002, "Refusing to overwrite symlink")
                if not stat.S_ISREG(existing_st.st_mode):
                    raise AcpRpcError(-32602, "Target exists and is not a regular file")
                mode = existing_st.st_mode & 0o777

            tmp_name = f".acp-tmp-{secrets.token_hex(12)}"
            tmp_fd: int | None = None
            created = False
            try:
                tmp_fd = os.open(
                    tmp_name,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    mode,
                    dir_fd=parent_fd,
                )
                created = True
                with contextlib.suppress(OSError):
                    os.fchmod(tmp_fd, mode)
                view = memoryview(payload)
                written = 0
                while written < len(payload):
                    if cancel_event is not None and cancel_event.is_set():
                        raise AcpRpcError(-32800, "Request cancelled")
                    n = os.write(tmp_fd, view[written : written + 65536])
                    if n <= 0:
                        raise AcpRpcError(-32603, "Short write while writing file")
                    written += n
                os.fsync(tmp_fd)
                os.close(tmp_fd)
                tmp_fd = None
                if cancel_event is not None and cancel_event.is_set():
                    raise AcpRpcError(-32800, "Request cancelled")
                # POSIX renameat: os.replace does not support dir_fd on macOS.
                os.rename(tmp_name, basename, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                created = False
                with contextlib.suppress(OSError):
                    os.fsync(parent_fd)
            except AcpRpcError:
                raise
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
                    raise AcpRpcError(-32002, "Symlink or directory conflict on write") from None
                if exc.errno in (errno.EACCES, errno.EPERM):
                    raise AcpRpcError(-32001, "Permission denied") from None
                raise AcpRpcError(-32603, f"Filesystem write error: errno {exc.errno}") from None
            finally:
                if tmp_fd is not None:
                    with contextlib.suppress(OSError):
                        os.close(tmp_fd)
                if created:
                    with contextlib.suppress(OSError):
                        os.unlink(tmp_name, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)

        return {}
