"""Unit and adversarial security tests for WorkspaceFsHandler (SEC-1, SEC-2)."""

from __future__ import annotations

import os
import stat
import threading
import time
from pathlib import Path

import pytest

from acp_gateway.client.fs_handler import WorkspaceFsHandler, is_sensitive_relpath
from acp_gateway.client.permission_policy import ActionRequest, PolicyPermissionGate
from acp_gateway.core.acp_connection import AcpRpcError


def _allow_all_gate(*, sensitive: bool = False) -> PolicyPermissionGate:
    return PolicyPermissionGate(
        allow_fs_read=True,
        allow_fs_write=True,
        allow_sensitive_paths=sensitive,
    )


def test_read_write_create_dirs_and_line_limit(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    real_ws = os.path.realpath(ws)

    with WorkspaceFsHandler([ws], _allow_all_gate()) as fs:
        target = os.path.join(real_ws, "nested", "dir", "hello.txt")
        assert fs.write_text_file(
            {"sessionId": "s1", "path": target, "content": "line1\nline2\nline3\n"}
        ) == {}
        assert Path(target).read_text(encoding="utf-8") == "line1\nline2\nline3\n"
        # Newly created file has restrictive 0600 permissions and no leftover temp files
        assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
        assert [p.name for p in Path(target).parent.iterdir()] == ["hello.txt"]

        assert fs.read_text_file({"sessionId": "s1", "path": target}) == {
            "content": "line1\nline2\nline3\n"
        }
        assert fs.read_text_file({"sessionId": "s1", "path": target, "line": 2, "limit": 1}) == {
            "content": "line2\n"
        }
        assert fs.read_text_file({"sessionId": "s1", "path": target, "line": 2}) == {
            "content": "line2\nline3\n"
        }
        assert fs.read_text_file({"sessionId": "s1", "path": target, "limit": 2}) == {
            "content": "line1\nline2\n"
        }

        # Overwrite preserves existing file mode
        os.chmod(target, 0o644)
        assert fs.write_text_file({"sessionId": "s1", "path": target, "content": "updated\n"}) == {}
        assert Path(target).read_text(encoding="utf-8") == "updated\n"
        assert stat.S_IMODE(os.stat(target).st_mode) == 0o644


def test_empty_file_and_line_past_eof_and_invalid_line_limit(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    real_ws = os.path.realpath(ws)
    empty = Path(real_ws) / "empty.txt"
    empty.write_text("", encoding="utf-8")
    two = Path(real_ws) / "two.txt"
    two.write_text("a\nb\n", encoding="utf-8")

    with WorkspaceFsHandler([ws], _allow_all_gate()) as fs:
        assert fs.read_text_file({"sessionId": "s1", "path": str(empty), "line": 1, "limit": 5}) == {
            "content": ""
        }
        with pytest.raises(AcpRpcError) as exc:
            fs.read_text_file({"sessionId": "s1", "path": str(empty), "line": 2})
        assert exc.value.code == -32602

        with pytest.raises(AcpRpcError) as exc:
            fs.read_text_file({"sessionId": "s1", "path": str(two), "line": 3})
        assert exc.value.code == -32602

        for bad in (0, -1, True, False, "1", 1.5):
            with pytest.raises(AcpRpcError) as exc:
                fs.read_text_file({"sessionId": "s1", "path": str(two), "line": bad})
            assert exc.value.code == -32602
            with pytest.raises(AcpRpcError) as exc:
                fs.read_text_file({"sessionId": "s1", "path": str(two), "limit": bad})
            assert exc.value.code == -32602


def test_invalid_paths_and_traversal_and_outside_root(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    real_ws = os.path.realpath(ws)

    with WorkspaceFsHandler([ws], _allow_all_gate()) as fs:
        invalid_paths = [
            None,
            123,
            "",
            "relative/file.txt",
            f"{real_ws}/../outside.txt",
            f"{real_ws}/./file.txt",
            f"{real_ws}/sub/../../outside.txt",
            f"{real_ws}/bad\x00name.txt",
            f"{real_ws}/bad\nname.txt",
            f"{real_ws}/bad\x7fname.txt",
            f"{real_ws}/",
            real_ws,  # path == root rejected for file ops
        ]
        for bad in invalid_paths:
            with pytest.raises(AcpRpcError) as exc:
                fs.read_text_file({"sessionId": "s1", "path": bad})
            assert exc.value.code == -32602, f"expected -32602 for {bad!r}"

            with pytest.raises(AcpRpcError) as exc:
                fs.write_text_file({"sessionId": "s1", "path": bad, "content": "x"})
            assert exc.value.code == -32602, f"expected -32602 for {bad!r}"

        # Valid absolute path outside canonical root -> -32002
        with pytest.raises(AcpRpcError) as exc:
            fs.read_text_file({"sessionId": "s1", "path": os.path.realpath(outside)})
        assert exc.value.code == -32002
        with pytest.raises(AcpRpcError) as exc:
            fs.write_text_file({"sessionId": "s1", "path": os.path.realpath(outside), "content": "x"})
        assert exc.value.code == -32002


def test_symlink_file_and_symlink_parent_dir_and_dangling_symlink_rejected(tmp_path: Path):
    """SEC-2: symlink file, symlink parent dir (macOS ENOTDIR!), and dangling symlink -> -32002."""
    ws = tmp_path / "ws"
    ws.mkdir()
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    outside_file = outside_dir / "secret.txt"
    outside_file.write_text("do-not-touch", encoding="utf-8")
    real_ws = os.path.realpath(ws)

    # 1. Symlink file pointing outside workspace
    sym_file = ws / "link.txt"
    os.symlink(outside_file, sym_file)

    # 2. Symlink parent directory pointing outside workspace
    sym_dir = ws / "linkdir"
    os.symlink(outside_dir, sym_dir)

    # 3. Dangling symlink file pointing to nonexistent outside target
    dangling_target = outside_dir / "never-created.txt"
    dangling_sym = ws / "dangling.txt"
    os.symlink(dangling_target, dangling_sym)

    # 4. Dangling symlink parent directory
    dangling_dir = ws / "dangling_dir"
    os.symlink(outside_dir / "missing_subdir", dangling_dir)

    with WorkspaceFsHandler([ws], _allow_all_gate(), allow_create_dirs=True) as fs:
        # Symlink file read & write -> -32002
        with pytest.raises(AcpRpcError) as exc:
            fs.read_text_file({"sessionId": "s1", "path": os.path.join(real_ws, "link.txt")})
        assert exc.value.code == -32002
        with pytest.raises(AcpRpcError) as exc:
            fs.write_text_file(
                {"sessionId": "s1", "path": os.path.join(real_ws, "link.txt"), "content": "pwn"}
            )
        assert exc.value.code == -32002
        assert outside_file.read_text(encoding="utf-8") == "do-not-touch"

        # Symlink parent directory on BOTH read and write -> -32002 (explicit macOS ENOTDIR check)
        with pytest.raises(AcpRpcError) as exc:
            fs.read_text_file(
                {"sessionId": "s1", "path": os.path.join(real_ws, "linkdir", "secret.txt")}
            )
        assert exc.value.code == -32002
        with pytest.raises(AcpRpcError) as exc:
            fs.write_text_file(
                {
                    "sessionId": "s1",
                    "path": os.path.join(real_ws, "linkdir", "injected.txt"),
                    "content": "pwn",
                }
            )
        assert exc.value.code == -32002
        assert not (outside_dir / "injected.txt").exists()

        # Dangling symlink file write -> -32002, target NOT created
        with pytest.raises(AcpRpcError) as exc:
            fs.write_text_file(
                {"sessionId": "s1", "path": os.path.join(real_ws, "dangling.txt"), "content": "pwn"}
            )
        assert exc.value.code == -32002
        assert not dangling_target.exists()

        # Dangling symlink parent directory write -> -32002
        with pytest.raises(AcpRpcError) as exc:
            fs.write_text_file(
                {
                    "sessionId": "s1",
                    "path": os.path.join(real_ws, "dangling_dir", "file.txt"),
                    "content": "pwn",
                }
            )
        assert exc.value.code == -32002
        assert not (outside_dir / "missing_subdir").exists()


def test_unopened_fifo_and_directory_rejected_without_blocking(tmp_path: Path):
    """SEC-2: O_NONBLOCK + immediate fstat rejects unopened FIFO in < 1.0s with -32602."""
    ws = tmp_path / "ws"
    ws.mkdir()
    real_ws = os.path.realpath(ws)
    fifo_path = os.path.join(real_ws, "trap.fifo")
    os.mkfifo(fifo_path)
    sub_dir = os.path.join(real_ws, "adir")
    os.mkdir(sub_dir)

    with WorkspaceFsHandler([ws], _allow_all_gate()) as fs:
        t0 = time.monotonic()
        with pytest.raises(AcpRpcError) as exc:
            fs.read_text_file({"sessionId": "s1", "path": fifo_path})
        elapsed = time.monotonic() - t0
        assert exc.value.code == -32602
        assert elapsed < 1.0

        # Directory read and write rejected with -32602
        with pytest.raises(AcpRpcError) as exc:
            fs.read_text_file({"sessionId": "s1", "path": sub_dir})
        assert exc.value.code == -32602
        with pytest.raises(AcpRpcError) as exc:
            fs.write_text_file({"sessionId": "s1", "path": sub_dir, "content": "x"})
        assert exc.value.code == -32602
        with pytest.raises(AcpRpcError) as exc:
            fs.write_text_file({"sessionId": "s1", "path": fifo_path, "content": "x"})
        assert exc.value.code == -32602


def test_sensitive_path_classification_and_denial(tmp_path: Path):
    """SEC-1/SEC-2: sensitive paths denied by default across case and NFC/NFD normalization."""
    ws = tmp_path / "ws"
    ws.mkdir()
    real_ws = os.path.realpath(ws)

    sensitive_cases = [
        [".GIT", "config"],
        [".git", "HEAD"],
        [".claude", "settings.json"],
        [".gemini", "oauth.json"],
        [".vscode", "tasks.json"],
        [".zed", "settings.json"],
        [".mcp.json"],
        [".env"],
        [".ENV.local"],
        ["ssh", "id_rsa"],
        ["ssh", "id_ed25519_work"],
        ["certs", "server.PEM"],
        ["certs", "ca\u0301.key"],  # NFD decomposed accented filename ending in .key
        ["certs", "bundle.p12"],
        [".npmrc"],
        [".pypirc"],
        [".netrc"],
    ]
    for segs in sensitive_cases:
        assert is_sensitive_relpath(segs) is True, f"expected sensitive: {segs}"

    assert is_sensitive_relpath(["src", "main.py"]) is False
    assert is_sensitive_relpath(["docs", "env_notes.md"]) is False

    # Denied when allow_sensitive_paths=False
    with WorkspaceFsHandler([ws], _allow_all_gate(sensitive=False)) as fs:
        for segs in sensitive_cases:
            path = os.path.join(real_ws, *segs)
            with pytest.raises(AcpRpcError) as exc:
                fs.write_text_file({"sessionId": "s1", "path": path, "content": "x"})
            assert exc.value.code == -32001
            # Gate ran BEFORE dir creation: sensitive parent dir was never created
            if len(segs) > 1:
                assert not (ws / segs[0]).exists()

    # Allowed when allow_sensitive_paths=True
    with WorkspaceFsHandler([ws], _allow_all_gate(sensitive=True)) as fs:
        env_path = os.path.join(real_ws, ".env")
        assert fs.write_text_file({"sessionId": "s1", "path": env_path, "content": "K=V\n"}) == {}
        assert fs.read_text_file({"sessionId": "s1", "path": env_path}) == {"content": "K=V\n"}


def test_byte_caps_utf8_validation_gate_denial_and_cancel(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    real_ws = os.path.realpath(ws)
    big = Path(real_ws) / "big.txt"
    big.write_bytes(b"x" * 65)
    bad_utf8 = Path(real_ws) / "bin.dat"
    bad_utf8.write_bytes(b"\xff\xfe\xfd")

    with WorkspaceFsHandler(
        [ws],
        _allow_all_gate(),
        max_read_bytes=64,
        max_write_bytes=32,
        allow_create_dirs=False,
    ) as fs:
        with pytest.raises(AcpRpcError) as exc:
            fs.read_text_file({"sessionId": "s1", "path": str(big)})
        assert exc.value.code == -32602

        with pytest.raises(AcpRpcError) as exc:
            fs.read_text_file({"sessionId": "s1", "path": str(bad_utf8)})
        assert exc.value.code == -32602

        with pytest.raises(AcpRpcError) as exc:
            fs.write_text_file(
                {"sessionId": "s1", "path": os.path.join(real_ws, "too_big.txt"), "content": "a" * 33}
            )
        assert exc.value.code == -32602

        # allow_create_dirs=False refuses missing parent directory with -32002
        with pytest.raises(AcpRpcError) as exc:
            fs.write_text_file(
                {"sessionId": "s1", "path": os.path.join(real_ws, "nope", "f.txt"), "content": "hi"}
            )
        assert exc.value.code == -32002

    # Fail-closed default gate denies both read and write BEFORE directory creation
    seen_actions: list[ActionRequest] = []
    deny_gate = PolicyPermissionGate()
    with WorkspaceFsHandler([ws], deny_gate) as fs:
        with pytest.raises(AcpRpcError) as exc:
            fs.write_text_file(
                {"sessionId": "s1", "path": os.path.join(real_ws, "uncreated", "a.txt"), "content": "x"}
            )
        assert exc.value.code == -32001
        assert not (ws / "uncreated").exists()

    # Pre-set cancel_event stops operation before I/O
    cancel = threading.Event()
    cancel.set()
    gate_recording = PolicyPermissionGate(
        allow_fs_read=True,
        allow_fs_write=True,
        authorizer=lambda a: (seen_actions.append(a), True)[1],
    )
    with WorkspaceFsHandler([ws], gate_recording) as fs:
        with pytest.raises(AcpRpcError) as exc:
            fs.read_text_file({"sessionId": "s1", "path": str(big)}, cancel_event=cancel)
        assert exc.value.code in (-32001, -32800)
        assert seen_actions == []
