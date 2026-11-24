"""Isolated tests for scripts/install_gateway.sh (SEC-7, SEC-12, cutover, rollback, uninstall).

NEVER touches real $HOME, real ~/Library/LaunchAgents, real ~/.claude, real launchctl, or live port 8960.
Every test runs inside tmp_path with fake-bin shims prepended to PATH, isolated port 18960, and test labels.
"""

from __future__ import annotations

import json
import plistlib
import stat
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALL_SH = REPO_ROOT / "scripts" / "install_gateway.sh"
TEST_PORT = "18960"
TEST_LABEL = "com.test.acp-gateway"
TEST_LEGACY = "com.test.legacy-acp-gateway"
PIN_SHA256 = "4cea3c96875a4bb66a1c136d972b5cfdc5f7c91579ff7b9cbfc158a4358270bc"
PIN_TEAM_ID = "EQHXZ8M8AV"


def _write_exe(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def _setup_sandbox(
    tmp_path: Path,
    *,
    fake_codesign_and_sha: bool = True,
    initial_loaded: list[str] | None = None,
    foreign_listener: bool = False,
    health_mode: str = "healthy",
    bootstrap_fail_labels: list[str] | None = None,
) -> dict[str, Path]:
    home = tmp_path / "home"
    fake_bin = tmp_path / "fake-bin"
    state_dir = tmp_path / "state"
    home.mkdir()
    fake_bin.mkdir()
    state_dir.mkdir()

    # Dedicated agy home & relay config & dummy par
    (home / ".local" / "share" / "acp-gateway" / "home" / ".gemini" / "antigravity-acp").mkdir(parents=True)
    (home / ".claude").mkdir(parents=True)
    relay = home / ".claude" / "model-relay.json"
    relay.write_text(json.dumps({"providers": {"other": {"baseUrl": "http://127.0.0.1:9999"}}}, indent=2) + "\n",
                     encoding="utf-8")
    par_dir = home / ".local" / "opt" / "agy-acp-server" / "1.5.2"
    par_dir.mkdir(parents=True)
    par = par_dir / "agy_acp_server.par"
    _write_exe(par, "#!/bin/sh\necho fake-par\n")

    state_file = state_dir / "state.json"
    state_file.write_text(
        json.dumps(
            {
                "loaded": list(initial_loaded or []),
                "foreign_listener": foreign_listener,
                "health_mode": health_mode,
                "bootstrap_fail_labels": list(bootstrap_fail_labels or []),
                "calls": [],
            }
        ),
        encoding="utf-8",
    )

    py = sys.executable

    # Fake launchctl: tracks loaded labels and calls in state.json
    _write_exe(
        fake_bin / "launchctl",
        f"""#!{py}
import json, plistlib, sys
from pathlib import Path

sf = Path({str(state_file)!r})
st = json.loads(sf.read_text(encoding="utf-8"))
args = sys.argv[1:]
st["calls"].append(["launchctl", *args])
cmd = args[0] if args else ""

def save():
    sf.write_text(json.dumps(st), encoding="utf-8")

if cmd == "print":
    target = args[1] if len(args) > 1 else ""
    label = target.rsplit("/", 1)[-1]
    save()
    sys.exit(0 if label in st["loaded"] else 113)
elif cmd == "bootout":
    target = args[1] if len(args) > 1 else ""
    label = target.rsplit("/", 1)[-1]
    if label in st["loaded"]:
        st["loaded"].remove(label)
    save()
    sys.exit(0)
elif cmd == "bootstrap":
    plist_path = args[2] if len(args) > 2 else ""
    with open(plist_path, "rb") as fh:
        label = plistlib.load(fh)["Label"]
    if label in st.get("bootstrap_fail_labels", []):
        save()
        sys.exit(5)
    if label not in st["loaded"]:
        st["loaded"].append(label)
    save()
    sys.exit(0)
save()
sys.exit(1)
""",
    )

    # Fake lsof: port is listening iff foreign_listener is True OR any service is loaded
    _write_exe(
        fake_bin / "lsof",
        f"""#!{py}
import json, sys
from pathlib import Path

sf = Path({str(state_file)!r})
st = json.loads(sf.read_text(encoding="utf-8"))
st["calls"].append(["lsof", *sys.argv[1:]])
sf.write_text(json.dumps(st), encoding="utf-8")
listening = bool(st.get("foreign_listener")) or bool(st.get("loaded"))
if listening:
    print("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME")
    print("python3 99999 test 5u IPv4 0x0 0t0 TCP 127.0.0.1:{TEST_PORT} (LISTEN)")
    sys.exit(0)
sys.exit(1)
""",
    )

    # Fake curl: answers /health based on health_mode & currently loaded label
    _write_exe(
        fake_bin / "curl",
        f"""#!{py}
import json, sys
from pathlib import Path

sf = Path({str(state_file)!r})
st = json.loads(sf.read_text(encoding="utf-8"))
st["calls"].append(["curl", *sys.argv[1:]])
sf.write_text(json.dumps(st), encoding="utf-8")
mode = st.get("health_mode", "healthy")
loaded = st.get("loaded", [])
if mode == "healthy":
    if loaded:
        print(json.dumps({{"ok": True, "children": 1, "standby": 1}}))
        sys.exit(0)
    sys.exit(7)
elif mode == "fail_new_recover_legacy":
    if {TEST_LABEL!r} in loaded:
        print(json.dumps({{"ok": True, "children": 0, "standby": 0}}))
        sys.exit(0)
    if {TEST_LEGACY!r} in loaded:
        print(json.dumps({{"ok": True, "children": 1, "standby": 1}}))
        sys.exit(0)
    sys.exit(7)
sys.exit(7)
""",
    )

    if fake_codesign_and_sha:
        _write_exe(
            fake_bin / "codesign",
            f"""#!/bin/sh
if [ "$1" = "--verify" ]; then exit 0; fi
if [ "$1" = "-dv" ]; then echo "TeamIdentifier={PIN_TEAM_ID}" >&2; exit 0; fi
exit 1
""",
        )
        _write_exe(
            fake_bin / "shasum",
            f"""#!/bin/sh
echo "{PIN_SHA256}  $3"
""",
        )

    return {"home": home, "fake_bin": fake_bin, "state": state_file, "relay": relay, "par": par}


def _run_installer(
    sb: dict[str, Path],
    *extra_args: str,
    legacy_label: str = "",
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = {
        "HOME": str(sb["home"]),
        "PATH": f"{sb['fake_bin']}:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin",
        "ACP_GATEWAY_LABEL": TEST_LABEL,
        "ACP_GATEWAY_LEGACY_LABEL": legacy_label,
        "ACP_GATEWAY_PORT": TEST_PORT,
        "ACP_GATEWAY_PAR": str(sb["par"]),
        "ACP_GATEWAY_PYTHON": sys.executable,
        **(extra_env or {}),
    }
    return subprocess.run(
        ["bash", str(INSTALL_SH), *extra_args],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_tampered_par_rejected_with_real_codesign_and_shasum(tmp_path):
    """SEC-7: real codesign + shasum reject an unsigned/tampered .par before any bootout or write."""
    sb = _setup_sandbox(tmp_path, fake_codesign_and_sha=False)
    res = _run_installer(sb)
    assert res.returncode != 0
    assert "codesign" in res.stderr.lower() or "sha256" in res.stderr.lower()
    st = json.loads(sb["state"].read_text(encoding="utf-8"))
    # No launchctl bootout/bootstrap ran and no plist/app created
    assert not any(c[0] == "launchctl" and c[1] in ("bootout", "bootstrap") for c in st["calls"])
    assert not (sb["home"] / "Library" / "LaunchAgents" / f"{TEST_LABEL}.plist").exists()
    assert not (sb["home"] / ".local" / "share" / "acp-gateway" / "app").exists()


def test_foreign_listener_rejected_before_any_mutation(tmp_path):
    """Refuses cutover when PORT is held by an unrelated listener (neither LABEL nor LEGACY_LABEL loaded)."""
    sb = _setup_sandbox(tmp_path, fake_codesign_and_sha=True, foreign_listener=True, initial_loaded=[])
    res = _run_installer(sb, legacy_label=TEST_LEGACY)
    assert res.returncode != 0
    assert "already in use" in res.stderr
    st = json.loads(sb["state"].read_text(encoding="utf-8"))
    assert not any(c[0] == "launchctl" and c[1] in ("bootout", "bootstrap") for c in st["calls"])
    assert not (sb["home"] / "Library" / "LaunchAgents" / f"{TEST_LABEL}.plist").exists()


def test_fresh_install_idempotent_rerun_and_backup_rotation(tmp_path):
    """SEC-12: 0700 share dir, 0600 log/plist/backups, Umask=63, same-inode relay edit, no-op rerun, rotation<=3."""
    sb = _setup_sandbox(tmp_path, fake_codesign_and_sha=True)
    inode_before = sb["relay"].stat().st_ino

    res1 = _run_installer(sb)
    assert res1.returncode == 0, res1.stderr
    assert "model-relay provider agy: added" in res1.stdout

    # Permissions & plist checks
    share = sb["home"] / ".local" / "share" / "acp-gateway"
    log_path = sb["home"] / "Library" / "Logs" / "acp-gateway.log"
    plist_path = sb["home"] / "Library" / "LaunchAgents" / f"{TEST_LABEL}.plist"
    assert stat.S_IMODE(share.stat().st_mode) == 0o700
    assert stat.S_IMODE(log_path.stat().st_mode) == 0o600
    assert plist_path.exists()
    with plist_path.open("rb") as fh:
        pl = plistlib.load(fh)
    assert pl["Label"] == TEST_LABEL
    assert pl["ProgramArguments"] == [sys.executable, "-m", "acp_gateway.relay"]
    assert pl["Umask"] == 63
    assert pl["EnvironmentVariables"]["ACP_GATEWAY_PORT"] == TEST_PORT

    # Relay updated in place (same inode) with 0600 backup
    assert sb["relay"].stat().st_ino == inode_before
    cfg = json.loads(sb["relay"].read_text(encoding="utf-8"))
    assert cfg["providers"]["agy"]["baseUrl"] == f"http://127.0.0.1:{TEST_PORT}"
    assert cfg["providers"]["agy"]["retry"] is False
    baks1 = sorted((sb["home"] / ".claude").glob("model-relay.json.bak-*-acp-gateway"))
    assert len(baks1) == 1
    assert stat.S_IMODE(baks1[0].stat().st_mode) == 0o600

    # Idempotent re-run: unchanged -> skips write and creates NO new backup
    mtime_before = sb["relay"].stat().st_mtime_ns
    res2 = _run_installer(sb)
    assert res2.returncode == 0, res2.stderr
    assert "model-relay provider agy: unchanged" in res2.stdout
    assert sb["relay"].stat().st_mtime_ns == mtime_before
    baks2 = sorted((sb["home"] / ".claude").glob("model-relay.json.bak-*-acp-gateway"))
    assert baks2 == baks1

    # Trigger 4 more distinct edits -> rotation keeps at most 3 backups
    for i in range(4):
        c = json.loads(sb["relay"].read_text(encoding="utf-8"))
        c["providers"]["agy"]["model"] = f"different-{i}"
        sb["relay"].write_text(json.dumps(c, indent=2) + "\n", encoding="utf-8")
        r = _run_installer(sb)
        assert r.returncode == 0, r.stderr
    baks_final = sorted((sb["home"] / ".claude").glob("model-relay.json.bak-*-acp-gateway"))
    assert len(baks_final) == 3
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in baks_final)


def test_cutover_from_legacy_label_removes_legacy_plist_and_keeps_0600_backup(tmp_path):
    """Cutover from LEGACY_LABEL boots out legacy, removes legacy plist, retains 0600 prior backup."""
    sb = _setup_sandbox(tmp_path, fake_codesign_and_sha=True, initial_loaded=[TEST_LEGACY])
    la_dir = sb["home"] / "Library" / "LaunchAgents"
    la_dir.mkdir(parents=True, exist_ok=True)
    legacy_plist = la_dir / f"{TEST_LEGACY}.plist"
    with legacy_plist.open("wb") as fh:
        plistlib.dump({"Label": TEST_LEGACY, "ProgramArguments": ["/bin/echo", "legacy"]}, fh)

    res = _run_installer(sb, legacy_label=TEST_LEGACY)
    assert res.returncode == 0, res.stderr
    assert not legacy_plist.exists()
    assert (la_dir / f"{TEST_LABEL}.plist").exists()
    prior_baks = list((sb["home"] / ".local" / "share" / "acp-gateway").glob(f"prior-{TEST_LEGACY}.plist.bak-*"))
    assert len(prior_baks) == 1
    assert stat.S_IMODE(prior_baks[0].stat().st_mode) == 0o600
    st = json.loads(sb["state"].read_text(encoding="utf-8"))
    assert st["loaded"] == [TEST_LABEL]


def test_rollback_on_unhealthy_cutover_restores_prior_service_and_app(tmp_path):
    """When new service fails health (standby=0), rollback restores prior app, prior plist, and prior launchd job."""
    sb = _setup_sandbox(
        tmp_path,
        fake_codesign_and_sha=True,
        initial_loaded=[TEST_LEGACY],
        health_mode="fail_new_recover_legacy",
    )
    la_dir = sb["home"] / "Library" / "LaunchAgents"
    la_dir.mkdir(parents=True, exist_ok=True)
    legacy_plist = la_dir / f"{TEST_LEGACY}.plist"
    with legacy_plist.open("wb") as fh:
        plistlib.dump({"Label": TEST_LEGACY, "ProgramArguments": ["/bin/echo", "legacy"]}, fh)

    app_dir = sb["home"] / ".local" / "share" / "acp-gateway" / "app"
    app_dir.mkdir(parents=True, exist_ok=True)
    sentinel = app_dir / "PRIOR_SENTINEL.txt"
    sentinel.write_text("prior-app-version", encoding="utf-8")
    relay_before = sb["relay"].read_text(encoding="utf-8")

    res = _run_installer(sb, legacy_label=TEST_LEGACY)
    assert res.returncode != 0
    assert "Rollback succeeded" in res.stderr
    # Prior app & legacy plist restored, new plist removed, legacy job reloaded, relay untouched
    assert sentinel.read_text(encoding="utf-8") == "prior-app-version"
    assert legacy_plist.exists()
    assert not (la_dir / f"{TEST_LABEL}.plist").exists()
    st = json.loads(sb["state"].read_text(encoding="utf-8"))
    assert st["loaded"] == [TEST_LEGACY]
    assert sb["relay"].read_text(encoding="utf-8") == relay_before


def test_uninstall_cleans_service_and_relay_while_preserving_home(tmp_path):
    """--uninstall boots out both labels, removes plists & app, removes providers.agy, preserves dedicated home."""
    sb = _setup_sandbox(tmp_path, fake_codesign_and_sha=True)
    res_in = _run_installer(sb)
    assert res_in.returncode == 0, res_in.stderr
    home_marker = sb["home"] / ".local" / "share" / "acp-gateway" / "home" / ".gemini" / "antigravity-acp" / "login.dat"
    home_marker.write_text("keep-me", encoding="utf-8")

    inode_before = sb["relay"].stat().st_ino
    res_un = _run_installer(sb, "--uninstall", legacy_label=TEST_LEGACY)
    assert res_un.returncode == 0, res_un.stderr
    assert not (sb["home"] / "Library" / "LaunchAgents" / f"{TEST_LABEL}.plist").exists()
    assert not (sb["home"] / ".local" / "share" / "acp-gateway" / "app").exists()
    assert home_marker.read_text(encoding="utf-8") == "keep-me"
    assert sb["relay"].stat().st_ino == inode_before
    cfg = json.loads(sb["relay"].read_text(encoding="utf-8"))
    assert "agy" not in cfg["providers"]
    assert "other" in cfg["providers"]
    st = json.loads(sb["state"].read_text(encoding="utf-8"))
    assert st["loaded"] == []
