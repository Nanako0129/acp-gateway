#!/bin/bash
# Install (or --uninstall) the acp-gateway LaunchAgent and the model-relay provider `agy`.
# Runs a snapshot of this repo's src/acp_gateway (so editing the checkout never changes the live service),
# listens on 127.0.0.1:$PORT only, and drives the verified official standalone ACP server 1.5.2.
#
# Configurable environment variables (all optional):
#   ACP_GATEWAY_LABEL         LaunchAgent label (default: com.local.acp-gateway)
#   ACP_GATEWAY_LEGACY_LABEL  Optional prior LaunchAgent label to cut over from
#   ACP_GATEWAY_PORT          Loopback HTTP port (default: 8960)
#   ACP_GATEWAY_PAR           Path to agy_acp_server.par (default: ~/.local/opt/agy-acp-server/1.5.2/agy_acp_server.par)
#   ACP_GATEWAY_PYTHON        Python 3.11 interpreter (default: /opt/homebrew/bin/python3.11)
#
# Usage:
#   bash scripts/install_gateway.sh
#   bash scripts/install_gateway.sh --uninstall
set -euo pipefail

LABEL="${ACP_GATEWAY_LABEL:-com.local.acp-gateway}"
LEGACY_LABEL="${ACP_GATEWAY_LEGACY_LABEL:-}"
PORT="${ACP_GATEWAY_PORT:-8960}"
PAR="${ACP_GATEWAY_PAR:-$HOME/.local/opt/agy-acp-server/1.5.2/agy_acp_server.par}"
PY="${ACP_GATEWAY_PYTHON:-/opt/homebrew/bin/python3.11}"

PIN_SHA256="4cea3c96875a4bb66a1c136d972b5cfdc5f7c91579ff7b9cbfc158a4358270bc"
PIN_TEAM_ID="EQHXZ8M8AV"

PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LEGACY_PLIST=""
if [ -n "$LEGACY_LABEL" ]; then
  LEGACY_PLIST="$HOME/Library/LaunchAgents/$LEGACY_LABEL.plist"
fi
SHARE="$HOME/.local/share/acp-gateway"
APP="$SHARE/app"
LOG="$HOME/Library/Logs/acp-gateway.log"
RELAY="$HOME/.claude/model-relay.json"
REPO=$(cd "$(dirname "$0")/.." && pwd)
TS="$(date +%Y%m%d-%H%M%S)-$$"
APP_BAK="$SHARE/app.bak-$TS"
UID_NUM=$(id -u)

PRIOR_LABEL=""
PRIOR_PLIST=""
PRIOR_PLIST_BAK=""
APP_SWAPPED=0
PLIST_WRITTEN=0

is_loaded() {
  [ -n "${1:-}" ] && launchctl print "gui/$UID_NUM/$1" >/dev/null 2>&1
}

relay_edit() { # $1 = add | remove
  "$PY" - "$RELAY" "$1" "$PORT" <<'PY'
import datetime
import fcntl
import glob
import json
import os
import sys

path, op, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
desired = {
    "baseUrl": f"http://127.0.0.1:{port}",
    "token": "acp-gateway-local",
    "model": "acp-gemini-4-hydrogen-medium[1m]",
    "matchModels": ["^acp-gemini-"],
    "authHeader": "bearer",
    "stripCacheControl": True,
    "stripToolSearch": True,
    "retry": False,
    "fallback": False,
}

with open(path, "r+", encoding="utf-8") as fh:
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
    raw = fh.read()
    cfg = json.loads(raw)
    if not isinstance(cfg, dict):
        raise ValueError("model-relay config must be a JSON object")
    providers = cfg.get("providers")
    if providers is None:
        providers = {}
        cfg["providers"] = providers
    if not isinstance(providers, dict):
        raise ValueError("model-relay config 'providers' must be an object")

    if op == "add":
        merged = dict(desired)
        existing = providers.get("agy")
        if isinstance(existing, dict):
            for key in ("model", "models", "efforts"):
                if key in existing:
                    merged[key] = existing[key]
        if existing == merged:
            print("model-relay provider agy: unchanged")
            sys.exit(0)
        providers["agy"] = merged
    elif op == "remove":
        if "agy" not in providers:
            print("model-relay provider agy: unchanged")
            sys.exit(0)
        providers.pop("agy", None)
    else:
        raise ValueError(f"unsupported op: {op}")

    # Serialize and validate JSON in memory before creating backup or mutating file.
    serialized = json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"
    json.loads(serialized)

    # Atomic 0600 backup, rejecting symlink target.
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    bak = f"{path}.bak-{ts}-acp-gateway"
    if os.path.islink(bak):
        raise RuntimeError(f"refusing symlink backup path: {bak}")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(bak, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        bfh = os.fdopen(fd, "w", encoding="utf-8")
    except BaseException:
        os.close(fd)
        raise
    with bfh:
        bfh.write(raw)
        bfh.flush()
        os.fsync(bfh.fileno())

    # Rotate old backups, keeping the newest 3.
    pattern = f"{glob.escape(path)}.bak-*-acp-gateway"
    backups = sorted(p for p in glob.glob(pattern) if not os.path.islink(p))
    for old in backups[:-3]:
        try:
            os.unlink(old)
        except OSError:
            pass

    # Write in place (preserve inode for file watchers) and fsync.
    fh.seek(0)
    fh.write(serialized)
    fh.truncate()
    fh.flush()
    os.fsync(fh.fileno())

print("model-relay provider agy:", "added" if op == "add" else "removed")
PY
}

rollback_prior() {
  echo "Rolling back acp-gateway cutover..." >&2
  launchctl bootout "gui/$UID_NUM/$LABEL" 2>/dev/null || true
  for _ in $(seq 1 10); do
    is_loaded "$LABEL" || break
    sleep 0.5
  done
  if [ "$PLIST_WRITTEN" = 1 ]; then
    rm -f "$PLIST"
  fi
  rm -rf "$APP.new"
  if [ "$APP_SWAPPED" = 1 ]; then
    if [ -d "$APP_BAK" ]; then
      rm -rf "$APP"
      mv "$APP_BAK" "$APP"
    else
      rm -rf "$APP"
    fi
  fi
  if [ -n "$PRIOR_LABEL" ] && [ -f "$PRIOR_PLIST_BAK" ]; then
    (umask 077; install -m 600 "$PRIOR_PLIST_BAK" "$PRIOR_PLIST")
    launchctl bootstrap "gui/$UID_NUM" "$PRIOR_PLIST" 2>/dev/null || true
    recovered=0
    for _ in $(seq 1 20); do
      if curl -fsS --max-time 2 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
        recovered=1
        break
      fi
      sleep 0.5
    done
    if [ "$recovered" = 1 ]; then
      echo "Rollback succeeded: prior service ($PRIOR_LABEL) recovered on port $PORT." >&2
    else
      echo "Rollback warning: prior service ($PRIOR_LABEL) bootstrapped but /health did not respond within 10s." >&2
    fi
  fi
  exit 1
}

if [ "${1:-}" = "--uninstall" ]; then
  if is_loaded "$LABEL"; then
    launchctl bootout "gui/$UID_NUM/$LABEL" 2>/dev/null || true
  fi
  if is_loaded "$LEGACY_LABEL"; then
    launchctl bootout "gui/$UID_NUM/$LEGACY_LABEL" 2>/dev/null || true
  fi
  rm -f "$PLIST"
  if [ -n "$LEGACY_PLIST" ]; then
    rm -f "$LEGACY_PLIST"
  fi
  rm -rf "$APP"
  if [ -f "$RELAY" ]; then
    relay_edit remove
  fi
  echo "Uninstalled acp-gateway (dedicated home preserved at $SHARE/home)."
  exit 0
fi

# ---- Pre-flight checks (before any bootout or file mutation) ----
case "$PORT" in
  ''|*[!0-9]*) echo "Error: invalid ACP_GATEWAY_PORT: $PORT" >&2; exit 1 ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  echo "Error: ACP_GATEWAY_PORT out of range: $PORT" >&2
  exit 1
fi

[ -x "$PY" ] || { echo "Error: Python executable not found: $PY" >&2; exit 1; }
if [ -L "$RELAY" ] && [ ! -e "$RELAY" ]; then
  echo "Error: $RELAY is a broken symlink" >&2
  exit 1
fi
[ -f "$RELAY" ] || { echo "Error: model-relay config not found: $RELAY" >&2; exit 1; }
[ -x "$PAR" ] || { echo "Error: ACP server binary not executable: $PAR" >&2; exit 1; }
[ -d "$SHARE/home/.gemini/antigravity-acp" ] || {
  echo "Error: dedicated home not initialized: $SHARE/home/.gemini/antigravity-acp" >&2
  exit 1
}

# SEC-7: verify code signature, TeamIdentifier, and pinned SHA-256 before cutover.
codesign --verify --strict "$PAR" >/dev/null 2>&1 || {
  echo "Error: codesign verification failed for $PAR" >&2
  exit 1
}
codesign -dv "$PAR" 2>&1 | grep -q "TeamIdentifier=$PIN_TEAM_ID" || {
  echo "Error: unexpected TeamIdentifier for $PAR (expected $PIN_TEAM_ID)" >&2
  exit 1
}
ACTUAL_SHA=$(shasum -a 256 "$PAR" | awk '{print $1}')
if [ "$ACTUAL_SHA" != "$PIN_SHA256" ]; then
  echo "Error: sha256 mismatch for $PAR" >&2
  exit 1
fi

# Foreign-listener check: refuse if PORT is held by anything other than LABEL or LEGACY_LABEL.
if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  if ! is_loaded "$LABEL" && ! is_loaded "$LEGACY_LABEL"; then
    echo "Error: port $PORT is already in use by an unrelated process" >&2
    exit 1
  fi
fi

# ---- Pre-cutover / pre-upgrade backup (SEC-12) ----
mkdir -p "$SHARE" && chmod 700 "$SHARE"
mkdir -p "$(dirname "$LOG")" && (umask 077; touch "$LOG"; chmod 600 "$LOG")
mkdir -p "$(dirname "$PLIST")"

if [ -f "$PLIST" ]; then
  PRIOR_LABEL="$LABEL"
  PRIOR_PLIST="$PLIST"
elif [ -n "$LEGACY_LABEL" ] && [ -f "$LEGACY_PLIST" ]; then
  PRIOR_LABEL="$LEGACY_LABEL"
  PRIOR_PLIST="$LEGACY_PLIST"
fi
if [ -n "$PRIOR_PLIST" ]; then
  PRIOR_PLIST_BAK="$SHARE/prior-$PRIOR_LABEL.plist.bak-$TS"
  (umask 077; install -m 600 "$PRIOR_PLIST" "$PRIOR_PLIST_BAK")
fi
if [ -d "$APP" ]; then
  cp -R "$APP" "$APP_BAK"
fi

# ---- Cutover ----
if is_loaded "$LABEL"; then
  launchctl bootout "gui/$UID_NUM/$LABEL" 2>/dev/null || true
fi
if is_loaded "$LEGACY_LABEL"; then
  launchctl bootout "gui/$UID_NUM/$LEGACY_LABEL" 2>/dev/null || true
fi

port_clear=0
for _ in $(seq 1 20); do
  if ! lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1 \
     && ! is_loaded "$LABEL" \
     && ! is_loaded "$LEGACY_LABEL"; then
    port_clear=1
    break
  fi
  sleep 0.5
done
if [ "$port_clear" != 1 ]; then
  echo "Error: port $PORT did not clear within 10s after bootout" >&2
  rollback_prior
fi

rm -rf "$APP.new"
mkdir -p "$APP.new"
cp -R "$REPO/src/acp_gateway" "$APP.new/"
find "$APP.new" -name __pycache__ -type d -exec rm -rf {} +
rm -rf "$APP"
mv "$APP.new" "$APP"
APP_SWAPPED=1

# Generate XML plist safely via plistlib (SEC-12: no XML injection, explicit Umask=63).
if ! (umask 077; "$PY" - "$PLIST" "$LABEL" "$PY" "$APP" "$PORT" "$LOG" <<'PY'
import os
import plistlib
import sys

plist_path, label, py, app, port, log = sys.argv[1:7]
data = {
    "Label": label,
    "ProgramArguments": [py, "-m", "acp_gateway.relay"],
    "WorkingDirectory": app,
    "EnvironmentVariables": {
        "PYTHONPATH": app,
        "ACP_GATEWAY_PORT": str(port),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin",
    },
    "Umask": 63,  # 0o077
    "RunAtLoad": True,
    "KeepAlive": True,
    "StandardOutPath": log,
    "StandardErrorPath": log,
}
with open(plist_path, "wb") as fh:
    plistlib.dump(data, fh, fmt=plistlib.FMT_XML, sort_keys=True)
os.chmod(plist_path, 0o600)
PY
); then
  echo "Error: failed to generate plist $PLIST" >&2
  rollback_prior
fi
PLIST_WRITTEN=1

if ! plutil -lint "$PLIST" >/dev/null 2>&1; then
  echo "Error: plist validation failed for $PLIST" >&2
  rollback_prior
fi

ok=0
for attempt in 1 2 3; do
  if launchctl bootstrap "gui/$UID_NUM" "$PLIST" 2>/dev/null; then
    ok=1
    break
  fi
  echo "bootstrap attempt $attempt failed; retrying..." >&2
  sleep 1
done
if [ "$ok" != 1 ]; then
  echo "Error: launchctl bootstrap failed for $PLIST" >&2
  rollback_prior
fi

healthy=0
health_body=""
for _ in $(seq 1 30); do
  if health_body=$(curl -fsS --max-time 2 "http://127.0.0.1:$PORT/health" 2>/dev/null); then
    if "$PY" -c 'import json, sys; d = json.loads(sys.argv[1]); ok = d.get("ok") is True and isinstance(d.get("standby"), int) and not isinstance(d.get("standby"), bool) and d["standby"] >= 1; sys.exit(0 if ok else 1)' "$health_body" 2>/dev/null; then
      healthy=1
      break
    fi
  fi
  sleep 0.5
done
if [ "$healthy" != 1 ]; then
  echo "Error: acp-gateway did not report ok=true with standby>=1 within 15s" >&2
  tail -20 "$LOG" >&2 || true
  rollback_prior
fi

# ---- Cutover succeeded ----
rm -rf "$APP_BAK"
if [ -n "$LEGACY_LABEL" ] && [ "$LEGACY_LABEL" != "$LABEL" ] && [ -f "$LEGACY_PLIST" ]; then
  rm -f "$LEGACY_PLIST"
fi
echo "acp-gateway started: $health_body"
relay_edit add
echo "Done."
