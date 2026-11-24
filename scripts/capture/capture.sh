#!/bin/bash
# PlanRelay R1(b): capture real Claude Code request bodies with no network and no credentials.
# Usage: capture.sh <out_dir> [faithful]
#   faithful: copy the current global CLAUDE.md into the throwaway config dir (output stays local, never committed)
# Containment: fresh CLAUDE_CONFIG_DIR (no login, plugins, hooks, MCP), MODEL_RELAY_* unset, proxies pointed at a
# local sink that records connection attempts, nonessential traffic off, strict MCP config, dummy API key.
set -euo pipefail
OUT=${1:?out dir}; MODE=${2:-empty}
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"; chmod 700 "$OUT"
[ -z "$(ls -A "$OUT")" ] || { echo "out dir not empty: $OUT" >&2; exit 1; }
DUMP=; SINKPID=
WORK=$(mktemp -d "${TMPDIR:-/tmp}/cc-capture.XXXXXX")
cleanup() { [ -n "$DUMP" ] && kill "$DUMP" 2>/dev/null; [ -n "$SINKPID" ] && kill "$SINKPID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM HUP
CFG="$WORK/config"; PROJ="$WORK/proj"; mkdir -p "$CFG" "$PROJ"
printf 'CAPTURE-FIRST-LINE\nsecond line\n' >| "$PROJ/notes.txt"
if [ "$MODE" = faithful ]; then
  SRC_CFG=${CLAUDE_CONFIG_DIR:-$HOME/.claude}
  [ -f "$SRC_CFG/CLAUDE.md" ] && cp "$SRC_CFG/CLAUDE.md" "$CFG/CLAUDE.md"
fi
PORT=18990; SINK=18991
python3 "$HERE/dump_server.py" "$OUT" "$PORT" "$PROJ/notes.txt" >| "$WORK/dump.log" 2>&1 &
DUMP=$!
python3 - "$SINK" >| "$WORK/sink.log" 2>&1 <<'PY' &
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(16)
while True:
    c, _ = s.accept(); print("egress attempt", flush=True); c.close()
PY
SINKPID=$!
sleep 1
kill -0 "$DUMP" "$SINKPID" || { echo "listener failed to start (port busy?)" >&2; exit 1; }
for pt in "$PORT" "$SINK"; do
  lsof -nP -iTCP:"$pt" -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $2}' | grep -qxE "$DUMP|$SINKPID" \
    || { echo "port $pt is not held by our listener" >&2; exit 1; }
done
SETTINGS=$(printf '{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:%s","CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC":"1"}}' "$PORT")
set +e
# env -i: nothing inherited from this Claude Code session (plugin dirs, messaging socket, tokens, relay vars)
( cd "$PROJ" && env -i HOME="$HOME" PATH="$PATH" TMPDIR="${TMPDIR:-/tmp}" LANG="${LANG:-en_US.UTF-8}" TERM=dumb \
    CLAUDE_CONFIG_DIR="$CFG" ANTHROPIC_BASE_URL="http://127.0.0.1:$PORT" ANTHROPIC_API_KEY="sk-capture-dummy" \
    HTTP_PROXY="http://127.0.0.1:$SINK" HTTPS_PROXY="http://127.0.0.1:$SINK" NO_PROXY="127.0.0.1,localhost" \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    perl -e 'alarm shift; exec @ARGV' 180 claude -p --settings "$SETTINGS" --strict-mcp-config --max-turns 6 \
      "Use the Agent tool with subagent_type general-purpose to read notes.txt and tell me its first line." \
      >| "$WORK/claude.out" 2>&1 )
RC=$?
set -e
echo "claude exit=$RC; requests captured: $(ls "$OUT" | wc -l | tr -d ' ')"
grep -h "^captured" "$WORK/dump.log" || true
echo "egress attempts at the sink: $(grep -c 'egress attempt' "$WORK/sink.log" || true)"
echo "plugin-injection hits (count only): $(grep -rliE 'PONYTAIL|pilotfish|stingray|prismantis' "$OUT" 2>/dev/null | wc -l | tr -d ' ')"
echo "credential-pattern hits (count only): $(grep -rlE 'sk[-]ant-|Bearer [A-Za-z0-9]' "$OUT" 2>/dev/null | wc -l | tr -d ' ')"
