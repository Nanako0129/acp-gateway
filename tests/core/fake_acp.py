"""Scriptable fake ACP agent for tests/core. argv[1] is a JSON behaviour dict:

early_update          send a session/update for the new session BEFORE the session/new reply
config_options        configOptions list returned by session/new
legacy_models         models.availableModels modelIds returned by session/new
prompt_images         initialize declares agentCapabilities.promptCapabilities.image
flood_stderr          bytes of stderr written (blocking) before the initialize reply
stderr_lines          lines written to stderr when exiting
exit_on               method on which to write stderr_lines and exit with exit_code
permission            params dict sent as session/request_permission during session/prompt
agent_request         method sent as an agent->client request during session/prompt
wait_cancel           after the permission request, read until session/cancel arrives
cancel_perm_after     after sending permission id 900, emit $/cancel_request for id 900
stop_reason           prompt result stopReason (default end_turn)
update_on_prompt      session/update payloads sent during session/prompt
raw_frames_on_prompt  raw JSON objects emitted on stdout before prompt completes
oversized_frame_bytes emit a single stdout line exceeding this many bytes during session/prompt
x/dump returns env NAMES, selected env values, cwd, and every message received.
"""

import json
import os
import sys
import time

B = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
LOG = []


def emit(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def read():
    line = sys.stdin.readline()
    if not line:
        sys.exit(0)
    msg = json.loads(line)
    LOG.append(msg)
    return msg


def update(sid, payload):
    emit({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": sid, "update": payload}})


def wait_response(rid):
    while (m := read()).get("id") != rid or "method" in m:
        pass
    return m


while True:
    msg = read()
    rid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
    if method is None:
        continue
    if method == B.get("exit_on"):
        sys.stderr.write("\n".join(B.get("stderr_lines", [])) + "\n")
        sys.stderr.flush()
        sys.exit(B.get("exit_code", 3))
    if method == "initialize":
        for _ in range(B.get("flood_stderr", 0) // 100):
            sys.stderr.write("x" * 99 + "\n")  # blocks forever if the client never drains
        sys.stderr.flush()
        caps = {"promptCapabilities": {"image": True}} if B.get("prompt_images") else {}
        emit({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": 1, "agentCapabilities": caps}})
    elif method == "session/new":
        sid = "sess-1"
        if B.get("early_update"):
            update(sid, {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "early"}})
        result = {"sessionId": sid, "configOptions": B.get("config_options", [])}
        if B.get("legacy_models"):
            result["models"] = {"availableModels": [{"modelId": m} for m in B["legacy_models"]]}
        emit({"jsonrpc": "2.0", "id": rid, "result": result})
    elif method == "session/prompt":
        sid = params["sessionId"]
        if B.get("oversized_frame_bytes"):
            n = int(B["oversized_frame_bytes"])
            sys.stdout.write('{"jsonrpc":"2.0","method":"session/update","params":{"blob":"' + ("a" * n) + '"}}\n')
            sys.stdout.flush()
            time.sleep(5)
            sys.exit(0)
        for frame in B.get("raw_frames_on_prompt", []):
            emit(frame)
        for u in B.get("update_on_prompt", []):
            update(sid, u)
        meta = {}
        if B.get("permission"):
            emit({"jsonrpc": "2.0", "id": 900, "method": "session/request_permission",
                  "params": {"sessionId": sid, **B["permission"]}})
            if B.get("cancel_perm_after") is not None:
                time.sleep(float(B["cancel_perm_after"]))
                emit({"jsonrpc": "2.0", "method": "$/cancel_request", "params": {"requestId": 900}})
                meta["permissionResponse"] = wait_response(900)
            elif not B.get("wait_cancel"):
                meta["permissionResponse"] = wait_response(900)
        if B.get("agent_request"):
            emit({"jsonrpc": "2.0", "id": 901, "method": B["agent_request"], "params": {"sessionId": sid}})
            meta["agentRequestResponse"] = wait_response(901)
        if B.get("wait_cancel"):
            while read().get("method") != "session/cancel":
                pass
        reason = "cancelled" if B.get("wait_cancel") else B.get("stop_reason", "end_turn")
        emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": reason, "_meta": meta}})
    elif method == "x/dump":
        emit({"jsonrpc": "2.0", "id": rid, "result": {
            "env_names": sorted(os.environ),
            "env_selected": {
                k: os.environ.get(k)
                for k in ("HOME", "GEMINI_HOME", "AGY_ACP_FORCE_FILE_STORAGE", "XDG_CONFIG_HOME")
                if k in os.environ
            },
            "mux": {k: v for k, v in os.environ.items() if k.startswith("ACP_MUX_")},
            "cwd": os.getcwd(),
            "log": LOG,
        }})
    elif method == "x/error":
        emit({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": "boom"}})
    elif rid is not None:
        emit({"jsonrpc": "2.0", "id": rid, "result": {}})
