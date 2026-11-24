"""Scriptable fake full ACP v1 agent for Mode B end-to-end tests."""

from __future__ import annotations

import json
import sys
import time
from typing import Any

BEHAVIOUR: dict[str, Any] = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
LOG: list[dict[str, Any]] = []
NEXT_REQ_ID = 5000
SESS_SEQ = 0


def emit(obj: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def read_msg() -> dict[str, Any]:
    line = sys.stdin.readline()
    if not line:
        sys.exit(0)
    msg = json.loads(line)
    LOG.append(msg)
    return msg


def send_update(sid: str, payload: dict[str, Any]) -> None:
    emit({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": sid, "update": payload}})


def next_id() -> int:
    global NEXT_REQ_ID
    NEXT_REQ_ID += 1
    return NEXT_REQ_ID


def wait_for_response(rid: Any) -> dict[str, Any]:
    while True:
        msg = read_msg()
        if msg.get("id") == rid and "method" not in msg:
            return msg


def resolve_placeholders(obj: Any, state: dict[str, Any]) -> Any:
    if isinstance(obj, str):
        if obj.startswith("$") and obj[1:] in state:
            return state[obj[1:]]
        return obj
    if isinstance(obj, list):
        return [resolve_placeholders(x, state) for x in obj]
    if isinstance(obj, dict):
        return {k: resolve_placeholders(v, state) for k, v in obj.items()}
    return obj


def handle_prompt(rid: Any, params: dict[str, Any]) -> None:
    sid = params["sessionId"]
    state: dict[str, Any] = {"sessionId": sid}
    steps = BEHAVIOUR.get("prompt_steps", [])
    results: list[Any] = []

    for step in steps:
        kind = step.get("kind")
        if kind == "text":
            send_update(
                sid,
                {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": step["text"]}},
            )
        elif kind == "update":
            send_update(sid, step["update"])
        elif kind == "client_req":
            req_id = step.get("id", next_id())
            req_params = resolve_placeholders(dict(step.get("params", {})), state)
            if not step.get("omit_session_id"):
                req_params.setdefault("sessionId", sid)
            emit({"jsonrpc": "2.0", "id": req_id, "method": step["method"], "params": req_params})
            if step.get("cancel_after") is not None:
                time.sleep(float(step["cancel_after"]))
                emit({"jsonrpc": "2.0", "method": "$/cancel_request", "params": {"requestId": req_id}})
            resp = wait_for_response(req_id)
            results.append({"method": step["method"], "resp": resp})
            save_as = step.get("save_terminal_id")
            if save_as and isinstance(resp.get("result"), dict) and "terminalId" in resp["result"]:
                state[save_as] = resp["result"]["terminalId"]
        elif kind == "permission":
            req_id = step.get("id", next_id())
            perm_params = dict(step.get("params", {}))
            perm_params.setdefault("sessionId", sid)
            emit({"jsonrpc": "2.0", "id": req_id, "method": "session/request_permission", "params": perm_params})
            if step.get("emit_update_while_pending"):
                send_update(
                    sid,
                    {
                        "sessionUpdate": "agent_message_chunk",
                        "content": {"type": "text", "text": step["emit_update_while_pending"]},
                    },
                )
            if step.get("cancel_after") is not None:
                time.sleep(float(step["cancel_after"]))
                emit({"jsonrpc": "2.0", "method": "$/cancel_request", "params": {"requestId": req_id}})
            resp = wait_for_response(req_id)
            results.append({"method": "session/request_permission", "resp": resp})
        elif kind == "wait_cancel":
            while True:
                m = read_msg()
                if m.get("method") == "session/cancel":
                    break
            emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "cancelled", "_meta": {"results": results}}})
            return

    stop_reason = BEHAVIOUR.get("stop_reason", "end_turn")
    emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": stop_reason, "_meta": {"results": results}}})


def main() -> None:
    global SESS_SEQ
    while True:
        msg = read_msg()
        rid = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        if method is None:
            continue

        if method == "initialize":
            result = {
                "protocolVersion": BEHAVIOUR.get("protocol_version", 1),
                "agentInfo": BEHAVIOUR.get("agent_info", {"name": "fake-full-agent", "version": "1.0.0"}),
                "authMethods": BEHAVIOUR.get("auth_methods", []),
                "agentCapabilities": BEHAVIOUR.get("agent_capabilities", {}),
            }
            emit({"jsonrpc": "2.0", "id": rid, "result": result})
        elif method == "session/new":
            SESS_SEQ += 1
            sid = BEHAVIOUR.get("session_id", f"sess-{SESS_SEQ}")
            res: dict[str, Any] = {"sessionId": sid}
            if "config_options" in BEHAVIOUR:
                res["configOptions"] = BEHAVIOUR["config_options"]
            if "modes" in BEHAVIOUR:
                res["modes"] = BEHAVIOUR["modes"]
            emit({"jsonrpc": "2.0", "id": rid, "result": res})
        elif method == "session/load":
            sid = params["sessionId"]
            for upd in BEHAVIOUR.get("load_replay_updates", []):
                send_update(sid, upd)
            if BEHAVIOUR.get("load_error"):
                err = BEHAVIOUR["load_error"]
                emit({"jsonrpc": "2.0", "id": rid, "error": err})
            else:
                res = {}
                if "config_options" in BEHAVIOUR:
                    res["configOptions"] = BEHAVIOUR["config_options"]
                if "modes" in BEHAVIOUR:
                    res["modes"] = BEHAVIOUR["modes"]
                emit({"jsonrpc": "2.0", "id": rid, "result": res})
        elif method == "session/resume":
            sid = params["sessionId"]
            for upd in BEHAVIOUR.get("resume_replay_updates", []):
                send_update(sid, upd)
            emit({"jsonrpc": "2.0", "id": rid, "result": {}})
        elif method == "session/close":
            emit({"jsonrpc": "2.0", "id": rid, "result": {}})
        elif method == "session/list":
            emit({"jsonrpc": "2.0", "id": rid, "result": {"sessions": BEHAVIOUR.get("sessions_list", [])}})
        elif method == "session/delete":
            emit({"jsonrpc": "2.0", "id": rid, "result": {}})
        elif method == "session/set_config_option":
            emit(
                {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "result": {
                        "configOptions": BEHAVIOUR.get("updated_config_options", BEHAVIOUR.get("config_options", []))
                    },
                }
            )
        elif method == "session/set_mode":
            emit({"jsonrpc": "2.0", "id": rid, "result": {}})
        elif method == "session/prompt":
            handle_prompt(rid, params)
        elif method == "x/dump":
            emit({"jsonrpc": "2.0", "id": rid, "result": {"log": LOG}})
        elif rid is not None:
            emit({"jsonrpc": "2.0", "id": rid, "result": {}})


if __name__ == "__main__":
    main()
