#!/usr/bin/env python3
"""Local Anthropic-API stand-in for capturing real Claude Code request bodies (PlanRelay R1(b)). No network.

Binds 127.0.0.1 only, never forwards anything. Each POST is saved as NN.json (path incl. query, allowlisted headers,
body) and answered with canned SSE that walks Claude Code through:
  main turn (tools include Agent/Task) -> tool_use Agent(general-purpose, read notes.txt)
  subagent first request (no Agent tool) -> tool_use Read(notes.txt)
  subagent tool_result turn -> end_turn text
  main turn carrying the Agent result -> end_turn text
  anything else (title, quota checks) -> end_turn "ok"
Usage: dump_server.py <out_dir> <port> <notes_path>
"""
import http.server
import json
import os
import socketserver
import sys
import threading

OUT, PORT, NOTES = sys.argv[1], int(sys.argv[2]), sys.argv[3]
HEADER_ALLOW = {"content-type", "anthropic-version", "anthropic-beta", "x-claude-code-session-id", "user-agent",
                "x-app", "x-stainless-lang", "x-stainless-package-version", "accept"}
lock = threading.Lock()
state = {"n": 0}


def sse(events):
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()


def message(blocks, stop):
    ev = [{"type": "message_start", "message": {"id": "msg_cap", "type": "message", "role": "assistant",
                                                "model": "capture", "content": [], "stop_reason": None,
                                                "usage": {"input_tokens": 1, "output_tokens": 0}}}]
    for i, b in enumerate(blocks):
        if b["type"] == "text":
            ev += [{"type": "content_block_start", "index": i, "content_block": {"type": "text", "text": ""}},
                   {"type": "content_block_delta", "index": i, "delta": {"type": "text_delta", "text": b["text"]}}]
        else:
            ev += [{"type": "content_block_start", "index": i,
                    "content_block": {"type": "tool_use", "id": b["id"], "name": b["name"], "input": {}}},
                   {"type": "content_block_delta", "index": i,
                    "delta": {"type": "input_json_delta", "partial_json": json.dumps(b["input"])}}]
        ev.append({"type": "content_block_stop", "index": i})
    ev += [{"type": "message_delta", "delta": {"stop_reason": stop}, "usage": {"output_tokens": 1}},
           {"type": "message_stop"}]
    return sse(ev)


def reply_for(body):
    tools = [t.get("name") for t in body.get("tools") or []]
    msgs = body.get("messages") or []
    # Claude Code 2.1.325 appends role:"system" messages after the tool_result: look at everything after the last
    # assistant message, not just the last message.
    last_asst = max((i for i, m in enumerate(msgs) if m.get("role") == "assistant"), default=-1)
    results = [c for m in msgs[last_asst + 1:] if isinstance(m.get("content"), list)
               for c in m["content"] if isinstance(c, dict) and c.get("type") == "tool_result"]
    ids = {c.get("tool_use_id") for c in results}
    if "toolu_cap_read" in ids:
        return message([{"type": "text", "text": "The first line was read."}], "end_turn"), "subagent-result"
    if "toolu_cap_agent" in ids:
        return message([{"type": "text", "text": "Done."}], "end_turn"), "main-result"
    if not tools or results:
        return message([{"type": "text", "text": "ok"}], "end_turn"), "other"
    agent = next((t for t in ("Agent", "Task") if t in tools), None)
    with lock:
        first_main = agent is not None and not state.get("main_seen")
        state["main_seen"] = state.get("main_seen") or first_main
    if first_main:  # only the first tool-bearing request is the main thread; later ones are the subagent
        return message([{"type": "tool_use", "id": "toolu_cap_agent", "name": agent,
                         "input": {"subagent_type": "general-purpose", "description": "Read notes",
                                   "prompt": "Read the file notes.txt in the current directory and report its "
                                             "first line."}}], "tool_use"), "main-first"
    if "Read" in tools:
        return message([{"type": "tool_use", "id": "toolu_cap_read", "name": "Read",
                         "input": {"file_path": NOTES}}], "tool_use"), "subagent-first"
    return message([{"type": "text", "text": "ok"}], "end_turn"), "other"


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {}
        with lock:
            state["n"] += 1
            n = state["n"]
        if n > 40:  # runaway guard: refuse instead of feeding a loop
            err = {"type": "error", "error": {"type": "invalid_request_error", "message": "capture cap"}}
            out = json.dumps(err).encode()
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
            return
        if self.path.split("?")[0].endswith("/count_tokens"):
            out, kind, ctype = json.dumps({"input_tokens": 1}).encode(), "count_tokens", "application/json"
        else:
            out, kind = reply_for(body)
            ctype = "text/event-stream"
        rec = {"n": n, "kind": kind, "method": "POST", "path": self.path,
               "headers": {k.lower(): v for k, v in self.headers.items() if k.lower() in HEADER_ALLOW},
               "body": body}
        with open(os.path.join(OUT, f"{n:02d}-{kind}.json"), "w") as fh:
            json.dump(rec, fh, ensure_ascii=False, indent=1)
        print(f"captured {n:02d} {kind} {self.path}", flush=True)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def do_GET(self):
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


S(("127.0.0.1", PORT), H).serve_forever()
