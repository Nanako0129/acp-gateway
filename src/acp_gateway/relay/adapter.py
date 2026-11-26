"""Anthropic Messages <-> the OpenAI-shaped messages the shared Conversation core speaks.

Deterministic: the same Claude Code history always maps to the same rows, so the matcher's prefix projection is
stable across requests. Rules:

- ``system`` (string or text blocks) -> one leading system message.
- assistant ``text`` -> content; ``tool_use`` -> ``tool_calls`` (ids verbatim); thinking blocks are dropped.
- a user message with ``tool_result`` blocks -> one ``role: tool`` row per result, in order; every other block of that
  message (reminder text, images) is appended to the LAST tool row, so the tail after a tool call stays tool-only.
- a ``role: system`` message inside ``messages`` -> wrapped in ``<system-message>`` and appended
  to the preceding user or tool row; after an assistant message (or first) it becomes its own user row.
- user and tool rows always carry a list of OpenAI content parts (text / image_url data URLs).
"""

from __future__ import annotations

import json
import math
import uuid
from typing import Any

STOP_REASON = {"tool_calls": "tool_use", "stop": "end_turn", "length": "max_tokens", "content_filter": "refusal",
               "cancelled": "end_turn"}


def _parts(content: Any) -> list[dict[str, Any]]:
    """Anthropic content (string or blocks) -> OpenAI content parts. Non text/image blocks are dropped."""
    if isinstance(content, str):
        return [{"type": "text", "text": content}] if content else []
    out: list[dict[str, Any]] = []
    for b in content or []:
        if not isinstance(b, dict):
            continue
        if b.get("type") == "text":
            out.append({"type": "text", "text": str(b.get("text") or "")})
        elif b.get("type") == "image":
            src = b.get("source") or {}
            if src.get("type") == "base64":
                url = f"data:{src.get('media_type') or 'image/png'};base64,{src.get('data') or ''}"
            else:
                url = str(src.get("url") or "")
            out.append({"type": "image_url", "image_url": {"url": url}})
    return out


BILLING_PREFIX = "x-anthropic-billing-header:"


def _system_text(system: Any) -> str:
    """System text without Claude Code's billing line: with a subscription login it carries a per-request
    ``cch=`` checksum, which would change the group key and the prefix on every request (a replay per step)."""
    if isinstance(system, str):
        texts = [system]
    else:
        texts = [str(b.get("text") or "") for b in system or [] if isinstance(b, dict) and b.get("type") == "text"]
    kept = []
    for t in texts:
        lines = [ln for ln in t.split("\n") if not ln.startswith(BILLING_PREFIX)]
        if any(ln.strip() for ln in lines):
            kept.append("\n".join(lines))
    return "\n\n".join(kept)


def to_openai(body: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Anthropic request body -> (messages, tools) for ``Conversation.run``."""
    rows: list[dict[str, Any]] = []
    system = _system_text(body.get("system"))
    if system:
        rows.append({"role": "system", "content": system})
    for m in body.get("messages") or []:
        if not isinstance(m, dict):
            continue
        role, content = m.get("role"), m.get("content")
        blocks = content if isinstance(content, list) else [{"type": "text", "text": content or ""}]
        if role == "assistant":
            text = "".join(str(b.get("text") or "") for b in blocks if isinstance(b, dict) and b.get("type") == "text")
            calls = [{"id": str(b.get("id")), "type": "function",
                      "function": {"name": str(b.get("name")),
                                   "arguments": json.dumps(b.get("input") or {}, ensure_ascii=False)}}
                     for b in blocks if isinstance(b, dict) and b.get("type") == "tool_use"]
            rows.append({"role": "assistant", "content": text, **({"tool_calls": calls} if calls else {})})
            continue
        if role == "system":
            wrapped = [{"type": "text", "text": "<system-message>\n" + _system_text(content) + "\n</system-message>",
                        "_acp_harness": True}]
            if rows and rows[-1]["role"] in ("user", "tool"):
                rows[-1]["content"] = rows[-1]["content"] + wrapped
            else:
                rows.append({"role": "user", "content": wrapped})
            continue
        results = [b for b in blocks if isinstance(b, dict) and b.get("type") == "tool_result"]
        others = _parts([b for b in blocks if isinstance(b, dict) and b.get("type") != "tool_result"])
        if results:
            for b in results:
                parts = _parts(b.get("content") if b.get("content") is not None else "")
                if b.get("is_error"):
                    parts = [{"type": "text", "text": "[tool error]"}] + parts
                rows.append({"role": "tool", "tool_call_id": str(b.get("tool_use_id")), "content": parts})
            rows[-1]["content"] = rows[-1]["content"] + [{**p, "_acp_harness": True} for p in others]
        else:
            rows.append({"role": "user", "content": others})
    tools = [{"type": "function", "function": {"name": str(t.get("name")), "description": str(t.get("description") or ""),
                                               "parameters": t.get("input_schema") or {"type": "object"}}}
             for t in body.get("tools") or [] if isinstance(t, dict) and t.get("name")]
    return rows, tools


def estimate_tokens(obj: Any) -> int:
    """Rough token count (UTF-8 bytes / 3, rounded up)."""
    raw = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
    return max(1, math.ceil(len(raw.encode("utf-8")) / 3))


def _pos_int(val: Any) -> int | None:
    return val if isinstance(val, int) and not isinstance(val, bool) and val > 0 else None


def _nonneg_int(val: Any) -> int | None:
    return val if isinstance(val, int) and not isinstance(val, bool) and val >= 0 else None


def to_message(result: dict[str, Any], model: str, input_tokens: int, *, include_thinking: bool = True) -> dict[str, Any]:
    """Conversation result -> Anthropic message object."""
    content: list[dict[str, Any]] = []
    reasoning = result.get("reasoning")
    has_thinking = include_thinking and isinstance(reasoning, str) and bool(reasoning.strip())
    if has_thinking:
        content.append({"type": "thinking", "thinking": reasoning, "signature": ""})
    if result.get("text"):
        content.append({"type": "text", "text": result["text"]})
    for call in result.get("tool_calls") or []:
        content.append({"type": "tool_use", "id": call.id, "name": call.name, "input": call.arguments or {}})
    stop = "tool_use" if result.get("tool_calls") else STOP_REASON.get(result.get("finish_reason") or "stop", "end_turn")
    reported = result.get("usage") if isinstance(result.get("usage"), dict) else {}
    cr_tok = _nonneg_int(reported.get("cache_read_input_tokens"))
    cw_tok = _nonneg_int(reported.get("cache_creation_input_tokens"))
    raw_in = _nonneg_int(reported.get("input_tokens"))
    if raw_in is not None and (raw_in > 0 or (cr_tok or 0) > 0 or (cw_tok or 0) > 0):
        in_tok: int | None = raw_in
    else:
        in_tok = _pos_int(reported.get("used"))
    out_tok = _pos_int(reported.get("output_tokens"))
    if out_tok is None:
        out_tok = estimate_tokens(content)
        if not has_thinking and isinstance(reasoning, str) and reasoning:
            out_tok += estimate_tokens(reasoning)
    usage: dict[str, int] = {
        "input_tokens": in_tok if in_tok is not None else input_tokens,
        "output_tokens": out_tok,
    }
    if cr_tok is not None:
        usage["cache_read_input_tokens"] = cr_tok
    if cw_tok is not None:
        usage["cache_creation_input_tokens"] = cw_tok
    # A fresh id per response: clients merge assistant messages that share an id.
    return {"id": "msg_" + uuid.uuid4().hex, "type": "message", "role": "assistant", "model": model,
            "content": content, "stop_reason": stop, "stop_sequence": None, "usage": usage}


def sse(message: dict[str, Any]) -> bytes:
    """One complete Anthropic SSE stream for a finished message. Every data line is a single json.dumps object."""
    def ev(obj: dict[str, Any]) -> str:
        return f"event: {obj['type']}\ndata: {json.dumps(obj, ensure_ascii=False)}\n\n"

    start_usage = {k: v for k, v in message["usage"].items() if k != "output_tokens"}
    start_usage["output_tokens"] = 0
    start = dict(message, content=[], stop_reason=None, usage=start_usage)
    out = [ev({"type": "message_start", "message": start})]
    for i, block in enumerate(message["content"]):
        if block["type"] == "thinking":
            out += [ev({"type": "content_block_start", "index": i,
                        "content_block": {"type": "thinking", "thinking": "", "signature": ""}}),
                    ev({"type": "content_block_delta", "index": i,
                        "delta": {"type": "thinking_delta", "thinking": block["thinking"]}})]
            if block.get("signature"):
                out.append(ev({"type": "content_block_delta", "index": i,
                               "delta": {"type": "signature_delta", "signature": block["signature"]}}))
        elif block["type"] == "text":
            out += [ev({"type": "content_block_start", "index": i, "content_block": {"type": "text", "text": ""}}),
                    ev({"type": "content_block_delta", "index": i,
                        "delta": {"type": "text_delta", "text": block["text"]}})]
        else:
            out += [ev({"type": "content_block_start", "index": i,
                        "content_block": {"type": "tool_use", "id": block["id"], "name": block["name"], "input": {}}}),
                    ev({"type": "content_block_delta", "index": i,
                        "delta": {"type": "input_json_delta",
                                  "partial_json": json.dumps(block["input"], ensure_ascii=False)}})]
        out.append(ev({"type": "content_block_stop", "index": i}))
    out += [ev({"type": "message_delta", "delta": {"stop_reason": message["stop_reason"], "stop_sequence": None},
                "usage": {"output_tokens": message["usage"]["output_tokens"]}}),
            ev({"type": "message_stop"})]
    return "".join(out).encode("utf-8")
