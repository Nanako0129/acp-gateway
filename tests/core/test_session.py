"""ACP session layer tests."""

from __future__ import annotations

import logging
import threading

import pytest

from acp_gateway.core.acp_connection import AcpError
from acp_gateway.core.permission import PermissionGate
from acp_gateway.core.session import NATIVE_TOOLS, _composite, new_session, select_model

from .conftest import dump

SERVER = {"type": "http", "name": "acpgw-deadbeef", "url": "http://127.0.0.1:1/mcp/p",
          "headers": [{"name": "Authorization", "value": "Bearer BEARER-SENTINEL"}]}


def gate(**kw):
    return PermissionGate("acpgw-deadbeef", {"terminal"}, **kw)


def requests_of(conn, method):
    return [m["params"] for m in dump(conn)["log"] if m.get("method") == method]


def test_session_new_declares_server_and_disables_native_tools(connect, caplog):
    conn = connect({"early_update": True})
    with caplog.at_level(logging.DEBUG):
        session = new_session(conn, mcp_server=SERVER, gate=gate())
    (params,) = requests_of(conn, "session/new")
    assert params["mcpServers"] == [SERVER] and params["cwd"] == conn.cwd
    assert params["_meta"] == {"antigravity": {"disabledTools": NATIVE_TOOLS, "eagerMcpServers": ["acpgw-deadbeef"],
                                               "mcpMaxOutputBytes": 256 * 1024}}
    assert {"run_command", "view_file", "list_resources", "read_resource"} <= set(NATIVE_TOOLS)
    assert session.updates.get(timeout=5)["content"]["text"] == "early"  # buffered early update
    assert "BEARER-SENTINEL" not in caplog.text


@pytest.mark.parametrize(
    ("config_options", "method", "key"),
    [
        ([{"id": "model", "category": "model", "options": [{"value": "m1"}, {"value": "m2"}]}],
         "session/set_config_option", "configId"),
        ([{"id": "model", "category": "model", "options": [{"value": "other"}]}], "session/set_model", "modelId"),
        ([], "session/set_model", "modelId"),
    ],
)
def test_model_selection_method(connect, config_options, method, key):
    conn = connect({"config_options": config_options})
    session = new_session(conn, mcp_server=SERVER, gate=gate(), model="m2")
    (params,) = requests_of(conn, method)
    assert params["sessionId"] == session.session_id and "m2" in params.values() and key in params


@pytest.mark.parametrize(
    ("stop", "finish"),
    [("end_turn", "stop"), ("max_tokens", "length"), ("max_turn_requests", "length"),
     ("refusal", "content_filter"), ("cancelled", "cancelled")],
)
def test_stop_reason_mapping(connect, stop, finish):
    session = new_session(connect({"stop_reason": stop}), mcp_server=SERVER, gate=gate())
    result = session.prompt("hi", timeout=10)
    assert (result.stop_reason, result.finish_reason) == (stop, finish)


def test_unknown_stop_reason_is_an_error(connect):
    session = new_session(connect({"stop_reason": "mystery"}), mcp_server=SERVER, gate=gate())
    with pytest.raises(AcpError):
        session.prompt("hi", timeout=10)


def test_prompt_updates_arrive_and_gate_answers_permissions(connect):
    ours = {"is_mcp_tool_call": True, "mcp": {"server": "acpgw-deadbeef", "tool": "terminal"}}
    conn = connect({
        "update_on_prompt": [{"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "a"}}],
        "permission": {"toolCall": {"toolCallId": "t1", "_meta": ours},
                       "options": [{"optionId": "ao", "kind": "allow_once"}, {"optionId": "aa", "kind": "allow_always"}]},
    })
    session = new_session(conn, mcp_server=SERVER, gate=gate())
    result = session.prompt("hi", timeout=10)
    assert result.result["_meta"]["permissionResponse"]["result"] == {"outcome": {"outcome": "selected", "optionId": "ao"}}
    assert session.updates.get(timeout=5)["content"]["text"] == "a"


def test_tripwire_runs_on_session_updates(connect):
    seen = []
    conn = connect({"update_on_prompt": [{"sessionUpdate": "tool_call", "toolCallId": "n1", "status": "in_progress",
                                          "title": "view_file"}]})
    session = new_session(conn, mcp_server=SERVER, gate=gate(on_foreign_tool_call=seen.append))
    session.prompt("hi", timeout=10)
    assert [u["toolCallId"] for u in seen] == ["n1"]


def test_cancel_ends_prompt_cancelled(connect):
    conn = connect({"wait_cancel": True, "update_on_prompt": [{"sessionUpdate": "agent_thought_chunk"}]})
    session = new_session(conn, mcp_server=SERVER, gate=gate())
    out = []
    t = threading.Thread(target=lambda: out.append(session.prompt("hi", timeout=10)))
    t.start()
    session.updates.get(timeout=5)  # the prompt is running and the fake now waits for cancel
    session.cancel()
    t.join(10)
    assert out[0].stop_reason == "cancelled"
    assert requests_of(conn, "session/cancel") == [{"sessionId": session.session_id}]


@pytest.mark.parametrize(
    ("model", "thinking", "legacy_ids", "expected"),
    [
        ("gemini-4-hydrogen", "xhigh", ["gemini-4-hydrogen", "gemini-4-hydrogen-xhigh"], "gemini-4-hydrogen-xhigh"),
        ("gemini-4-hydrogen", "low", ["gemini-4-hydrogen", "gemini-4-hydrogen-xhigh"], "gemini-4-hydrogen"),
        (
            "gemini-4-neon",
            "xhigh",
            ["gemini-4-neon-medium", "gemini-4-neon-high", "gemini-4-neon-xhigh"],
            "gemini-4-neon-xhigh",
        ),
        (
            "gemini-4-neon",
            "low",
            ["gemini-4-neon-medium", "gemini-4-neon-high", "gemini-4-neon-xhigh"],
            "gemini-4-neon-medium",
        ),
        (
            "gemini-4-hydrogen-medium",
            "xhigh",
            ["gemini-4-hydrogen-medium", "gemini-4-hydrogen-xhigh"],
            "gemini-4-hydrogen-xhigh",
        ),
        ("gemini-4-hydrogen", None, ["gemini-4-hydrogen", "gemini-4-hydrogen-xhigh"], "gemini-4-hydrogen"),
        ("gemini-4-hydrogen", "unknown", ["gemini-4-hydrogen", "gemini-4-hydrogen-xhigh"], "gemini-4-hydrogen"),
    ],
)
def test_composite_model_resolution(model, thinking, legacy_ids, expected):
    assert _composite(model, thinking, legacy_ids) == expected


def test_select_model_ignores_non_string_and_null_available_model_ids():
    class FakeConn:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict]] = []

        def request(self, method: str, params: dict, timeout: float | None = None):
            self.calls.append((method, params))
            return {}

    new_result = {
        "models": {
            "availableModels": [
                {"modelId": None},
                {"modelId": 123},
                {"modelId": ""},
                {},
                "not-a-dict",
                {"modelId": "gemini-4-hydrogen"},
                {"modelId": "gemini-4-hydrogen-xhigh"},
            ]
        },
        "configOptions": [
            {
                "id": "thinking_level",
                "category": "thought_level",
                "options": [{"value": "low"}, {"value": "medium"}, {"value": "high"}],
            }
        ],
    }

    # Non-string/null modelIds are ignored (never coerced to "None") and base model + low sets thought_level
    conn_low = FakeConn()
    select_model(conn_low, "s1", new_result, "gemini-4-hydrogen", "low")
    assert conn_low.calls == [
        ("session/set_model", {"sessionId": "s1", "modelId": "gemini-4-hydrogen"}),
        ("session/set_config_option", {"sessionId": "s1", "configId": "thinking_level", "value": "low"}),
    ]

    # Exact composite promotion for xhigh skips thought_level configOption
    conn_xhigh = FakeConn()
    select_model(conn_xhigh, "s1", new_result, "gemini-4-hydrogen", "xhigh")
    assert conn_xhigh.calls == [
        ("session/set_model", {"sessionId": "s1", "modelId": "gemini-4-hydrogen-xhigh"}),
    ]

    # Null modelId never matches a model named "None"
    conn_none = FakeConn()
    none_only = {"models": {"availableModels": [{"modelId": None}, {"modelId": "None-xhigh"}]}}
    select_model(conn_none, "s1", none_only, "None", "low")
    assert conn_none.calls == [
        ("session/set_model", {"sessionId": "s1", "modelId": "None-xhigh"}),
    ]
