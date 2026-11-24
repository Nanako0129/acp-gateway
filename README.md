# acp-gateway

Standalone, stdlib-only Python (>= 3.11) ACP v1 core and loopback Anthropic Messages relay gateway.

## Package Layout

- `acp_gateway.core` — ACP stdio JSON-RPC 2.0 connection (`AcpConnection`), strict child environment & non-echoing stderr diagnostics (`env_stderr`), session lifecycle (`session`), fail-closed permission gate (`permission`), loopback parked MCP server (`parked_mcp`), deterministic turn matcher (`matcher`), and per-conversation turn state (`conversation`).
- `acp_gateway.relay` — Loopback HTTP front end (`127.0.0.1` only) speaking Anthropic `/v1/messages` and `/v1/messages/count_tokens` over a branch pool (`BranchPool`), backed by `acp_gateway.core`.

## Running

```bash
PYTHONPATH=src python3.11 -m acp_gateway.relay
```

### Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `ACP_GATEWAY_PORT` | `8960` | Loopback HTTP listen port |
| `ACP_GATEWAY_AGY` | `~/.local/opt/agy-acp-server/1.5.2/agy_acp_server.par` | Official standalone ACP server binary |
| `ACP_GATEWAY_HOME` | `~/.local/share/acp-gateway/home` | Dedicated profile home passed explicitly to children |
| `ACP_GATEWAY_PIN_VERSION` | `1.5.2` | Pinned `agentInfo.version` required from `initialize` |
| `ACP_GATEWAY_MODEL` | `gemini-4-hydrogen-medium` | Default Gemini model ID |
| `ACP_GATEWAY_MAX_CHILDREN` | `6` | Maximum concurrent ACP child processes |
| `ACP_GATEWAY_STEP_DEADLINE` | `240` | Seconds without ACP activity before a step times out |
| `ACP_GATEWAY_TERMINAL_TOOLS` | `SubagentHandback` | Comma-separated tools that retire a branch immediately |
| `ACP_GATEWAY_COLLECT_WINDOW` | `0.05` | Seconds to batch parallel MCP tool calls per step |
| `ACP_GATEWAY_WARM_STANDBY` | `1` | Pre-warmed initialized ACP children kept ready |
| `ACP_GATEWAY_THINKING_LEVEL` | *(unset)* | Optional `low\|medium\|high\|xhigh` override |

## macOS LaunchAgent Installation

```bash
bash scripts/install_gateway.sh
bash scripts/install_gateway.sh --uninstall
```

The installer verifies binary code signature, Team ID, and SHA-256 before cutover, checks for foreign port listeners, backs up the prior service and application snapshot for automatic rollback on startup/health failure, and updates `~/.claude/model-relay.json` under an exclusive file lock.

## Testing & Linting

```bash
PYTHONPATH=src uv run --no-project --python 3.11 --with pytest python -m pytest -q tests
uvx ruff check src tests
```
