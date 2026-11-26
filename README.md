# acp-gateway

Standalone, stdlib-only Python (>= 3.11) ACP v1 core with two strictly isolated operating modes:

- **Mode A (`acp_gateway.relay`)** — Loopback Anthropic Messages HTTP relay (`127.0.0.1` only) over a branch pool, with zero client `fs/*` or `terminal/*` capabilities advertised.
- **Mode B (`acp_gateway.client`)** — Full ACP v1 client facade (`FullAcpClient`) with opt-in, workspace-scoped `fs/*` and `terminal/*` handlers, fail-closed permission policies (`PolicyPermissionGate` / `InteractivePermissionGate`), and terminal output sanitization.

## Package Layout

- `acp_gateway.core` — ACP stdio JSON-RPC 2.0 connection (`AcpConnection`), strict child environment & non-echoing stderr diagnostics (`env_stderr`), Mode A session lifecycle (`session`), Mode A fail-closed permission gate (`permission`), loopback parked MCP server (`parked_mcp`), deterministic turn matcher (`matcher`), and per-conversation turn state (`conversation`).
- `acp_gateway.relay` — **Mode A**: loopback HTTP front end (`127.0.0.1` only) speaking Anthropic `/v1/messages` and `/v1/messages/count_tokens` over a branch pool (`BranchPool`), backed by `acp_gateway.core`. Never imports `acp_gateway.client`.
- `acp_gateway.client` — **Mode B**: full ACP v1 client (`FullAcpClient`, `FullAcpSession`), symlink-safe `dir_fd` workspace filesystem handler (`WorkspaceFsHandler`), process-group-managed terminal handler (`WorkspaceTerminalHandler`), fail-closed permission gates (`PolicyPermissionGate`, `InteractivePermissionGate`), display sanitization (`sanitize_terminal_text`), and minimal CLI (`python -m acp_gateway.client`). Never imports `acp_gateway.relay` or `acp_gateway.core.permission`.

## Mode A vs Mode B

| Dimension | Mode A (`acp_gateway.relay`) | Mode B (`acp_gateway.client`) |
|---|---|---|
| Role | Loopback Anthropic HTTP relay | Direct full ACP v1 client & CLI |
| Client `fs/*` / `terminal/*` | Never registered (`False`) | Opt-in only (all `False` by default) |
| Permission gate | `core.permission.PermissionGate` (parked MCP only) | `PolicyPermissionGate` / `InteractivePermissionGate` (fail-closed) |
| Session capabilities | `session/new`, `session/prompt`, `session/cancel`, `session/close` | Plus capability-gated `session/load` (replay), `session/resume`, `session/list`, `session/delete`, `configOptions` |

## Mode B Fail-Closed Defaults & Security Boundary

- **Fail-closed by default**: `enable_fs_read`, `enable_fs_write`, and `enable_terminal` default to `False` (capabilities are derived strictly from registered handlers). `PolicyPermissionGate` defaults every allow flag (`allow_fs_read`, `allow_fs_write`, `allow_terminal`, `allow_sensitive_paths`, `allow_agent_permissions`, `allow_always_enabled`) to `False` and never auto-selects `allow_always`.
- **Filesystem containment**: `WorkspaceFsHandler` pins canonical workspace root FDs (`O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`), walks every path segment via `dir_fd` with `O_NOFOLLOW`, opens reads with `O_NONBLOCK` + immediate `fstat` regular-file checks, classifies NFC/casefold sensitive paths (`.git`, `.env*`, `.claude`, `.gemini`, `.mcp.json`, SSH keys, `*.pem`/`*.key`/`*.p12`, etc.), and writes atomically via sibling temp + `fsync` + POSIX `renameat`.
- **Not an OS sandbox**: `WorkspaceTerminalHandler` enforces symlink-safe `cwd` containment, zero ambient environment inheritance, dangerous env-var blocking, `shell=False`, output byte caps, concurrency caps, and process-group reaping/watchdogs — these are **application-layer containment controls only, NOT an OS sandbox**. Once a command is authorized and spawned, it runs with the invoking OS user's privileges and can access files outside workspace roots or the network unless wrapped in an external OS sandbox (such as a container, Seatbelt profile, or bubblewrap).

## Running

### Mode A (Loopback Relay)

```bash
PYTHONPATH=src python3.11 -m acp_gateway.relay
```

### Mode B (Full ACP Client CLI)

```bash
# Probe agent capabilities only (fail-closed; no fs/terminal registered):
PYTHONPATH=src python3.11 -m acp_gateway.client --command <agent-bin> --probe-only

# Run a prompt with explicit opt-in capabilities:
PYTHONPATH=src python3.11 -m acp_gateway.client --command <agent-bin> --workspace . --allow-fs-read --prompt "Summarize README.md"
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
| `ACP_GATEWAY_STEP_DEADLINE` | `480` | Seconds without ACP activity before a step times out |
| `ACP_GATEWAY_TERMINAL_TOOLS` | `SubagentHandback` | Comma-separated tools that retire a branch immediately |
| `ACP_GATEWAY_COLLECT_WINDOW` | `0.05` | Seconds to batch parallel MCP tool calls per step |
| `ACP_GATEWAY_WARM_STANDBY` | `1` | Pre-warmed initialized ACP children kept ready |
| `ACP_GATEWAY_THINKING_LEVEL` | *(unset)* | Optional `low\|medium\|high\|xhigh` override |

## Architecture & Credential Boundary

`acp-gateway` is a standard ACP v1 stdio client. It never reads, stores, or forwards upstream credentials, never calls provider API endpoints directly, and never spoofs `clientInfo`: it launches the official, unmodified ACP server binary (`agy_acp_server` or any ACP v1 agent) and speaks JSON-RPC 2.0 over stdio. Authentication and all upstream network requests are handled entirely by the official binary itself.

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
