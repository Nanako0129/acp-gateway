# PlanRelay: an Anthropic-compatible front end for agy ACP, used as a model-relay provider

Status: revision 4 (2026-11-23), after two plan-verifier REVISEs and the security review; closing-review blockers
fixed below, **approved by the user 2026-11-23** (R1 first). S2-D decided: option (b), no secret.

## Goal and how it is seen working

Claude Code subagents (and, when picked with `/provider`, a whole window) can run on the Gemini models of the
user's Antigravity plan through the official `agy acp` binary. **Seen working** when a `model-relay:agy` subagent
finishes a real multi-tool task (Read, Grep, Bash, Edit) in a Claude Code session, the relay log names the provider,
and the gateway log shows one ACP prompt per Claude Code turn (`resume_held` for tool rounds, `continue` across
turns) with the replay count and reasons.

## Policy boundary (user decision, 2026-11-23)

Only the official, unmodified binary talks to Google: `~/.local/bin/agy acp` (agy 1.5.15, Developer ID Application:
Google LLC, EQHXZ8M8AV). The gateway never reads OAuth tokens, never calls a Google endpoint, never impersonates a
client. It speaks ACP over stdio to the binary and serves a loopback MCP endpoint for Claude Code's tools.

## Architecture

```
Claude Code ──► model-relay :8950 ──► acp-gateway 127.0.0.1:8960 ──► agy acp (one child per conversation branch)
                                      POST /v1/messages[?beta=true]     ▲ session/prompt, session/update
                                      POST /v1/messages/count_tokens    │
                                      GET  /health (no prompt)          └── tools/call ──► parked MCP (loopback)
                                      Anthropic ⇄ OpenAI-shaped msgs        returned to Claude Code as tool_use
```

Reused unchanged from `src/antigravity_acp_mcp/`: AcpConnection, session layer, PermissionGate, ParkedMcpServer,
matcher, Conversation. **Not reused as is:** Registry (replaced by a branch pool, component 3).

New package `src/antigravity_acp_gateway/` (stdlib only, Python ≥ 3.11):

1. **`anthropic_adapter.py`** — Anthropic request → OpenAI-shaped messages + tools, deterministic so the matcher's
   prefix projection is identical every time the same history is sent:
   - `system` (string or blocks; `cache_control` already stripped by the relay) → one system message, blocks joined
     with `\n\n`.
   - `tools[].input_schema` → function parameters (order kept).
   - assistant `text` → content; `tool_use` → `tool_calls` (ids verbatim, order kept); `thinking` /
     `redacted_thinking` dropped.
   - **user message containing `tool_result` blocks**: each `tool_result` → one `role: tool` row in block order
     (text and image content; `is_error: true` prefixes `[tool error] `). **Every non-tool_result block of that
     same message (text such as `<system-reminder>`, hook context, images) is folded, in order, into the content of
     the LAST tool row of that message.** The tail after the assistant tool-call message therefore stays tool-only
     and `resume_held` fires; the same history always produces the same rows.
   - other user messages: `text` / base64 `image` → content parts.
   - Result → Anthropic message: one `text` block (if any), `tool_use` blocks (input = parked call arguments),
     stop_reason `tool_use` / `end_turn` / `max_tokens` / `refusal`. No thinking blocks (no valid signature).
   - usage: `input_tokens` / `output_tokens` estimated as ceil(UTF-8 bytes / 3) and logged as an estimate.
2. **`server.py`** — `ThreadingHTTPServer` bound to 127.0.0.1 only; token from env `ACP_GATEWAY_TOKEN` checked
   with `hmac.compare_digest` on `Authorization: Bearer` or `x-api-key`; path matched without the query string.
   - **Commit point:** no bytes are written until the first step result (text and/or tool_use) or an error exists.
     Before that, failures are real HTTP statuses; there are no pings before commit (worst case before commit:
     spawn ≤ 60 s + one step ≤ 90 s, under Claude Code's 600 s request timeout). After commit the stream is written
     in one go (`message_start`, per block `content_block_start/delta/stop` with `text_delta` / `input_json_delta`,
     `message_delta` with stop_reason and usage, `message_stop`), so no failure can occur mid-stream except a broken
     socket; a write error just ends the request. `stream: false` returns the same message as JSON.
   - **Errors, no retries:** RateLimited → 429 `rate_limit_error`; StepTimeout / native-tool abort / other
     ProviderError → 529 `overloaded_error`; fixed messages, never stderr bytes. **Every 429/529 carries
     `x-should-retry: false`** so Claude Code's SDK does not re-send it to agy. model-relay ignores that header and
     a provider without a `retry` field inherits the global retry (on, 3 attempts, 429/529 retryable), so the `agy`
     provider is configured with **`"retry": false`** (logic.js `resolveProviderRetry`): the error reaches Claude Code
     once and the user decides. Failover to a paid provider is not part of v1.
   - **Health shortcut:** model-relay's `/__ping` (and the panel's live ping) sends `max_tokens: 1`, one user
     message, no tools, no system, no session header. The gateway answers exactly that shape with a fixed 200
     (`content: [{type: text, text: ""}]`, usage 0) without touching agy, and logs `health-ping`; `/health` does the
     same for scripts. Any other request goes to agy.
   - **Cancel:** the relay's provider path does not abort the upstream request when Claude Code disconnects, so a
     disconnect is usually invisible to the gateway. v1 relies on (a) the 170 s parked-call deadline and the 90 s
     step deadline, and (b) the branch pool (an interrupted thread's next request starts or matches another branch;
     the abandoned branch is evicted). If the gateway does see a closed socket it cancels the request token.
     Changing model-relay stays out of scope.
   - Model: request `model` when it is an agy id (`gemini-4-*`, `gemini-3.8-flash*`), else `ACP_GATEWAY_MODEL`.
     Thinking: `output_config.effort` or `thinking.type` mapped like Hermes' reasoning_effort (none→low … max→xhigh);
     env `ACP_GATEWAY_THINKING_LEVEL` overrides.
3. **Branch pool** (replaces Registry for the gateway):
   - Group key = sha256(`x-claude-code-session-id` + system text + tools fingerprint). Main thread, subagents
     (different system band / tools) and compaction requests (different system / no tools) land in different groups.
   - Inside a group, each request is offered to the group's branches (Conversations): the first whose matcher
     decision is `resume_held` or `continue` serves it. **A request that matches no branch opens a new branch; it
     never supersedes or retires another branch**, so a fork can never cancel the real thread.
   - **Serialization:** each group has a lock held from the pool's decision until the chosen Conversation has
     installed its live view (`Conversation.run` is split into `begin()` — classify, set the view live, start the
     prompt or answer held calls — and `finish()` — await the result; behaviour otherwise unchanged and covered by the
     existing tests). Under that lock a second request in the group sees the branch as live, so `begin()` can never
     take the supersede path on a branch the pool picked; the pool passes it on to another branch or a new one.
   - **Accepted limit, idle-branch forks:** a same-prefix fork arriving while a branch is idle (e.g. Claude Code's
     prompt-suggestion or summary forks in a whole-window `/provider agy` session) looks exactly like the thread's
     next turn and may `continue` that branch; the real next turn then replays on a new branch. Never a cancel; at
     worst one replay, logged with the reason. Subagents (the primary target) do not get such forks; R3 counts
     replays per turn in a whole-window session and decides whether v2 needs fork detection.
   - Requests with no tools and no session header are served by a stateless guest (own child, closed afterwards).
   - Cap: at most `ACP_GATEWAY_MAX_CHILDREN` live agy children (default from the R1 RSS measurement so the total
     stays ≤ 8 GiB; provisional 4). When the cap is reached, the least-recently-used **non-live** branch is closed
     at once; idle branches are also closed after 600 s. If every child is live, the request waits up to 30 s for one
     to finish, then gets 529 + `x-should-retry: false`.
4. **`__main__.py`** + user-run `scripts/install_gateway.sh` (LaunchAgent; no secret under option (b) of S2-D;
   `--uninstall` removes it).
5. **model-relay config** (user-run edit with backup): provider `agy` — `baseUrl` http://127.0.0.1:8960, `token`
   env, `model` `gemini-4-hydrogen-medium[1m]`, `stripCacheControl: true`, `stripToolSearch: true`,
   `authHeader: bearer`, **`"retry": false`**, not in any failover chain.

## Slices

| ID | Outcome | Proving acceptance | Stop / rollback |
|---|---|---|---|
| R1 | Live facts for real Claude Code bodies on Mac `agy acp` (needs user go; ≤ 24 prompts to Google) | (a) caps probe on `agy acp` (no prompt): version string, promptCapabilities, configOptions, legacy ids; read-only diff of 1.5.15's native tool names against `NATIVE_TOOLS` (binary strings / tool listing); names-only inventory of the Mac agy config: global MCP servers, auto-approve / allow rules, workspace trust (S2-E). (a2) **Full S1a canary matrix on Mac 1.5.15** (7 probes × fresh / after-isError = 14 prompts, plus one external-MCP probe if (a) found any server): ship gate = zero native or external execution in all of them, same rule as PlanC H1; otherwise R2 does not start. (b) **Local capture, no network** (containment per S2-C): a dump server bound to 127.0.0.1 answers canned SSE, stores headers by allowlist only, never forwards; `claude -p` runs with a fresh `mktemp` `CLAUDE_CONFIG_DIR` (no credentials, plugins, hooks or MCP; for the band-faithful run only a copy of the global CLAUDE.md and the project memory files is placed in it), `MODEL_RELAY_*` / `HTTPS_PROXY` unset, `HTTP(S)_PROXY=http://127.0.0.1:9`, `NO_PROXY=127.0.0.1,localhost`, `--strict-mcp-config`, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, a dummy API key; afterwards a count-only scan for Anthropic API-key / `Bearer ` patterns must be 0 and the temp config dir is deleted. The run goes: main turn → canned `Task` tool_use → subagent first request → canned `Read` tool_use → subagent tool_result turn → canned end_turn → main receives the task result → canned end_turn; every request (URL incl. query, allowlisted headers, body) saved under the scratchpad only. Two runs: band-faithful (CLAUDE.md copy; stays in the scratchpad, never committed) and empty-config (source of committed fixtures). (c) A replay script feeds the captured **subagent** bodies, in order, through adapter + matcher + Conversation on `agy acp`: records 429 or not, first-step latency, the matcher decision sequence (expect replay → resume_held → continue/resume_held), and one disabledTools check (run_command attempt → 0 native execution). (d) Peak RSS of one `agy acp` child during (c) → sets the default cap. (e) Count only where the conversation lands in agy storage and whether a no-persist option exists (S3-I). | First 429 / auth / TOS signal → stop, no retry, no prompt rewriting; if the Claude Code band triggers 429 the design pauses. Any matrix execution → stop (no R2). Capture: any connection attempt to the proxy sink or a non-zero credential scan → abort and delete the capture |
| R2 | Gateway package with tests | Fixtures = the **empty-config** R1 captures plus synthetic edge cases; pre-commit scan of `git diff --cached` for macOS home-dir paths, private-LAN IPs, Keychain item names, CJK = 0 hits (S1-B). Tests: [tool_result, reminder text] user message → `resume_held`, next turn `continue`, unchanged prefix fingerprint; parallel tool_use; images; is_error; thinking dropped; fork body while the thread is live → served by a new branch, thread's next decision `resume_held`/`continue`; fork body while the thread is idle → documented outcome (continue on that branch, thread's next turn is a logged replay on a new branch), never a `_retire("superseded")`; fork and thread's next turn sent at the same moment to one idle branch → no `_retire("superseded")` on any branch; `begin()`/`finish()` split passes the existing conversation tests unchanged; SSE order + JSON validity; error before commit → real status; 429/529 carry `x-should-retry: false`; health shortcut never spawns a child; auth reject; loopback bind; query-string path; child cap with N idle branches → new key served at once by eviction; forced RateLimited → exactly one ACP prompt; version pin: an agy version other than the matrix-verified one → gateway refuses to serve (S1-A); Host/Origin not loopback → 403, empty/short token config → refuses to start (S3-F); body over 64 MiB or missing Content-Length → 413/411 before reading, auth checked first (S3-H); guests count toward the child cap; model text containing `\n\nevent: content_block_start` stays one `text_delta` (S3-J). ruff clean; `/code-review` and a fresh verifier. | any failing test |
| R3 | Installed and observed working | user runs the install script and the relay config edit (`"retry": false` on `agy` visible in the diff); a forced 429 from the gateway through the relay → exactly one gateway request line, one ACP prompt, no relay "retry 1" line; replays per turn counted in one whole-window session; a `model-relay:agy` subagent completes Read + Grep + Bash + Edit in a scratch repo; gateway log shows group/branch, decisions, replay reasons, `health-ping` lines for the relay's pings and no agy prompt for them; one Esc mid-turn observed: the abandoned branch is evicted or retires by deadline, nothing re-runs | `install_gateway.sh --uninstall` and the relay config backup restore |

## Known limits (accepted for v1)

- Text arrives per model step, not per token.
- usage is an estimate; Claude Code's auto-compact sees estimated numbers.
- A Claude Code tool running > 170 s retires the branch's ACP session; the next request replays the full history.
- Tool list changes mid-conversation (deferred tools) change the group key → a new branch with a replay; R3
  measures how often.
- Esc does not stop agy at once (relay limitation); the work ends at the next deadline or eviction.
- Gemini models of the plan only; quota is shared with the user's interactive agy use.
- agy keeps every subagent conversation in its own storage on the Mac (S3-I).

## Non-goals

No Google API calls, no token handling, no prompt rewriting to dodge 429, no model-relay code change, no
non-loopback listening, no thinking-block emission.

## Security review (pilotfish:security-reviewer, 2026-11-23) — dispositions

Verified as already held (no change): the relay strips the user's `authorization` / `x-api-key` and sends only the
provider token; the gateway token is not in the agy child env allowlist; parked MCP per-session path + bearer +
loopback Origin/Host + declared tool names; permission gate selects `allow_once` only for its own server and tools;
call ids are uuid4; mismatch logs carry no content.

| ID | Finding | Disposition |
|---|---|---|
| S1-A (P1) | `NATIVE_TOOLS` was measured on 1.5.2 on the gateway host; Mac runs 1.5.15; one run_command check is not the H1 gate | FIX: R1(a) tool-name diff + R1(a2) full 14-probe matrix on Mac 1.5.15 as a ship gate; the gateway pins the verified agy version (from `initialize` / `agy --version`) and refuses to serve on a different one until the matrix is re-run |
| S1-B (P1) | committing raw captures would publish CLAUDE.md, memory, paths (repo is public) | FIX: band-faithful capture stays in the scratchpad; committed fixtures come from an empty-config capture or are synthetic; pre-commit scan = 0 hits |
| S2-C (P2) | capture had no real egress containment; OAuth could reach the dump server; hooks could reroute | FIX: fresh `CLAUDE_CONFIG_DIR`, env unset, proxy sink, `--strict-mcp-config`, nonessential traffic off, allowlisted headers, count-only credential scan (R1(b)) |
| S2-D (P2) | how the relay gets the gateway token is unplanned and would end up in a plaintext file or env | USER DECISION (asked with the approval): (a) same as the other relay providers (settings.json env, token also in the Keychain for the LaunchAgent), or (b) no secret: loopback bind + Host/Origin loopback check + reject any request with an `Origin` header, relay token a fixed non-secret placeholder. Threat model: any same-user process can already run `agy acp`, so the token only adds browser/DNS-rebinding defence, which (b)'s checks give without a secret |
| S2-E (P2) | Mac agy uses the real HOME/config; global MCP servers or auto-approve could run tools outside Claude Code's permissions | FIX: R1(a) names-only inventory; external-MCP probe in the matrix when any server exists; if present, test a dedicated `GEMINI_HOME` (login kept?) before R2 |
| S3-F (P3) | no Host/Origin check; empty token compares equal | FIX: Host/Origin loopback check (as parked_mcp `_authorize`); refuse to start with an empty or < 32-char token (option a); compare bytes |
| S3-G (P3) | Keychain/LaunchAgent details | FIX: token stored via `security -i` from stdin, ≤ 64 chars, length checked; LaunchAgent wrapper reads it with explicit service/account/keychain path and `exec`s; never in plist `EnvironmentVariables` or `launchctl setenv`; read failure → exit; uninstall names service, account, keychain (option a only) |
| S3-H (P3) | unbounded body / threads; guests outside the cap | FIX: auth before body; Content-Length required, ≤ 64 MiB; guests count toward `MAX_CHILDREN` |
| S3-I (P3) | agy stores every subagent conversation (and the MCP bearer) in its DB | ACCEPT + DOCUMENT: R1(e) counts where; listed under Known limits for the user |
| S3-J (P3) | SSE frame injection from model text | FIX: every `data:` line is one `json.dumps` object; test |
| P4s | health shortcut semantics; error strings in logs; no-session requests sharing a group; content goes to Google; reminders folded into tool rows | NOTE: health shortcut is authenticated like any request and reports "gateway up", not "agy healthy"; logs record exception class names only; no-session tool requests key on system + tools and only continue on an exact prefix match; sending Claude Code context to Google is inherent and already true of the current Gemini providers; folding keeps execution under Claude Code's permissions |

## R1 findings so far (2026-11-23)

- Mac `agy` CLI 1.5.15 `agy acp` (Antigravity ACP Server 1.5.15) honours an isolated `HOME`/`GEMINI_HOME`
  (empty home → `Authentication required`); a dedicated home was created and logged in by the user; it has no MCP
  servers (an interactive agy config can carry global MCP servers and allow rules, so it must not be shared
  with the gateway). promptCapabilities image true, audio false; `thought_level` low…xhigh; the model list also offers Claude and
  gpt-oss ids, so the gateway must allow Gemini ids only.
- The model reports these native tools in 1.5.15: read_file, run_command, manage_task, send_message, schedule,
  invoke_subagent, define_subagent, manage_subagents, write_file, edit_file, search_web, run_workflow, swarm,
  ask_question, list_resources, read_resource.
- **None of `_meta.antigravity.disabledTools`, `_meta.agy.disabledTools`, `_meta.antigravity.enabledTools: []` or
  `enabledTools: ["ask_question"]` stops 1.5.15 from attempting `run_command`** (4 probes; each time a permission
  request arrived and was rejected, so nothing ran). The S1 disable mechanism measured on the standalone server 1.5.2
  does not carry over to the CLI's built-in ACP server.
- Google's public ACP release feed (`acp/feed/v1/next/1.5.0/acp_next.json`) still lists 1.5.2 as the latest
  standalone server (darwin-arm64 sha256 123a16d5…), the same build Hermes runs and where the 14-probe matrix passed.
- Prompts used so far: 5 of 24. Paused for a user decision on which official binary the gateway runs.
- **User decision: the official standalone ACP server 1.5.2** (downloaded from dl.google.com, sha256 123a16d5… =
  feed, codesign Google LLC EQHXZ8M8AV) at `~/.local/opt/agy-acp-server/1.5.2/`, logged in by the user into the
  dedicated home through the upstream `run_login` flow (`AGY_ACP_FORCE_FILE_STORAGE=1`: credentials in a file under
  the dedicated home, not the login Keychain).

## R1 report (2026-11-23) — PASSED, 24/24 prompts used

| Check | Result |
|---|---|
| caps (1.5.2, dedicated home) | session opens; models neon / carbon / argon / hydrogen / 3.8-flash; `thinking_level` low/medium/high; image + audio |
| (a2) 14-probe canary matrix, 55-name `disabledTools` (1.5.2 list ∪ 1.5.15 names) | **14/14 zero native execution**; no canary in reply, updates or agy storage; no marker; no URL title; no leftover harness process |
| (b) contained capture | 5 requests each run (main first → subagent first → main Agent result → subagent Read result → main notified); 0 egress attempts at the sink; 0 credential-pattern hits; 0 plugin-injection hits (empty config) |
| (c) replay, band-faithful subagent body | **no 429**; `replay` → `Read` tool_use in 8.1 s → `resume_held` → answer containing the file's first line in 4.2 s; one ACP prompt |
| (c) replay, band-faithful main body | no 429; first step 50.8 s (cold spawn + ~67 KB prompt), a `Read` tool_use |
| (d) peak RSS of one agy child tree | ≈ 383 MB → default `ACP_GATEWAY_MAX_CHILDREN` = 6 (≈ 2.3 GB, under the 8 GiB job limit) |
| (e) storage | every conversation is kept under the dedicated home's `.gemini/antigravity-acp/` (68 conversations, 43 MB after R1); no no-persist switch found in 1.5.2 (only `AGY_ACP_FORCE_FILE_STORAGE` for credentials) |

Design changes from R1 (apply in R2):
- **Claude Code 2.1.325 sends `role: "system"` messages inside `messages`** (after the first user message and after
  tool_result messages; content string or text blocks; identical text across requests). Adapter rule: a `system`
  message is folded, wrapped in `<system-message>…</system-message>`, into the preceding user or tool row; only one
  that follows an assistant message becomes its own user row. Without this the first replay put the system message
  in ACTIVE_REQUEST and the model answered "no active request".
- Subagents also receive the `Agent` tool (general-purpose has it), so nothing may key on its absence.
- History stays byte-identical across requests (list vs string content renders to the same text), and `system`
  blocks and `tools` are identical between consecutive requests of a thread, so prefix matching is viable.
- The gateway runs the standalone server 1.5.2, pins that version from `initialize.agentInfo.version`, uses the
  55-name `disabledTools` list, sets `AGY_ACP_FORCE_FILE_STORAGE=1`, `HOME` and `GEMINI_HOME` to the dedicated home.

