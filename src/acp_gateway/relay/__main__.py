"""Run the gateway: ``python -m acp_gateway.relay`` (normally from the LaunchAgent).

Environment (all optional):
  ACP_GATEWAY_PORT            8960
  ACP_GATEWAY_AGY             ~/.local/opt/agy-acp-server/1.5.2/agy_acp_server.par  (official standalone server)
  ACP_GATEWAY_HOME            ~/.local/share/acp-gateway/home  (dedicated agy home, logged in once by the user)
  ACP_GATEWAY_PIN_VERSION     1.5.2  (the version the canary matrix passed on; anything else is refused)
  ACP_GATEWAY_MODEL           gemini-4-hydrogen-medium
  ACP_GATEWAY_MAX_CHILDREN    6
  ACP_GATEWAY_STEP_DEADLINE   480  (seconds without agy activity before a step fails; agy retries 503s silently)
  ACP_GATEWAY_TERMINAL_TOOLS  SubagentHandback  (comma-separated tools that end a turn without a tool_result)
  ACP_GATEWAY_COLLECT_WINDOW  0.05  (seconds to collect parallel MCP tool calls per step)
  ACP_GATEWAY_WARM_STANDBY    1  (pre-warmed initialized agy children kept ready within MAX_CHILDREN)
  ACP_GATEWAY_THINKING_LEVEL  low|medium|high|xhigh override
"""

from __future__ import annotations

import logging
import os
import signal
import threading

from acp_gateway.core.acp_connection import AcpConnection
from acp_gateway.core.conversation import ProviderError

from .pool import BranchPool
from .server import make_server

GATEWAY_CLIENT_INFO = {
    "name": "acp-gateway",
    "title": "ACP Gateway",
    "version": "0.1.0",
}


def make_spawn(
    agy: str,
    pin: str,
    args: tuple[str, ...] = (),
    *,
    profile_home: str | None = None,
    gemini_home: str | None = None,
    force_file_storage: bool = False,
):
    def spawn(key: str, cwd: str) -> AcpConnection:
        conn = AcpConnection(
            agy,
            list(args),
            cwd,
            profile_home=profile_home,
            gemini_home=gemini_home,
            force_file_storage=force_file_storage,
            client_info=GATEWAY_CLIENT_INFO,
        )
        try:
            conn.start()
            info = (conn.initialize() or {}).get("agentInfo") or {}
        except BaseException:
            conn.close()
            raise
        if str(info.get("version")) != pin:
            conn.close()
            raise ProviderError(f"agy ACP server version {info.get('version')!r} is not the verified {pin}")
        return conn

    return spawn


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    home = os.path.expanduser(os.environ.get("ACP_GATEWAY_HOME", "~/.local/share/acp-gateway/home"))
    agy = os.path.expanduser(
        os.environ.get("ACP_GATEWAY_AGY", "~/.local/opt/agy-acp-server/1.5.2/agy_acp_server.par")
    )
    # SEC-4: pass explicit profile/Gemini homes & file-storage switch to AcpConnection
    # instead of mutating ambient os.environ["HOME"] or os.environ["GEMINI_HOME"].
    term_raw = os.environ.get("ACP_GATEWAY_TERMINAL_TOOLS", "SubagentHandback")
    terminal_tools = frozenset(t.strip() for t in term_raw.split(",") if t.strip())
    pool = BranchPool(
        make_spawn(
            agy,
            os.environ.get("ACP_GATEWAY_PIN_VERSION", "1.5.2"),
            profile_home=home,
            gemini_home=os.path.join(home, ".gemini"),
            force_file_storage=True,
        ),
        max_children=int(os.environ.get("ACP_GATEWAY_MAX_CHILDREN", "6")),
        step_deadline=float(os.environ.get("ACP_GATEWAY_STEP_DEADLINE", "480")),
        terminal_tools=terminal_tools,
        collect_window=float(os.environ.get("ACP_GATEWAY_COLLECT_WINDOW", "0.05")),
        warm_standby=int(os.environ.get("ACP_GATEWAY_WARM_STANDBY", "1")),
    )
    server = make_server(
        pool,
        int(os.environ.get("ACP_GATEWAY_PORT", "8960")),
        os.environ.get("ACP_GATEWAY_MODEL", "gemini-4-hydrogen-medium"),
    )

    def reaper() -> None:
        while True:
            threading.Event().wait(60)
            pool.reap()

    threading.Thread(target=reaper, daemon=True).start()
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown).start())
    logging.getLogger(__name__).info("acp-gateway: listening on 127.0.0.1:%d", server.server_address[1])
    try:
        server.serve_forever()
    finally:
        pool.close_all()


if __name__ == "__main__":
    main()
