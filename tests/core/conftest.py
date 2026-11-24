from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from acp_gateway.core.acp_connection import AcpConnection

FAKE = str(Path(__file__).with_name("fake_acp.py"))


@pytest.fixture
def connect(tmp_path):
    """connect(behaviour, mux_env=None, initialize=True, **kw) -> started AcpConnection on the fake."""
    made: list[AcpConnection] = []

    def factory(behaviour=None, mux_env=None, initialize=True, **kw):
        cwd = tmp_path / "empty-cwd"
        cwd.mkdir(exist_ok=True)
        conn = AcpConnection(
            sys.executable,
            [FAKE, json.dumps(behaviour or {})],
            str(cwd),
            mux_env=mux_env,
            **kw,
        )
        conn.start()
        made.append(conn)
        if initialize:
            conn.initialize(timeout=20)
        return conn

    yield factory
    for conn in made:
        conn.close()


@pytest.fixture
def planted_secrets(monkeypatch):
    names = ("DISCORD_BOT_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GH_TOKEN")
    for n in names:
        monkeypatch.setenv(n, "planted-" + n.lower())
    monkeypatch.setenv("ACP_MUX_SESSION_ID", "ambient-must-not-leak")
    monkeypatch.setenv("ACP_MUX_PAR", "/ambient/par")
    monkeypatch.setenv("HERMES_HOME", "/tmp/should-not-leak-hermes")
    monkeypatch.setenv("HERMES_REAL_HOME", "/tmp/should-not-leak-hermes-real")
    return names


def dump(conn: AcpConnection):
    return conn.request("x/dump", {}, timeout=10)
