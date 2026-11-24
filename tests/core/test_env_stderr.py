"""SEC-6: Hermes-free child environment contract and non-echoing stderr diagnostics."""

from __future__ import annotations

import os

import pytest

from acp_gateway.core.env_stderr import (
    _ACP_CHILD_ENV_ALLOW_EXACT,
    _acp_stderr_diagnostic,
    _acp_stderr_retry_class,
    _xdg_dir_is_profile_scoped,
    build_acp_child_env,
)


def test_hermes_vars_excluded_from_allowlist_and_dropped(monkeypatch, tmp_path):
    assert "HERMES_HOME" not in _ACP_CHILD_ENV_ALLOW_EXACT
    assert "HERMES_REAL_HOME" not in _ACP_CHILD_ENV_ALLOW_EXACT
    monkeypatch.setenv("HERMES_HOME", "/tmp/h1")
    monkeypatch.setenv("HERMES_REAL_HOME", "/tmp/h2")
    monkeypatch.setenv("OPENAI_API_KEY", "secret-val")
    monkeypatch.setenv("openai_api_key", "secret-lower")
    monkeypatch.setenv("LC_API_TOKEN", "sneaky-prefix")
    env = build_acp_child_env(profile_home=tmp_path)
    for forbidden in ("HERMES_HOME", "HERMES_REAL_HOME", "OPENAI_API_KEY", "openai_api_key", "LC_API_TOKEN"):
        assert forbidden not in env


def test_xdg_tilde_and_home_vars_expand_against_explicit_profile_home(monkeypatch, tmp_path):
    parent_home = tmp_path / "parent-home"
    profile_home = tmp_path / "profile-home"
    sibling_home = tmp_path / "sibling-home"
    parent_home.mkdir()
    profile_home.mkdir()
    sibling_home.mkdir()

    monkeypatch.setenv("HOME", str(parent_home))
    # Inside profile_home via ~, $HOME, ${HOME}, and absolute path -> allowed
    assert _xdg_dir_is_profile_scoped("~/.config", profile_home) is True
    assert _xdg_dir_is_profile_scoped("~", profile_home) is True
    assert _xdg_dir_is_profile_scoped("$HOME/.cache", profile_home) is True
    assert _xdg_dir_is_profile_scoped("${HOME}/.local/share", profile_home) is True
    assert _xdg_dir_is_profile_scoped(str(profile_home / ".local/state"), profile_home) is True

    # Escapes or parent/sibling paths -> rejected
    assert _xdg_dir_is_profile_scoped(str(parent_home / ".config"), profile_home) is False
    assert _xdg_dir_is_profile_scoped(str(sibling_home / ".config"), profile_home) is False
    assert _xdg_dir_is_profile_scoped("~/../parent-home/.config", profile_home) is False
    assert _xdg_dir_is_profile_scoped("$HOME/../sibling-home/.cache", profile_home) is False
    assert _xdg_dir_is_profile_scoped("${HOME}/../sibling-home/.cache", profile_home) is False
    assert _xdg_dir_is_profile_scoped("", profile_home) is False

    # Symlink inside profile_home pointing outside -> rejected
    escape_link = profile_home / "escape"
    escape_link.symlink_to(sibling_home)
    assert _xdg_dir_is_profile_scoped(str(escape_link), profile_home) is False
    assert _xdg_dir_is_profile_scoped("~/escape/sub", profile_home) is False


def test_build_acp_child_env_explicit_overrides_without_mutating_os_environ(monkeypatch, tmp_path):
    parent_home = tmp_path / "parent"
    profile_home = tmp_path / "profile"
    gemini_home = profile_home / ".gemini"
    parent_home.mkdir()
    profile_home.mkdir()

    monkeypatch.setenv("HOME", str(parent_home))
    monkeypatch.delenv("GEMINI_HOME", raising=False)
    monkeypatch.delenv("AGY_ACP_FORCE_FILE_STORAGE", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", "~/.config")
    monkeypatch.setenv("XDG_CACHE_HOME", str(parent_home / ".cache"))
    monkeypatch.setenv("XDG_DATA_HOME", "${HOME}/.local/share")

    env = build_acp_child_env(
        profile_home=profile_home,
        gemini_home=gemini_home,
        force_file_storage=True,
        mux_env={"ACP_MUX_AFFINITY": "k1"},
    )
    assert env["HOME"] == str(profile_home)
    assert env["GEMINI_HOME"] == str(gemini_home)
    assert env["AGY_ACP_FORCE_FILE_STORAGE"] == "1"
    assert env["ACP_MUX_AFFINITY"] == "k1"
    # Profile-scoped XDG retained; parent-home XDG dropped
    assert env["XDG_CONFIG_HOME"] == "~/.config"
    assert env["XDG_DATA_HOME"] == "${HOME}/.local/share"
    assert "XDG_CACHE_HOME" not in env
    # Ambient os.environ untouched
    assert os.environ["HOME"] == str(parent_home)
    assert "GEMINI_HOME" not in os.environ
    assert "AGY_ACP_FORCE_FILE_STORAGE" not in os.environ


def test_build_acp_child_env_rejects_unlisted_mux_keys(tmp_path):
    with pytest.raises(ValueError, match="not a permitted mux control variable"):
        build_acp_child_env(profile_home=tmp_path, mux_env={"ACP_MUX_PAR": "/evil"})


def test_stderr_diagnostic_never_echoes_and_classifies_retry():
    lines = ["Error 429 RESOURCE_EXHAUSTED", "Authorization: Bearer SENTINEL_SECRET_TOKEN_123"]
    diag = _acp_stderr_diagnostic(lines)
    assert "server stderr suppressed" in diag
    assert "authorization-header" in diag
    assert "bearer-token" in diag
    assert "SENTINEL_SECRET_TOKEN_123" not in diag
    assert "RESOURCE_EXHAUSTED" not in diag
    assert _acp_stderr_retry_class(lines) == "rate-limit"
    assert _acp_stderr_retry_class(["HTTP 401 unauthenticated"]) == "authentication"
    assert _acp_stderr_retry_class(["ordinary startup noise"]) is None
