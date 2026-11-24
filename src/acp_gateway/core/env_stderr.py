"""Hermes-free ACP child environment contract and non-echoing stderr diagnostics (SEC-6).

Derived from the MIT-licensed upstream child-env allowlist and stderr no-echo policy:
- Child processes receive only an explicit case-folded allowlist plus profile-scoped XDG dirs,
  explicit profile/Gemini home overrides, optional file-storage switch, and validated mux keys.
- Untrusted ACP child stderr is never echoed into exceptions, logs, or responses; diagnostics
  carry only line/byte counts, a truncated sha256 fingerprint, and fixed credential-shape class names.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path

# ---- failover signature regexes ----------------------------------------------

_RATE_LIMIT_RE = re.compile(
    r"(?:\b429\b|resource[_ -]?exhausted|too many requests|rate[_ -]?limit(?:ed)?|"
    r"quota(?:\s+(?:exceeded|exhausted|depleted|reached|unavailable)))",
    re.IGNORECASE,
)
_AUTH_RE = re.compile(
    r"(?:\b401\b|\b403\b|unauthenticated|invalid[_ -]?grant|"
    r"authentication\s+(?:failed|failure|required)|authorization\s+(?:failed|failure)|"
    r"(?:access|refresh|id)?\s*token\s+(?:expired|revoked|invalid))",
    re.IGNORECASE,
)

# ---- stderr policy -----------------------------------------------------------

_ACP_DIAGNOSTIC_MAX_CHARS = 512

# ACP child-process stderr is UNTRUSTED output: a server stuck in a login or
# headless-auth wait can print live credentials in shapes no fixed scrubber
# can anticipate, so the runtime never echoes raw stderr into exceptions,
# default logs, chat responses, or telemetry. Diagnostics carry only a
# deterministic, non-reversible summary: captured-tail line/byte counts,
# a truncated sha256 fingerprint for correlation, and which credential-shape
# CLASS names were observed (names, never values).
_ACP_STDERR_CREDENTIAL_SHAPES = (
    (
        "token-assignment",
        re.compile(
            r"(?i)\b(access[_ -]?token|refresh[_ -]?token|id[_ -]?token|api[_ -]?key|"
            r"client[_ -]?secret|oauth[_ -]?token)\b\s*[:=]"
        ),
    ),
    ("authorization-header", re.compile(r"(?i)\bauthorization\b\s*[:=]")),
    ("bearer-token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{6,}={0,2}")),
    ("oauth-url", re.compile(r"(?i)https?://[^\s]*(?:accounts\.google\.com|oauth)[^\s]*")),
    ("google-access-token-prefix", re.compile(r"\bya29\.[A-Za-z0-9._-]{4,}")),
    ("google-api-key-prefix", re.compile(r"\bAIza[0-9A-Za-z_-]{20,}")),
    ("github-token-prefix", re.compile(r"\bgh[opurs]_[A-Za-z0-9]{20,}")),
    ("pem-private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("cookie-header", re.compile(r"(?i)\bcookie\b\s*[:=]")),
)


def _acp_stderr_diagnostic(lines: list[str]) -> str:
    """Non-echoing, non-reversible summary of untrusted ACP child stderr.

    Deterministic for identical input; bounded; contains no substring of the
    child's output beyond fixed class names and the fingerprint.
    """
    raw = "\n".join(lines).encode("utf-8", "replace")
    decoded = raw.decode("utf-8", "replace")
    nonempty = [line for line in decoded.splitlines() if line.strip()]
    observed = sorted(
        name
        for name, pattern in _ACP_STDERR_CREDENTIAL_SHAPES
        if any(pattern.search(line) for line in nonempty)
    )
    return (
        "server stderr suppressed (untrusted text is never echoed; "
        "credential-shaped material may be live): captured tail "
        f"{len(nonempty)} line(s), {len(raw)} byte(s), "
        f"sha256={hashlib.sha256(raw).hexdigest()[:16]}; "
        f"credential-shape classes observed: "
        f"{', '.join(observed) if observed else 'none'}"
    )


_ACP_STDERR_RETRY_CLASSES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("rate-limit", _RATE_LIMIT_RE),
    ("authentication", _AUTH_RE),
)
_FAILOVER_RETRY_CLASSES = frozenset(name for name, _ in _ACP_STDERR_RETRY_CLASSES)


def _acp_stderr_retry_class(lines: list[str]) -> str | None:
    """Structured retry/failure class derived from captured child stderr.

    Returns one of the fixed ``_FAILOVER_RETRY_CLASSES`` names, or ``None``.
    The return value is always one of the client's own constants — never a
    substring of the child's output.
    """
    text = "\n".join(lines)
    return next(
        (name for name, pattern in _ACP_STDERR_RETRY_CLASSES if pattern.search(text)),
        None,
    )


# ---- child environment contract ----------------------------------------------

MUX_ENV_KEYS = frozenset(
    {
        "ACP_MUX_AFFINITY",
        "ACP_MUX_SESSION_ID",
        "ACP_MUX_AFFINITY_PIN",
        "ACP_MUX_AFFINITY_TTL_SECONDS",
        "ACP_MUX_AFFINITY_MAX_ENTRIES",
    }
)


def _resolve_home_dir() -> str:
    if home := os.environ.get("HOME", "").strip():
        return home
    if (expanded := os.path.expanduser("~")) and expanded != "~":
        return expanded
    try:
        import pwd

        return pwd.getpwuid(os.getuid()).pw_dir.strip() or tempfile.gettempdir()
    except Exception:  # noqa: BLE001 - fallback when HOME/passwd unavailable
        return tempfile.gettempdir()


# Exact case-folded ACP child minimum-environment allowlist (no wildcard prefixes;
# HERMES_HOME and HERMES_REAL_HOME intentionally excluded).
_ACP_CHILD_ENV_ALLOW_EXACT = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "LANG",
        "TERM",
        "TMPDIR",
        "TEMP",
        "TMP",
        "PYTHONUTF8",
        "GEMINI_HOME",
        "AGY_ACP_FORCE_FILE_STORAGE",
        # POSIX locale categories (enumerated, never LC_* prefix).
        "LC_ALL",
        "LC_CTYPE",
        "LC_MESSAGES",
        "LC_COLLATE",
        "LC_MONETARY",
        "LC_NUMERIC",
        "LC_TIME",
        # Windows OS and profile roots.
        "SYSTEMROOT",
        "WINDIR",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
    }
)

_ACP_CHILD_ENV_ALLOW_XDG_DIRS = frozenset(
    {
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
    }
)

_HOME_VAR_RE = re.compile(r"\$\{HOME\}|\$HOME(?![A-Za-z0-9_])")


def _is_acp_child_env_key(key: str) -> bool:
    folded = key.upper()
    return folded in _ACP_CHILD_ENV_ALLOW_EXACT or folded in _ACP_CHILD_ENV_ALLOW_XDG_DIRS


def _xdg_dir_is_profile_scoped(value: str, profile_home: Path) -> bool:
    """True only when an XDG base resolves inside the child's own profile home.

    Expands leading ``~`` (for the current user), ``$HOME``, and ``${HOME}``
    against ``profile_home`` BEFORE ``os.path.expandvars`` / ``Path.expanduser`` /
    ``Path.resolve`` so profile scoping is accurate even when
    ``profile_home != os.environ["HOME"]``.
    """
    candidate = (value or "").strip()
    if not candidate:
        return False
    try:
        root = profile_home.resolve()
        root_str = str(root)
        expanded = candidate
        if expanded == "~":
            expanded = root_str
        elif expanded.startswith("~/") or (os.sep != "/" and expanded.startswith("~" + os.sep)):
            expanded = root_str + expanded[1:]
        expanded = _HOME_VAR_RE.sub(lambda _: root_str, expanded)
        expanded = os.path.expandvars(expanded)
        resolved = Path(expanded).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return False
    resolved_key = os.path.normcase(str(resolved))
    root_key = os.path.normcase(str(root))
    if root_key.endswith(os.sep):
        return resolved_key.startswith(root_key)
    return resolved_key == root_key or resolved_key.startswith(root_key + os.sep)


def _acp_child_env_filter(
    env: Mapping[str, str], *, profile_home: str | Path | None = None
) -> dict[str, str]:
    """Narrow any candidate environment to the ACP child minimum contract."""
    home = (
        Path(profile_home).expanduser()
        if profile_home is not None
        else Path(_resolve_home_dir())
    )
    narrowed: dict[str, str] = {}
    for key, value in env.items():
        folded = key.upper()
        if folded in _ACP_CHILD_ENV_ALLOW_EXACT:
            narrowed[key] = value
        elif folded in _ACP_CHILD_ENV_ALLOW_XDG_DIRS and _xdg_dir_is_profile_scoped(value, home):
            narrowed[key] = value
    return narrowed


def _pop_case_insensitive(env: dict[str, str], target: str) -> None:
    target_upper = target.upper()
    for key in [k for k in env if k.upper() == target_upper]:
        env.pop(key, None)


def build_acp_child_env(
    *,
    profile_home: str | Path | None = None,
    gemini_home: str | Path | None = None,
    force_file_storage: bool = False,
    mux_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build the ACP child environment without mutating ambient ``os.environ``."""
    unknown = set(mux_env or ()) - MUX_ENV_KEYS
    if unknown:
        raise ValueError(f"not a permitted mux control variable: {sorted(unknown)}")
    home = (
        Path(profile_home).expanduser()
        if profile_home is not None
        else Path(_resolve_home_dir())
    )
    env = _acp_child_env_filter(os.environ, profile_home=home)
    _pop_case_insensitive(env, "HOME")
    env["HOME"] = str(home)
    if gemini_home is not None:
        _pop_case_insensitive(env, "GEMINI_HOME")
        env["GEMINI_HOME"] = str(Path(gemini_home).expanduser())
    if force_file_storage:
        _pop_case_insensitive(env, "AGY_ACP_FORCE_FILE_STORAGE")
        env["AGY_ACP_FORCE_FILE_STORAGE"] = "1"
    if mux_env:
        env.update(mux_env)
    return env
