"""Branch pool: routes each request to a Conversation without ever cancelling another.

Group = session id + system text + tools fingerprint. Inside a group the first branch whose decision is
``resume_held`` or ``continue`` takes the request; anything else opens a new branch. The group lock is held from the
decision until the chosen branch's view is live (``Conversation.begin``), so two requests can never claim one branch.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
import threading
import time
from collections.abc import Callable
from typing import Any

from acp_gateway.core.acp_connection import AcpConnection
from acp_gateway.core.conversation import Conversation, ProviderError

logger = logging.getLogger(__name__)


class PoolFull(ProviderError):
    """Every ACP child is busy; the caller answers 529."""


DEFAULT_TERMINAL_TOOLS = frozenset({"SubagentHandback"})


class BranchPool:
    def __init__(self, spawn: Callable[[str, str], AcpConnection], *, max_children: int = 6,
                 idle_ttl: float = 600.0, wait_s: float = 30.0, step_deadline: float = 240.0,
                 terminal_tools: frozenset[str] = DEFAULT_TERMINAL_TOOLS,
                 collect_window: float = 0.05, warm_standby: int = 0) -> None:
        self._spawn = spawn
        self.step_deadline = step_deadline
        self.terminal_tools = frozenset(terminal_tools)
        self.collect_window = max(0.0, float(collect_window))
        self.max_children = max_children
        self.warm_standby = max(0, min(int(warm_standby), max_children))
        self.idle_ttl = idle_ttl
        self.wait_s = wait_s
        self._lock = threading.Lock()  # groups dict + child accounting
        self._groups: dict[str, list[Conversation]] = {}
        self._group_locks: dict[str, threading.Lock] = {}
        self._guests: set[Conversation] = set()
        self._standby: list[tuple[AcpConnection, str]] = []
        self._warming = 0
        self._closing = 0  # evicted children still mid-close (counted so teardown never overshoots max_children)
        self._closed = False
        self._seq = 0
        self._opening = 0  # slots granted by _reserve whose child is not counted yet
        self._ensure_warm()

    # ---- accounting ------------------------------------------------------------------------------------------

    @staticmethod
    def _has_child(conv: Conversation) -> bool:
        return conv.conn is not None and not conv.conn.exited

    @staticmethod
    def _discard_standby(item: tuple[AcpConnection, str]) -> None:
        conn, cwd = item
        try:
            conn.close()
        finally:
            shutil.rmtree(cwd, ignore_errors=True)

    def _active_locked(self) -> int:
        convs = [c for g in self._groups.values() for c in g] + list(self._guests)
        live_convs = sum(1 for c in convs if self._has_child(c))
        live_standby = sum(1 for conn, _ in self._standby if not conn.exited)
        return live_convs + live_standby + self._opening + self._warming + self._closing

    def children(self) -> int:
        with self._lock:
            convs = [c for g in self._groups.values() for c in g] + list(self._guests)
            live_standby = sum(1 for conn, _ in self._standby if not conn.exited)
        return sum(1 for c in convs if self._has_child(c)) + live_standby

    def standby(self) -> int:
        with self._lock:
            return sum(1 for conn, _ in self._standby if not conn.exited)

    def _ensure_warm(self) -> None:
        if self.warm_standby <= 0:
            return
        to_start = 0
        dead: list[tuple[AcpConnection, str]] = []
        with self._lock:
            if self._closed:
                return
            dead = [item for item in self._standby if item[0].exited]
            if dead:
                self._standby = [item for item in self._standby if not item[0].exited]
            while (len(self._standby) + self._warming < self.warm_standby
                   and self._active_locked() < self.max_children):
                self._warming += 1
                to_start += 1
        for item in dead:
            self._discard_standby(item)
        for _ in range(to_start):
            threading.Thread(target=self._warm_one, name="acp-standby-warm", daemon=True).start()

    def _warm_one(self) -> None:
        cwd = tempfile.mkdtemp(prefix="acp-gw-cwd-")
        conn: AcpConnection | None = None
        try:
            conn = self._spawn("standby", cwd)
        except Exception as exc:  # noqa: BLE001 - standby warmup failure must never crash the server
            logger.info("acp-gateway: warm standby spawn failed (%s)", type(exc).__name__)
            shutil.rmtree(cwd, ignore_errors=True)
            with self._lock:
                self._warming -= 1
            return
        keep = False
        closing = False
        with self._lock:
            self._warming -= 1
            if not self._closed and not conn.exited and len(self._standby) < self.warm_standby:
                self._standby.append((conn, cwd))
                keep = True
                count = len(self._standby)
            elif not conn.exited:
                self._closing += 1
                closing = True
        if keep:
            logger.info("acp-gateway: warm standby ready (%d)", count)
        else:
            try:
                self._discard_standby((conn, cwd))
            finally:
                if closing:
                    with self._lock:
                        self._closing -= 1

    def _reserve(self) -> tuple[AcpConnection, str] | None:
        """Grant one slot for a new child (released by ``_release``): pop a healthy warm standby if available,
        else evict the least recently used idle branch, wait, or raise PoolFull."""
        deadline = time.monotonic() + self.wait_s
        while True:
            victim = None
            dead: list[tuple[AcpConnection, str]] = []
            with self._lock:
                while self._standby:
                    item = self._standby.pop(0)
                    if not item[0].exited:
                        self._opening += 1
                        prewarmed = item
                        break
                    dead.append(item)
                else:
                    prewarmed = None
                if prewarmed is None and self._active_locked() < self.max_children:
                    self._opening += 1
                    break
                if prewarmed is None:
                    idle = [c for g in self._groups.values() for c in g if self._has_child(c) and not c.live]
                    if idle:
                        victim = min(idle, key=lambda c: c.last_used)
                        for g in self._groups.values():
                            if victim in g:
                                g.remove(victim)
                        self._closing += 1
            for item in dead:
                self._discard_standby(item)
            if prewarmed is not None:
                self._ensure_warm()
                return prewarmed
            if victim is not None:
                logger.info("acp-gateway: evicted idle branch %s (cap %d)", victim.key, self.max_children)
                try:
                    victim.close()
                finally:
                    with self._lock:
                        self._closing -= 1
                continue
            if time.monotonic() >= deadline:
                raise PoolFull(f"all {self.max_children} Antigravity children are busy")
            time.sleep(0.5)
        for item in dead:
            self._discard_standby(item)
        return None

    def _release(self, prewarmed: tuple[AcpConnection, str] | None = None) -> None:
        discard = False
        closing = False
        with self._lock:
            self._opening -= 1
            if prewarmed is not None:
                conn, _ = prewarmed
                if not self._closed and not conn.exited and len(self._standby) < self.warm_standby:
                    self._standby.append(prewarmed)
                else:
                    discard = True
                    if not conn.exited:
                        self._closing += 1
                        closing = True
        if discard and prewarmed is not None:
            try:
                self._discard_standby(prewarmed)
            finally:
                if closing:
                    with self._lock:
                        self._closing -= 1

    def reap(self) -> None:
        """Close branches idle for longer than ``idle_ttl``."""
        now = time.monotonic()
        with self._lock:
            stale = [c for g in self._groups.values() for c in g if not c.live and now - c.last_used > self.idle_ttl]
            for g in self._groups.values():
                g[:] = [c for c in g if c not in stale]
            for k in [k for k, g in self._groups.items() if not g]:
                self._groups.pop(k, None)
            closing = [self._has_child(c) for c in stale]
            remaining = sum(1 for live in closing if live)
            self._closing += remaining
        try:
            for c, was_live in zip(stale, closing, strict=True):
                try:
                    c.close()
                finally:
                    if was_live:
                        remaining -= 1
                        with self._lock:
                            self._closing -= 1
        except BaseException:
            if remaining:
                with self._lock:
                    self._closing -= remaining
            raise
        self._ensure_warm()

    def close_all(self) -> None:
        with self._lock:
            self._closed = True
            convs = [c for g in self._groups.values() for c in g] + list(self._guests)
            standby, self._standby = list(self._standby), []
            self._groups.clear()
            self._guests.clear()
        for c in convs:
            c.close()
        for item in standby:
            self._discard_standby(item)

    # ---- serving ---------------------------------------------------------------------------------------------

    def serve(self, group: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]], model: str,
              thinking: str | None, token: threading.Event, *, stateless: bool = False) -> dict:
        if stateless:
            prewarmed = self._reserve()
            released = threading.Event()

            def release_once() -> None:
                if not released.is_set():
                    released.set()
                    self._release()

            conn0, cwd0 = prewarmed if prewarmed is not None else (None, None)
            dead_prewarmed: tuple[AcpConnection, str] | None = None
            with self._lock:
                if conn0 is not None and not conn0.exited:
                    conv = Conversation("guest", self._spawn, stateless=True, step_deadline=self.step_deadline,
                                        collect_window=self.collect_window, initial_conn=conn0, cwd=cwd0)
                    self._guests.add(conv)
                    released.set()
                    self._opening -= 1  # already counted via _has_child(conv); atomic handoff
                else:
                    if conn0 is not None and cwd0 is not None:
                        dead_prewarmed = (conn0, cwd0)
                    conv = Conversation("guest", self._spawn, stateless=True, step_deadline=self.step_deadline,
                                        collect_window=self.collect_window, initial_conn=None, cwd=None)
                    self._guests.add(conv)
                    # _opening stays reserved until conv.finish(on_open=release_once)
            try:
                if dead_prewarmed is not None:
                    self._discard_standby(dead_prewarmed)
                started = conv.begin(messages, tools, model, token, thinking)
                return conv.finish(started, on_open=release_once)
            finally:
                release_once()
                with self._lock:
                    was_live = self._has_child(conv)
                    self._guests.discard(conv)
                    if was_live:
                        self._closing += 1
                try:
                    conv.close()
                finally:
                    if was_live:
                        with self._lock:
                            self._closing -= 1
                self._ensure_warm()

        with self._lock:
            glock = self._group_locks.setdefault(group, threading.Lock())
        reserved = False
        prewarmed = None
        matched: tuple[Conversation, dict] | None = None
        try:
            while True:
                with glock:
                    with self._lock:
                        branches = list(self._groups.get(group, []))
                    declines = []
                    for cand in sorted(branches, key=lambda c: c.last_used, reverse=True):
                        h = cand.begin(messages, tools, model, token, thinking, only=("resume_held", "continue"))
                        if "declined" in h:
                            declines.append(f"{cand.key}: {h['declined']}" + (f" ({h['why']})" if h.get("why") else ""))
                        if "gen" in h:
                            if reserved:
                                self._release(prewarmed)
                                reserved, prewarmed = False, None
                            matched = (cand, h)
                            break
                    if matched is not None:
                        break
                    if reserved:  # a slot is held: open the new branch under the group lock
                        conn0, cwd0 = prewarmed if prewarmed is not None else (None, None)
                        prewarmed = None  # ownership transfers below
                        dead_prewarmed = None
                        with self._lock:
                            self._seq += 1
                            if conn0 is not None and not conn0.exited:
                                conv = Conversation(
                                    f"{group[:12]}-{self._seq}", self._spawn,
                                    step_deadline=self.step_deadline, terminal_tools=self.terminal_tools,
                                    collect_window=self.collect_window, initial_conn=conn0, cwd=cwd0,
                                )
                                self._groups.setdefault(group, []).append(conv)
                                self._opening -= 1  # now counted via _has_child(conv), no double-count
                                reserved = False
                            else:
                                if conn0 is not None and cwd0 is not None:
                                    dead_prewarmed = (conn0, cwd0)
                                conv = Conversation(
                                    f"{group[:12]}-{self._seq}", self._spawn,
                                    step_deadline=self.step_deadline, terminal_tools=self.terminal_tools,
                                    collect_window=self.collect_window, initial_conn=None, cwd=None,
                                )
                                self._groups.setdefault(group, []).append(conv)
                                # reserved stays True so _opening remains held until fresh spawn completes
                        if dead_prewarmed is not None:
                            self._discard_standby(dead_prewarmed)
                        logger.info("acp-gateway: new branch %s (group has %d)%s", conv.key, len(branches) + 1,
                                    "; declined by " + "; ".join(declines) if declines else "")
                        handle = conv.begin(messages, tools, model, token, thinking)
                        if "gen" not in handle:  # a fresh branch always replays; anything else breaks the core contract
                            raise ProviderError(f"unexpected decision on a new branch: {sorted(handle)}")
                        break
                # no branch matched: get a child slot without holding the group lock, then re-check (another request
                # of this group may have opened a matching branch meanwhile)
                prewarmed = self._reserve()
                reserved = True
            if matched is not None:
                cand, h = matched
                return cand.finish(h)
            on_open = self._release if reserved else None
            reserved = False
            return conv.finish(handle, on_open=on_open)
        finally:
            if reserved:
                self._release(prewarmed)
            self._ensure_warm()
