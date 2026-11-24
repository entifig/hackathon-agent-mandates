"""Seen request nonces, persisted so a gateway restart does not reopen the replay window.

A signed request is fresh for TS_WINDOW seconds either side of its `ts`. Inside that window the nonce is what stops a
replay, so the set of seen nonces must outlive the process: before this store it lived in memory, and a request
captured shortly before a restart could be replayed after it ("No key" break).

  - Only a request whose signature verified is recorded (Gateway.decide_with_claims), so an unsigned request cannot
    burn a legitimate agent's future nonce.
  - The nonce is recorded, and fsynced, before the request is forwarded.
  - An entry whose ts is older than now - TS_WINDOW can never be accepted again (its ts is outside the window), so it
    is pruned: on load, and whenever the file reaches twice what the last compaction kept (at least
    COMPACT_MIN_LINES). The file stays bounded by twice the signed requests within one window.
  - Nonces are at most MAX_NONCE_LEN characters, so a giant nonce cannot bloat the file.
  - Unreadable, corrupt or unsaveable: every request is refused (NONCE_UNAVAILABLE), never a 500 and never an empty
    set. A missing file is a first run.

File: <state_dir>/nonces.jsonl, one {"nonce": str, "ts": int} per line, appended per request and compacted with a
temp file + fsync + os.replace.
shortcut: one process. Several replicas need a shared store (e.g. Redis SET NX with an expiry).
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

TS_WINDOW = 300  # seconds either side of now that a request's ts may be
MAX_NONCE_LEN = 128
COMPACT_MIN_LINES = 1000


class NonceStoreUnavailable(RuntimeError):  # noqa: N818
    """The nonce file could not be read or written. Every request is refused until it is fixed."""


class NonceStore:
    """nonce -> request ts. `path=None` keeps it in memory only (tests, the eval's in-process gateway)."""

    def __init__(self, path: Path | None = None, window: int = TS_WINDOW):
        self.path = path
        self.window = window
        self.error: str | None = None
        self._seen: dict[str, int] = {}
        self._lines = 0  # lines in the file now, live or not
        self._live = 0  # entries kept by the last compaction

    @classmethod
    def load(cls, path: Path, window: int = TS_WINDOW) -> NonceStore:
        """Read and compact the file. Never raises: a bad file leaves the store unavailable, not empty."""
        store = cls(path, window)
        if not path.exists():
            return store
        try:
            for line in path.read_text().splitlines():
                if not line.strip():
                    continue
                entry = json.loads(line)
                nonce, ts = entry["nonce"], entry["ts"]
                if not isinstance(nonce, str) or type(ts) is not int:
                    raise ValueError("bad entry")
                store._seen[nonce] = max(ts, store._seen.get(nonce, ts))
            store._compact()
        except NonceStoreUnavailable:
            pass  # error already set
        except Exception as e:  # noqa: BLE001  (any failure to read is the same answer: fail closed)
            store._seen = {}
            store.error = f"{path.name} unreadable ({type(e).__name__})"
        return store

    def check_available(self) -> None:
        if self.error:
            raise NonceStoreUnavailable(self.error)

    def seen(self, nonce: str) -> bool:
        return nonce in self._seen

    def add(self, nonce: str, ts: int) -> None:
        """Record a verified request's nonce, durably, before it is forwarded. Raises NonceStoreUnavailable."""
        self.check_available()
        self._seen[nonce] = ts
        if self.path is None:
            self._prune()
            return
        try:
            with self.path.open("a") as f:
                f.write(json.dumps({"nonce": nonce, "ts": ts}) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:
            self.error = f"{self.path.name} could not be saved ({type(e).__name__})"
            raise NonceStoreUnavailable(self.error) from e
        self._lines += 1
        if self._lines >= max(COMPACT_MIN_LINES, 2 * self._live):
            self._compact()

    def _prune(self) -> None:
        oldest = int(time.time()) - self.window
        self._seen = {n: ts for n, ts in self._seen.items() if ts >= oldest}

    def _compact(self) -> None:
        """Drop entries that can no longer be replayed and rewrite the file atomically."""
        self._prune()
        if self.path is None:
            return
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".nonces.", suffix=".tmp")
            with os.fdopen(fd, "w") as f:
                f.writelines(json.dumps({"nonce": n, "ts": ts}) + "\n" for n, ts in self._seen.items())
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except OSError as e:
            if tmp:
                Path(tmp).unlink(missing_ok=True)
            self.error = f"{self.path.name} could not be compacted ({type(e).__name__})"
            raise NonceStoreUnavailable(self.error) from e
        self._lines = self._live = len(self._seen)
