"""Run budgets (question 11): what a mandate may return over its whole life, not per call.

A mandate may carry a signed top-level claim

    "budget": {"pupils": 40, "calls": 100, "id": "elmwood-y11-fsm"}

    pupils  required int >= 0. Most DISTINCT pupils the mandate may ever name or see. A pupil already charged costs
            nothing the second time, so "one at a time over a known cohort" fits.
    calls   optional int >= 0. Most calls forwarded to an MCP server, whatever came back.
    id      optional non-empty string. Lets an issuer make several mandates for one person share ONE budget (a parent
            and a delegated child, two mandates for one job). Defaults to the mandate's jti.

The ledger key is (iss, delegator.principal, id or jti): two issuers, or two people, never share a budget by
picking the same id.

A budget is only as good as the gateway's knowledge of what a call costs. It must not decide from the data, or the
decision itself becomes an uncharged oracle (a withheld result vs an empty one says something about a pupil). So a
budgeted mandate is charged on its REQUEST, before forwarding, from the arguments and the ledger alone:

  1. only tools in BUDGET_TOOLS (no `aggregate`: counts name no pupil, so differencing them is uncounted);
  2. `search` only by exactly one pupil ID, so a query cannot test a row's contents (BUDGET_QUERY);
  3. every pupil ID named in the arguments is charged, found or not; over `pupils` is refused (BUDGET_EXHAUSTED);
  4. once the budget is full, only calls that name pupils already charged, on a tool whose result is bounded by the
     IDs it names, go through;
  5. the call is counted (and persisted) before forwarding.

A delegated child (question 7, delegation.py) is charged to EVERY budget in its chain (`chain_budgets`): its own, if
it carries one (keyed by the gateway as "delegated:<parent jti>:<child jti>", never an id the child picks), and its
parent's. A call goes through only if it fits all of them, so a helper is not a way round the parent's budget, and the
helper's pupils count against the parent's run.

The result is still scanned as a backstop for tools that list pupils without naming them (`roster`, `get`): a result
that would take the mandate past `pupils` is withheld whole and its pupils are not charged.

Usage persists to <state_dir>/budget_ledger.json (temp file, fsync, os.replace) so a restart does not hand out fresh
budgets. An unreadable or corrupt ledger, or one that fails to save, makes every budgeted call DENY
BUDGET_UNAVAILABLE: never a reset to empty.
shortcut: one process. The lock is an asyncio.Lock and the file is not locked; share the ledger (e.g. a database
row per key) before running more than one gateway replica or worker.
shortcut: a missing ledger file is read as a first run (empty). Deleting it while the gateway is down resets budgets.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# A pupil's pseudo ID ("Psuedo ID" column, "P0004"), for scanning text. No word boundaries and any case:
# "P0004P0005" or "p0004" still count. Over-counting only costs budget; under-counting is a hole.
PUPIL_ID = re.compile(r"P[0-9]{4,}", re.IGNORECASE)
# A search query a budgeted mandate may send: one pupil ID and nothing else (fullmatch, ASCII digits only).
ID_QUERY = re.compile(r"P[0-9]{4,}")
CLAIM_KEYS = {"pupils", "calls", "id"}
# Tools a budgeted mandate may use: every one either names the pupils it touches or returns their IDs.
BUDGET_TOOLS = {"search", "pupil", "draft", "write", "roster", "get", "classification"}
# Tools whose result covers only the pupils named in the arguments, so their cost is known before forwarding.
ID_BOUNDED_TOOLS = {"search", "pupil", "draft", "write"}

Key = tuple[str, str, str]  # (iss, delegator.principal, id or jti)


class BudgetInvalid(ValueError):  # noqa: N818
    """The mandate's budget claim is malformed. The gateway denies rather than guessing (fail closed)."""


class LedgerUnavailable(RuntimeError):  # noqa: N818
    """The ledger could not be read or saved. Budgeted calls are refused until it is fixed."""


@dataclass(frozen=True)
class Budget:
    pupils: int
    calls: int | None
    key: Key
    label: str = "mandate"  # "mandate", or for a delegated child "child" / "parent": named in refusals


def _count(raw: dict, name: str) -> int:
    value = raw[name]
    if type(value) is not int or value < 0:  # type(): bool is an int subclass, True is not a budget
        raise BudgetInvalid(f"budget.{name} must be an integer >= 0, got {value!r}")
    return value


def parse_budget(claims: dict) -> Budget | None:
    """The mandate's budget, or None when it carries no `budget` claim (unlimited, as before). Raises BudgetInvalid."""
    if "budget" not in claims:
        return None
    raw = claims["budget"]
    if not isinstance(raw, dict):
        raise BudgetInvalid(f"budget must be an object, got {type(raw).__name__}")
    if unknown := sorted(map(str, raw.keys() - CLAIM_KEYS)):
        raise BudgetInvalid(f"unknown budget keys {unknown}")
    if "pupils" not in raw:
        raise BudgetInvalid("budget.pupils is required")
    calls = _count(raw, "calls") if "calls" in raw else None
    budget_id = raw.get("id", claims.get("jti"))
    if not isinstance(budget_id, str) or not budget_id:
        raise BudgetInvalid(f"budget.id must be a non-empty string, got {budget_id!r}")
    delegator = claims.get("delegator")
    principal = delegator.get("principal") if isinstance(delegator, dict) else None
    if not isinstance(principal, str) or not principal:
        raise BudgetInvalid("a budgeted mandate needs a delegator.principal to key its ledger")
    iss = claims.get("iss")
    if not isinstance(iss, str):
        raise BudgetInvalid("iss must be a string")
    return Budget(pupils=_count(raw, "pupils"), calls=calls, key=(iss, principal, budget_id))


def chain_budgets(claims: dict) -> list[Budget]:
    """Every budget a call under these verified claims is charged to, own first. An ordinary mandate: its budget,
    if any. A delegated child (gateway-built claims with the verified parent under `parent`): its own and its
    parent's, so a helper cannot spend outside the parent's budget. Raises BudgetInvalid."""
    own = parse_budget(claims)
    parent = claims.get("parent")
    if not isinstance(parent, dict):  # verify_mandate refuses an issuer-signed `parent`: only a child has one
        return [own] if own else []
    budgets = [dataclasses.replace(own, label="child")] if own else []
    if parent_budget := parse_budget(parent):
        budgets.append(dataclasses.replace(parent_budget, label="parent"))
    return budgets


def request_refusal(tool: str, arguments: dict) -> str | None:
    """Why a budgeted mandate may not make this call whatever its ledger says (BUDGET_QUERY), or None."""
    if tool not in BUDGET_TOOLS:
        return f"{tool} is not available to a budgeted mandate (its cost cannot be counted in pupils)"
    if tool == "search":
        query = arguments.get("query")
        if not isinstance(query, str) or not ID_QUERY.fullmatch(query):
            return "a budgeted mandate searches by one pupil ID only, e.g. query='P0004'"
    return None


def pupil_ids(value) -> set[str]:
    """Every pupil ID anywhere in a value: dict keys and values, list items, strings, and str() of the rest."""
    found: set[str] = set()
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list | tuple | set | frozenset):
            stack.extend(item)
        elif item is None or isinstance(item, bool | int | float):
            continue  # a number has no P in it
        else:
            found.update(m.upper() for m in PUPIL_ID.findall(item if isinstance(item, str) else str(item)))
    return found


@dataclass
class Usage:
    calls: int = 0
    pupils: set[str] = field(default_factory=set)


def _entry_usage(entry) -> tuple[Key, Usage]:
    """One ledger file entry, checked field by field: anything odd makes the whole ledger unavailable."""
    key = (entry["iss"], entry["principal"], entry["id"])
    calls, pupils = entry["calls"], entry["pupils"]
    if not all(isinstance(k, str) for k in key) or type(calls) is not int or calls < 0:
        raise ValueError("bad entry")
    if not isinstance(pupils, list) or not all(isinstance(p, str) for p in pupils):
        raise ValueError("bad pupils")
    return key, Usage(calls=calls, pupils=set(pupils))


class Ledger:
    """Usage per budget key, persisted to one JSON file. Callers hold `lock(key)` from first check to last charge."""

    def __init__(self, path: Path | None = None):
        self.path = path
        self.error: str | None = None  # set when the file could not be read or saved: every budgeted call is refused
        self._usage: dict[Key, Usage] = {}
        self._locks: dict[Key, asyncio.Lock] = {}

    @classmethod
    def load(cls, path: Path) -> Ledger:
        """Read the ledger file if there is one. Never raises: a bad file leaves the ledger unavailable, not empty."""
        ledger = cls(path)
        if not path.exists():
            return ledger  # first run
        try:
            data = json.loads(path.read_text())
            ledger._usage = dict(map(_entry_usage, data["budgets"]))
            if len(ledger._usage) != len(data["budgets"]):
                raise ValueError("duplicate entries")
        except Exception as e:  # noqa: BLE001  (any failure to read is the same answer: fail closed)
            ledger._usage = {}
            ledger.error = f"{path.name} unreadable ({type(e).__name__})"
        return ledger

    def lock(self, key: Key) -> asyncio.Lock:
        return self._locks.setdefault(key, asyncio.Lock())

    def usage(self, key: Key) -> Usage:
        return self._usage.setdefault(key, Usage())

    def check_available(self) -> None:
        if self.error:
            raise LedgerUnavailable(self.error)

    def calls_left(self, budget: Budget) -> bool:
        return budget.calls is None or self.usage(budget.key).calls < budget.calls

    def new_pupils(self, budget: Budget, ids: set[str]) -> set[str]:
        return ids - self.usage(budget.key).pupils

    def fits(self, budget: Budget, ids: set[str]) -> bool:
        return len(self.usage(budget.key).pupils) + len(self.new_pupils(budget, ids)) <= budget.pupils

    def full(self, budget: Budget) -> bool:
        return len(self.usage(budget.key).pupils) >= budget.pupils

    def charge(self, budget: Budget | list[Budget], ids: set[str], calls: int = 0) -> None:
        """Add `ids` and `calls` to the usage of each budget (each ledger key once) and save once. The caller checked
        `fits` first."""
        keys = list(dict.fromkeys(b.key for b in (budget if isinstance(budget, list) else [budget])))
        if not calls and all(ids <= self.usage(key).pupils for key in keys):
            return  # nothing new: no write
        for key in keys:
            used = self.usage(key)
            used.calls += calls
            used.pupils |= ids
        self.save()

    def report(self, budget: Budget) -> dict:
        used = self.usage(budget.key)
        return {
            "pupils_used": len(used.pupils),
            "pupils_limit": budget.pupils,
            "calls_used": used.calls,
            "calls_limit": budget.calls,
        }

    def save(self) -> None:
        """Write the ledger atomically. On failure the ledger becomes unavailable and LedgerUnavailable is raised."""
        self.check_available()
        if self.path is None:
            return
        data = {
            "budgets": [
                {"iss": iss, "principal": principal, "id": budget_id, "calls": u.calls, "pupils": sorted(u.pupils)}
                for (iss, principal, budget_id), u in sorted(self._usage.items())
            ]
        }
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".budget_ledger.", suffix=".tmp")
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=1)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except OSError as e:
            if tmp:
                Path(tmp).unlink(missing_ok=True)
            self.error = f"{self.path.name} could not be saved ({type(e).__name__})"
            raise LedgerUnavailable(self.error) from e
