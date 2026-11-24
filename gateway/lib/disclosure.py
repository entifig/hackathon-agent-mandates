"""Safe aggregate counts (question 8): small-count suppression for `aggregate`, decided by the gateway.

The MCP server's aggregate(table, group_by, measure, where) returns one row per group, {group cols..., total, count},
with no suppression. Whether a count is safe depends on the RESULT (a count of 1 in-care pupil of one ethnic group at
one school identifies that child), so the gateway checks both before and after the call. This applies to every
aggregate call through this gateway, whatever the mandate: there is no way to opt out.

Before the call (gateway_verify.decide, after the scope check; 403 DENY, nothing forwarded):
  - arguments must have the types the tool takes: table str, group_by list of distinct str, measure str,
    where absent/null or {str: str}, nothing else (AGGREGATE_MALFORMED)
  - at most MAX_GROUP_BY group_by columns (AGGREGATE_DISCLOSIVE)
  - no identifying column (pupil ID, names, dates of birth, postcodes, a near-unique score...) in group_by,
    measure or where (AGGREGATE_DISCLOSIVE)
  - `where` may only pick ONE census snapshot: exactly {AcademicYear, CensusTerm}, or nothing. Any other filter
    (Gender, URN, a pupil ID) is a subgroup that can be differenced against the unfiltered answer, so subgroups must be
    asked for as group_by, where they get the same suppression (AGGREGATE_DISCLOSIVE)

The call: the gateway forwards aggregate(table, group_by + ["Psuedo ID"], measure, where), so it can count PEOPLE.
`total` and `count` are census rows, not pupils: one pupil has up to 11 rows (one per census), so 15 in-care rows at
Ashfield are 3 children. A threshold on rows would release them. The pupil-level rows never leave the gateway: it
sums them back into exactly the answer the agent asked for (same numbers as the plain call), then:

After the call, per group (cell), with k = min_count and P = distinct pupils in the cell:
  1. P < k: the group is left out of the answer altogether. A missing group then means "none, or fewer than k", so
     the answer does not even say that a small group exists (group_by ["URN", "InCareAtCurrentSchool"] would
     otherwise show which schools have a child in care).
  2. count is suppressed unless at least k pupils in the cell have the measure AND at least k do not. This hides
     small counts, zeros next to small counts (0 vs 3 is itself a disclosure), and "all but two are in care"
     (total minus count).
  3. secondary suppression: along every group_by dimension, each slice (e.g. one school's row, one ethnic group's
     column, the whole table for one group_by column) holds either no hidden cell or at least two, so a margin the
     agent can ask for separately (group_by ["URN"] beside ["URN", "Ethnicity"]) minus the released cells never gives
     one hidden cell. Totals are done first and depend only on totals, so the same table with another `measure` hides
     the same totals; a hidden total hides its count. Choices are canonical (column names sorted), so
     ["URN", "Ethnicity"] and ["Ethnicity", "URN"] hide the same cells.
  4. every released number is rounded to the nearest multiple of round_to (half up), so differences between answers
     (all census rows minus the sum of the snapshots, or two linked tables) are off by several units, not exact.
Hidden numbers are replaced with SUPPRESSED. The response carries a `disclosure` note with the policy applied.

Who sets k: the gateway. MIN_COUNT and ROUND_TO below are the floor for every mandate. A mandate may carry a signed
    "disclosure": {"min_count": 20, "round_to": 10}
which RAISES either value for that mandate; a value below the floor is ignored (the floor applies). A malformed claim
(not an object, unknown key, not an int >= 1) denies every call DISCLOSURE_INVALID, like a malformed budget.

shortcut: the gateway knows the census schema (PUPIL_COLUMN, SNAPSHOT, IDENTIFYING). A new table with a differently
named pupil column fails closed (the upstream call errors) rather than being counted in rows.
shortcut: nothing is remembered between calls; differencing across answers is limited by the `where` rule, the
consistent secondary suppression and rounding, not prevented (see questions/08-aggregation.md, "Still unresolved").
"""

from __future__ import annotations

import re
from dataclasses import dataclass

TOOL = "aggregate"
MIN_COUNT = 10  # gateway floor: fewest distinct pupils behind any released number
ROUND_TO = 5  # gateway floor: released numbers are multiples of this
MAX_GROUP_BY = 2  # "by school, by ethnic group": two dimensions; each more makes every cell smaller
PUPIL_COLUMN = "Psuedo ID"  # sic, as in the data
SNAPSHOT = frozenset({"AcademicYear", "CensusTerm"})  # the only filter: one census, in which a pupil has one row
ARGUMENT_KEYS = frozenset({"table", "group_by", "measure", "where"})
CLAIM_KEYS = frozenset({"min_count", "round_to"})
SUPPRESSED = "suppressed"
# Direct identifiers and near-unique values (DeprivationScore has 1,395 values for 1,500 pupils). The pattern catches
# the usual names in a table this gateway has not seen.
IDENTIFYING = frozenset({PUPIL_COLUMN, "DisplayName", "DeprivationScore"})
IDENTIFYING_PATTERN = re.compile(
    r"(^|[\s_\-])id$|^id[\s_\-]|name|birth|\bdob\b|postcode|post_code|address|email|phone|\bupn\b|\buln\b",
    re.IGNORECASE,
)


class DisclosureInvalid(ValueError):  # noqa: N818
    """The mandate's disclosure claim is malformed. The gateway denies rather than guessing (fail closed)."""


class UncheckableResult(ValueError):  # noqa: N818
    """The upstream result is not the shape the gateway can count. Nothing is released."""


@dataclass(frozen=True)
class Policy:
    min_count: int = MIN_COUNT
    round_to: int = ROUND_TO


def parse_disclosure(claims: dict) -> Policy:
    """The policy for this mandate: the gateway floor, raised by the mandate's `disclosure` claim if it has one."""
    if "disclosure" not in claims:
        return Policy()
    raw = claims["disclosure"]
    if not isinstance(raw, dict):
        raise DisclosureInvalid(f"disclosure must be an object, got {type(raw).__name__}")
    if unknown := sorted(map(str, raw.keys() - CLAIM_KEYS)):
        raise DisclosureInvalid(f"unknown disclosure keys {unknown}")
    for name, value in raw.items():
        if type(value) is not int or value < 1:  # type(): True is not a threshold
            raise DisclosureInvalid(f"disclosure.{name} must be an integer >= 1, got {value!r}")
    return Policy(
        min_count=max(MIN_COUNT, raw.get("min_count", MIN_COUNT)),
        round_to=max(ROUND_TO, raw.get("round_to", ROUND_TO)),
    )


def identifying(column: str) -> bool:
    return column in IDENTIFYING or bool(IDENTIFYING_PATTERN.search(column))


def request_refusal(arguments: dict) -> tuple[str, str] | None:
    """Why this aggregate call is refused before it is forwarded, as (reason_code, detail), or None."""
    if unknown := sorted(map(str, arguments.keys() - ARGUMENT_KEYS)):
        return "AGGREGATE_MALFORMED", f"unknown arguments {unknown}"
    table, group_by, measure = arguments.get("table"), arguments.get("group_by"), arguments.get("measure")
    where = arguments.get("where")
    if not isinstance(table, str) or not isinstance(measure, str):
        return "AGGREGATE_MALFORMED", "table and measure must be strings"
    if not isinstance(group_by, list) or not all(isinstance(c, str) for c in group_by):
        return "AGGREGATE_MALFORMED", "group_by must be a list of column names"
    if len(set(group_by)) != len(group_by):
        return "AGGREGATE_MALFORMED", "group_by names a column twice"
    if where is not None and (
        not isinstance(where, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in where.items())
    ):
        return "AGGREGATE_MALFORMED", "where must be an object of column name to string value"
    if len(group_by) > MAX_GROUP_BY:
        return "AGGREGATE_DISCLOSIVE", f"at most {MAX_GROUP_BY} group_by columns, got {len(group_by)}"
    named = [*group_by, measure, *(where or {})]
    if bad := sorted({c for c in named if identifying(c)}):
        return "AGGREGATE_DISCLOSIVE", f"identifying column(s) {bad} cannot be grouped, counted or filtered on"
    if where and set(where) != SNAPSHOT:
        return (
            "AGGREGATE_DISCLOSIVE",
            f"where may only pick one census snapshot ({sorted(SNAPSHOT)}), got {sorted(where)}; "
            "ask for subgroups with group_by",
        )
    return None


def upstream_arguments(arguments: dict) -> dict:
    """What the gateway forwards: the agent's call, grouped one level further by pupil."""
    return {**arguments, "group_by": [*arguments["group_by"], PUPIL_COLUMN]}


# ---------------------------------------------------------------- after the call


@dataclass
class _Cell:
    total: int = 0  # census rows
    count: int = 0  # census rows with measure == "1"
    pupils: int = 0  # distinct pupils
    with_measure: int = 0  # distinct pupils with at least one row where measure == "1"
    without_measure: int = 0  # distinct pupils with at least one row where it is not


def _cells(group_by: list[str], rows) -> dict[tuple[str, ...], _Cell]:
    """Sum the pupil-level upstream rows back into the agent's groups. Raises UncheckableResult."""
    if not isinstance(rows, list):
        raise UncheckableResult("result is not a list")
    cells: dict[tuple[str, ...], _Cell] = {}
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {*group_by, PUPIL_COLUMN, "total", "count"}:
            raise UncheckableResult("unexpected result row")
        total, count = row["total"], row["count"]
        values = tuple(row[c] for c in group_by)
        pupil = row[PUPIL_COLUMN]
        if type(total) is not int or type(count) is not int or not 0 <= count <= total or total < 1:
            raise UncheckableResult("unexpected counts")
        if not all(isinstance(v, str) for v in (*values, pupil)) or (values, pupil) in seen:
            raise UncheckableResult("unexpected group values")
        seen.add((values, pupil))
        cell = cells.setdefault(values, _Cell())
        cell.total += total
        cell.count += count
        cell.pupils += 1
        cell.with_measure += count > 0
        cell.without_measure += count < total
    return cells


def _secondary(values: dict[tuple, int], hidden: set[tuple], canon) -> None:
    """Hide more cells, in place, until no slice along any dimension holds exactly one hidden cell."""
    if not values:
        return
    ndim = len(next(iter(values)))
    if ndim == 0:
        return  # one cell, no margin to subtract it from
    dims = sorted(range(ndim), key=lambda d: canon.order[d])
    changed = True
    while changed:
        changed = False
        for d in dims:
            slices: dict[tuple, list[tuple]] = {}
            for key in values:
                slices.setdefault(canon(key[:d] + key[d + 1 :], skip=d), []).append(key)
            for _, keys in sorted(slices.items()):
                inside = [k for k in keys if k in hidden]
                shown = [k for k in keys if k not in hidden]
                if len(inside) == 1 and shown:
                    # the smallest non-zero cell hides the most like it; ties broken canonically
                    hidden.add(min(shown, key=lambda k: (values[k] == 0, values[k], canon(k))))
                    changed = True


class _Canon:
    """Orders keys by column NAME, so the same group_by in another order hides the same cells."""

    def __init__(self, group_by: list[str]):
        self.order = [sorted(group_by).index(c) for c in group_by]  # rank of each position's column name

    def __call__(self, key: tuple, skip: int | None = None) -> tuple:
        positions = [d for d in range(len(self.order)) if d != skip]
        return tuple(v for _, v in sorted(zip((self.order[d] for d in positions), key, strict=True)))


def _round(value: int, base: int) -> int:
    return (2 * value + base) // (2 * base) * base  # nearest multiple, half up


def protect(arguments: dict, rows, policy: Policy) -> tuple[list[dict], dict]:
    """The agent's answer from the pupil-level upstream rows, with small counts suppressed and the rest rounded.
    Returns (released rows, note). Raises UncheckableResult."""
    group_by: list[str] = arguments["group_by"]
    k = policy.min_count
    cells = _cells(group_by, rows)
    canon = _Canon(group_by)

    small = {key for key, c in cells.items() if c.pupils < k}
    listed = {key: c for key, c in cells.items() if key not in small}
    hidden_totals = set(small)
    _secondary({key: c.total for key, c in cells.items()}, hidden_totals, canon)
    hidden_counts = hidden_totals | {
        key for key, c in cells.items() if c.with_measure < k or c.without_measure < k
    }
    _secondary({key: c.count for key, c in cells.items()}, hidden_counts, canon)

    released = []
    for key in sorted(listed):  # the upstream order: by group_by values as asked
        cell = listed[key]
        released.append(
            dict(
                zip(group_by, key, strict=True),
                total=SUPPRESSED if key in hidden_totals else _round(cell.total, policy.round_to),
                count=SUPPRESSED if key in hidden_counts else _round(cell.count, policy.round_to),
            )
        )
    marked = sum(v == SUPPRESSED for row in released for v in (row["total"], row["count"]))
    note = {
        "min_count": k,
        "round_to": policy.round_to,
        "suppressed": marked,
        "note": (
            f"Groups with fewer than {k} distinct pupils are left out, so a missing group means none or fewer than "
            f"{k}. A count is shown only when at least {k} pupils in the group have '{arguments['measure']}' and at "
            f"least {k} do not; other numbers hidden so that margins cannot recover them are '{SUPPRESSED}'. "
            f"total and count are census rows, rounded to the nearest {policy.round_to}."
        ),
    }
    return released, note
