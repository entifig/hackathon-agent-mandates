"""Question 8: safe aggregate counts. Small-count suppression in the gateway, checked against the real synthetic data.

Every test that needs "the truth" reads the census CSV the MCP server serves; nothing here changes that data.
"""

import csv
import itertools
from collections import defaultdict
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gateway import cli, main
from gateway import eval as ev
from gateway.lib import audit, disclosure
from gateway.lib.common import priv_from_pem
from gateway.lib.disclosure import MIN_COUNT, SUPPRESSED, Policy, protect, upstream_arguments
from mcp_server.api.routes_mcp import aggregate, mcp

ROOT = Path(__file__).resolve().parents[2]
CENSUS = "personal_data_school_census"
IN_CARE, FSM = "InCareAtCurrentSchool", "FSMeligible"
SNAPSHOT = {"AcademicYear": "2023/24", "CensusTerm": "SPR"}
COUNTS_SCOPE = [
    {"server": "pupil-data", "tools": ["aggregate"], "constraints": {"table": [CENSUS], "measure": [IN_CARE, FSM]}}
]


def census() -> list[dict]:
    with (ROOT / "mcp_server/data/synthetic/synthetic_personal_data_school_census.csv").open(newline="") as f:
        return list(csv.DictReader(f))


ROWS = census()


def truth(group_by, measure, where=None) -> dict[tuple, dict]:
    """Per group: distinct pupils, pupils with / without the measure, from the CSV itself."""
    cells = defaultdict(lambda: {"pupils": set(), "with": set(), "without": set()})
    for row in ROWS:
        if any(row[k] != v for k, v in (where or {}).items()):
            continue
        cell = cells[tuple(row[c] for c in group_by)]
        cell["pupils"].add(row["Psuedo ID"])
        cell["with" if row[measure] == "1" else "without"].add(row["Psuedo ID"])
    return {k: {n: len(v) for n, v in c.items()} for k, c in cells.items()}


def answer(group_by, measure, where=None, policy=None) -> list[dict]:
    """What the gateway releases, computed the way main._forward_aggregate does, against the real MCP tool."""
    arguments = {"table": CENSUS, "group_by": group_by, "measure": measure, **({"where": where} if where else {})}
    return protect(arguments, aggregate(**upstream_arguments(arguments)), policy or Policy())[0]


def keyed(rows, group_by) -> dict[tuple, dict]:
    return {tuple(r[c] for c in group_by): r for r in rows}


# group_by sets and filters the property tests sweep: the question's own, the red team's, and some margins
GROUPINGS = [[], ["URN"], ["Ethnicity"], ["URN", "Ethnicity"], ["URN", IN_CARE], ["Ethnicity", IN_CARE], ["URN", FSM]]
FILTERS = [None, SNAPSHOT, {"AcademicYear": "2021/22", "CensusTerm": "AUT"}]
SWEEP = [(g, m, w) for g in GROUPINGS for m in (IN_CARE, FSM) for w in FILTERS]


# ---------------------------------------------------------------- the gateway, in process


@pytest.fixture
def gw(tmp_path, monkeypatch):
    state = tmp_path / "state"
    cli.main(["--state", str(state), "init"])
    cli.main(["--state", str(state), "issue", "--agent-key", str(state / "agent.pem"), "-o", str(state / "m.jwt")])
    monkeypatch.setattr(main, "STATE_DIR", state)
    monkeypatch.setitem(main.MCP_SERVERS, "pupil-data", mcp)
    monkeypatch.delenv("GATEWAY_AUDIT_LOG", raising=False)
    with TestClient(main.app) as client:
        yield client, state


@pytest.fixture
def issue(gw):
    """issue(scope, extra) -> call(tool, **arguments) -> response, under a new mandate for the test agent key."""
    client, state = gw
    priv = priv_from_pem((state / "agent.pem").read_bytes())

    def issue(scope=COUNTS_SCOPE, extra=None):
        token, _ = cli.issue_mandate(
            state,
            priv.public_key(),
            scope=scope,
            deny=cli.DEFAULT_DENY,
            ttl=600,
            purpose="In-care counts by school and ethnic group",
            principal="officer:jsmith",
            org="la:hackathon",
            extra=extra or {},
        )

        def call(tool="aggregate", **arguments):
            body = cli.sign_request(priv, server="pupil-data", tool=tool, arguments=arguments, mandate=token)
            return client.post("/tools/call", json=body)

        return call

    return issue


@pytest.fixture
def forwarded(monkeypatch):
    """Arguments of every call that reached the MCP server."""
    seen = []
    upstream = main.call_upstream

    async def recording(target, body):
        seen.append(body.arguments)
        return await upstream(target, body)

    monkeypatch.setattr(main, "call_upstream", recording)
    return seen


def reason(r):
    return r.status_code, r.json()["decision"]["reason_code"]


def counts(group_by, measure=IN_CARE, where=None) -> dict:
    return {"table": CENSUS, "group_by": group_by, "measure": measure, **({"where": where} if where else {})}


# ---------------------------------------------------------------- the question, through the gateway


def test_in_care_by_school_and_ethnic_group_is_released_with_every_small_count_hidden(issue, forwarded):
    r = issue()(**counts(["URN", "Ethnicity"], where=SNAPSHOT))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decision"]["decision"] == "ALLOW"
    assert body["disclosure"]["min_count"] == MIN_COUNT
    # the gateway asked for counts per pupil, and released none of them
    assert forwarded == [
        {**counts(["URN", "Ethnicity"], where=SNAPSHOT), "group_by": ["URN", "Ethnicity", "Psuedo ID"]}
    ]
    assert "Psuedo ID" not in str(body["result"])
    real = truth(["URN", "Ethnicity"], IN_CARE, SNAPSHOT)
    for row in body["result"]:
        cell = real[(row["URN"], row["Ethnicity"])]
        assert cell["pupils"] >= MIN_COUNT
        assert row["count"] == SUPPRESSED  # 7 children in care in the whole census: no cell has 10
    # every small group is left out, so a missing group says nothing
    shown = {(row["URN"], row["Ethnicity"]) for row in body["result"]}
    assert {k for k, c in real.items() if c["pupils"] < MIN_COUNT}.isdisjoint(shown)


def test_a_count_over_the_threshold_is_released_rounded(issue):
    r = issue()(**counts(["URN"], measure=FSM, where=SNAPSHOT))
    assert r.status_code == 200
    plain = keyed(aggregate(CENSUS, ["URN"], FSM, SNAPSHOT), ["URN"])
    released = [row for row in r.json()["result"] if row["count"] != SUPPRESSED]
    assert released
    for row in released:
        assert row["count"] % 5 == 0
        assert abs(row["count"] - plain[(row["URN"],)]["count"]) <= 2


def test_eval_counts_case_still_allowed(issue):
    (stem_scope,) = [scope for prefix, (_, scope) in ev.JOBS.items() if prefix == "counts mandate"]
    ((name, tool, arguments),) = [c for c in ev.VALID if c[1] == "aggregate"]
    r = issue(scope=stem_scope)(tool, **arguments)
    assert (r.status_code, r.json()["decision"]["decision"]) == (200, "ALLOW"), name
    assert "disclosure" in r.json()
    # and the eval's in-care case is still refused by the scope, before this policy runs
    ((_, _, tool, arguments, code),) = [c for c in ev.INVALID if c[2] == "aggregate"]
    assert reason(issue(scope=stem_scope)(tool, **arguments)) == (403, code)


# ---------------------------------------------------------------- red team: what must never come out


@pytest.mark.parametrize(("group_by", "measure", "where"), SWEEP)
def test_no_released_number_rests_on_fewer_than_k_pupils(group_by, measure, where):
    real = truth(group_by, measure, where)
    for row in answer(group_by, measure, where):
        cell = real[tuple(row[c] for c in group_by)]
        assert cell["pupils"] >= MIN_COUNT, row  # a listed group has at least k pupils
        if row["count"] != SUPPRESSED:  # a count, and total minus count, each stand for at least k pupils
            assert cell["with"] >= MIN_COUNT, row
            assert cell["without"] >= MIN_COUNT, row


def test_group_by_school_ethnicity_and_in_care_is_refused_before_the_call(issue, forwarded):
    r = issue()(**counts(["URN", "Ethnicity", IN_CARE], where=SNAPSHOT))
    assert reason(r) == (403, "AGGREGATE_DISCLOSIVE")
    assert forwarded == []


def test_grouping_by_the_sensitive_column_shows_no_small_group(issue):
    # two columns are allowed; the (school, "1") groups that would point at a child in care are simply not there
    r = issue()(**counts(["URN", IN_CARE], where=SNAPSHOT))
    assert r.status_code == 200
    assert [row for row in r.json()["result"] if row[IN_CARE] == "1"] == []


def test_greystone_child_in_care_is_never_counted(issue):
    # the Day 2 60-point flag: the one pupil in care at SCH07
    for grouping in (["URN"], ["URN", "Ethnicity"], ["URN", "Gender"]):
        for where in (None, {"AcademicYear": "2022/23", "CensusTerm": "SPR"}):
            r = issue()(**counts(grouping, where=where))
            assert r.status_code == 200
            assert all(row["count"] == SUPPRESSED for row in r.json()["result"] if row["URN"] == "SCH07")


def test_total_minus_count_does_not_leak():
    # group_by the measure itself: every FSM=1 group has count == total, i.e. "none without" -> hidden
    for row in answer(["URN", FSM], FSM, SNAPSHOT):
        assert row["count"] == SUPPRESSED, row
    # and a hand-made group where all but two pupils have the measure
    rows = [{"URN": "S", "Psuedo ID": f"P{i:04d}", "total": 1, "count": int(i >= 2)} for i in range(30)]
    (row,) = protect(counts(["URN"]), rows, Policy())[0]
    assert (row["total"], row["count"]) == (30, SUPPRESSED)


def test_rows_are_not_pupils():
    # 15 in-care census rows at Ashfield are 3 children: a row threshold would have released them
    plain = keyed(aggregate(CENSUS, ["URN"], IN_CARE), ["URN"])
    assert plain[("SCH01",)]["count"] >= MIN_COUNT
    assert truth(["URN"], IN_CARE)[("SCH01",)]["with"] < MIN_COUNT
    assert keyed(answer(["URN"], IN_CARE), ["URN"])[("SCH01",)]["count"] == SUPPRESSED


@pytest.mark.parametrize(
    "where",
    [
        {"Gender": "F"},
        {"AcademicYear": "2023/24"},  # half a snapshot: a year minus its terms
        {"URN": "SCH07"},
        {**SNAPSHOT, "Gender": "F"},
        {**SNAPSHOT, "URN": "SCH07"},
        {"Psuedo ID": "P0586"},  # a single pupil
        {**SNAPSHOT, "Psuedo ID": "P0586"},
    ],
)
def test_where_may_only_pick_one_snapshot(issue, forwarded, where):
    assert reason(issue()(**counts(["URN"], where=where))) == (403, "AGGREGATE_DISCLOSIVE")
    assert forwarded == []


def test_where_one_snapshot_or_none_is_allowed(issue):
    call = issue()
    assert call(**counts(["URN"], where=SNAPSHOT)).status_code == 200
    assert call(**counts(["URN"])).status_code == 200
    assert call(**counts(["URN"]), where=None).status_code == 200
    assert call(**counts(["URN"]), where={}).status_code == 200


@pytest.mark.parametrize(("group_by", "measure", "where"), [s for s in SWEEP if len(s[0]) >= 1])
def test_a_margin_never_recovers_one_hidden_cell(group_by, measure, where):
    """Differencing two group_by sets: group_by minus one column is a margin the agent can ask for separately.
    Every slice of the answer that has more than one group in it hides none of them, or at least two."""
    real = truth(group_by, measure, where)
    shown = keyed(answer(group_by, measure, where), group_by)
    for field in ("total", "count"):
        hidden = {k for k in real if k not in shown or shown[k][field] == SUPPRESSED}
        for d in range(len(group_by)):
            slices = defaultdict(list)
            for key in real:
                slices[key[:d] + key[d + 1 :]].append(key)
            for keys in slices.values():
                inside = sum(k in hidden for k in keys)
                assert inside != 1 or len(keys) == 1, (field, group_by, keys)


def test_a_single_group_slice_is_hidden_in_its_margin_too():
    # the escape clause above: a slice with one group has the same pupils as its margin, so both are hidden
    whole = keyed(answer(["URN", "Ethnicity"], IN_CARE, SNAPSHOT), ["URN", "Ethnicity"])
    margin = keyed(answer(["Ethnicity"], IN_CARE, SNAPSHOT), ["Ethnicity"])
    for (ethnicity,), row in margin.items():
        if row["count"] != SUPPRESSED:
            assert sum(k[1] == ethnicity for k in whole) != 1


def test_school_margin_minus_released_cells_isolates_nothing():
    margin = keyed(answer(["URN"], FSM, SNAPSHOT), ["URN"])
    cells = answer(["URN", "Ethnicity"], FSM, SNAPSHOT)
    real = truth(["URN", "Ethnicity"], FSM, SNAPSHOT)
    for (urn,), row in margin.items():
        if row["count"] == SUPPRESSED:
            continue
        mine = [c for c in cells if c["URN"] == urn]
        hidden = len([k for k in real if k[0] == urn]) - sum(c["count"] != SUPPRESSED for c in mine)
        assert hidden != 1, urn


def test_same_cells_hidden_whatever_the_column_order_or_measure():
    a = keyed(answer(["URN", "Ethnicity"], FSM, SNAPSHOT), ["URN", "Ethnicity"])
    b = keyed(answer(["Ethnicity", "URN"], FSM, SNAPSHOT), ["URN", "Ethnicity"])
    assert a == b
    # totals do not depend on the measure, so two measures cannot be played against each other
    c = keyed(answer(["URN", "Ethnicity"], IN_CARE, SNAPSHOT), ["URN", "Ethnicity"])
    assert {k: v["total"] for k, v in a.items()} == {k: v["total"] for k, v in c.items()}


def test_released_numbers_are_the_plain_answer_rounded():
    for group_by, measure, where in SWEEP:
        plain = keyed(aggregate(CENSUS, group_by, measure, where), group_by)
        for key, row in keyed(answer(group_by, measure, where), group_by).items():
            for field in ("total", "count"):
                if row[field] != SUPPRESSED:
                    assert row[field] % 5 == 0
                    assert abs(row[field] - plain[key][field]) <= 2


def test_differencing_all_censuses_against_the_snapshots_is_blurred_by_rounding():
    """All censuses minus the ten other snapshots: each released number is up to 2 off, so the difference is not the
    hidden cell. Shown on Ironbridge (SCH09) FSM, whose summer 2021/22 count is hidden."""
    snapshots = sorted({(r["AcademicYear"], r["CensusTerm"]) for r in ROWS})
    whole = keyed(answer(["URN"], FSM), ["URN"])
    released, unknown = 0, []
    for year, term in snapshots:
        where = {"AcademicYear": year, "CensusTerm": term}
        row = keyed(answer(["URN"], FSM, where), ["URN"]).get(("SCH09",))
        if row is None or row["count"] == SUPPRESSED:
            unknown.append(where)
        else:
            released += row["count"]
    assert len(unknown) == 1  # the attack applies...
    estimate = whole[("SCH09",)]["count"] - released
    actual = keyed(aggregate(CENSUS, ["URN"], FSM, unknown[0]), ["URN"])[("SCH09",)]["count"]
    assert actual < MIN_COUNT
    assert estimate != actual  # ...but it does not land
    assert len(snapshots) * 2 >= MIN_COUNT  # the rounding error can reach the whole hidden range


# ---------------------------------------------------------------- red team: what must never be asked


@pytest.mark.parametrize(
    "arguments",
    [
        counts(["Psuedo ID"]),
        counts(["URN"], measure="Psuedo ID"),
        {"table": "display_names", "group_by": ["DisplayName"], "measure": "Gender"},
        {"table": "personal_data_deprivation", "group_by": ["DeprivationScore"], "measure": "DeprivationDecile"},
        counts(["date_of_birth"]),
        counts(["Postcode"]),
        counts(["pupil_id"]),
    ],
)
def test_identifying_columns_are_refused(issue, forwarded, arguments):
    scope = [{"server": "pupil-data", "tools": ["aggregate"]}]
    assert reason(issue(scope=scope)(**arguments)) == (403, "AGGREGATE_DISCLOSIVE")
    assert forwarded == []


def test_ordinary_columns_are_not_mistaken_for_identifiers():
    census_columns = ROWS[0].keys() - {"Psuedo ID"}
    assert [c for c in census_columns if disclosure.identifying(c)] == []


@pytest.mark.parametrize(
    "arguments",
    [
        {"table": CENSUS, "group_by": "URN", "measure": IN_CARE},
        {"table": CENSUS, "group_by": [1], "measure": IN_CARE},
        {"table": CENSUS, "group_by": [["URN"]], "measure": IN_CARE},
        {"table": CENSUS, "group_by": None, "measure": IN_CARE},
        {"table": CENSUS, "group_by": {"URN": 1}, "measure": IN_CARE},
        {"table": CENSUS, "measure": IN_CARE},
        {"table": CENSUS, "group_by": ["URN", "URN"], "measure": IN_CARE},
        {"table": CENSUS, "group_by": ["URN"], "measure": 5},
        {"table": CENSUS, "group_by": ["URN"], "measure": [IN_CARE]},
        {"table": None, "group_by": ["URN"], "measure": IN_CARE},
        {"table": CENSUS, "group_by": ["URN"], "measure": IN_CARE, "where": "AcademicYear=2023/24"},
        {"table": CENSUS, "group_by": ["URN"], "measure": IN_CARE, "where": [SNAPSHOT]},
        {
            "table": CENSUS,
            "group_by": ["URN"],
            "measure": IN_CARE,
            "where": {"AcademicYear": 2023, "CensusTerm": "SPR"},
        },
        {"table": CENSUS, "group_by": ["URN"], "measure": IN_CARE, "where": {**SNAPSHOT, "CensusTerm": None}},
        {"table": CENSUS, "group_by": ["URN"], "measure": IN_CARE, "where": {"AcademicYear": {"$ne": "x"}}},
        {"table": CENSUS, "group_by": ["URN"], "measure": IN_CARE, "limit": 5},
    ],
)
def test_malformed_aggregate_is_denied_not_500(issue, forwarded, arguments):
    scope = [{"server": "pupil-data", "tools": ["aggregate"]}]
    r = issue(scope=scope)(**arguments)
    assert reason(r) == (403, "AGGREGATE_MALFORMED"), r.text
    assert forwarded == []


def test_odd_upstream_result_is_withheld(issue, monkeypatch):
    for odd in (
        [{"URN": "SCH01", "total": 50, "count": 1}],
        {"rows": []},
        [{"URN": "S", "Psuedo ID": "P1", "total": -1, "count": 0}],
    ):

        async def upstream(_target, _body, odd=odd):
            return True, odd

        monkeypatch.setattr(main, "call_upstream", upstream)
        r = issue()(**counts(["URN"]))
        assert reason(r) == (403, "AGGREGATE_UNCHECKABLE")
        assert "result" not in r.json()


# ---------------------------------------------------------------- who sets k


def test_secondary_suppression_on_a_small_table():
    # A-X is small. Hiding it alone would let row A's margin give it back, so a partner goes in each row and column
    # until every school and every group hides none or at least two. Only A-Z survives.
    cells = [("A", "X", 30, 3), ("A", "Y", 30, 15), ("A", "Z", 40, 20), ("B", "Y", 30, 12), ("B", "Z", 30, 14)]
    cells += [("C", "Y", 30, 11), ("C", "Z", 30, 13)]
    rows = []
    for urn, eth, n, yes in cells:
        rows += [
            {"URN": urn, "E": eth, "Psuedo ID": f"{urn}{eth}{i}", "total": 1, "count": int(i < yes)} for i in range(n)
        ]
    out = keyed(protect(counts(["URN", "E"]), rows, Policy())[0], ["URN", "E"])
    assert {k for k, v in out.items() if v["count"] != SUPPRESSED} == {("A", "Z")}
    assert out[("A", "Z")]["count"] == 20
    assert {v["total"] for v in out.values()} == {30, 40}  # every total is large, none hidden


@pytest.mark.parametrize(
    ("claim", "k", "base"),
    [({}, 10, 5), ({"min_count": 20}, 20, 5), ({"min_count": 3, "round_to": 1}, 10, 5), ({"round_to": 10}, 10, 10)],
)
def test_a_mandate_may_raise_k_never_lower_it(issue, claim, k, base):
    r = issue(extra={"disclosure": claim})(**counts(["URN"], measure=FSM, where=SNAPSHOT))
    assert r.status_code == 200
    assert (r.json()["disclosure"]["min_count"], r.json()["disclosure"]["round_to"]) == (k, base)
    real = truth(["URN"], FSM, SNAPSHOT)
    for row in r.json()["result"]:
        if row["count"] != SUPPRESSED:
            assert real[(row["URN"],)]["with"] >= k
            assert row["count"] % base == 0


@pytest.mark.parametrize(
    "claim",
    [None, 10, "10", [], {"k": 10}, {"min_count": 0}, {"min_count": True}, {"min_count": 10.0}, {"round_to": -5}],
)
def test_malformed_disclosure_claim_denies_every_call(issue, claim):
    scope = [*COUNTS_SCOPE, *cli.DEFAULT_SCOPE]
    call = issue(scope=scope, extra={"disclosure": claim})
    assert reason(call(**counts(["URN"]))) == (403, "DISCLOSURE_INVALID")
    assert reason(call("search", query=ev.PUPIL, urn="SCH01")) == (403, "DISCLOSURE_INVALID")


def test_budgeted_mandate_still_cannot_aggregate(issue):
    r = issue(extra={"budget": {"pupils": 40}})(**counts(["URN"]))
    assert reason(r) == (403, "BUDGET_QUERY")


def test_audit_entry_records_the_suppression(gw, issue):
    _, state = gw
    issue()(**counts(["URN", "Ethnicity"], where=SNAPSHOT))
    issue()(**counts(["URN", "Ethnicity", "Gender"]))
    allowed, refused = audit.read_entries(state / "audit.jsonl")
    assert allowed["released"]["pupils"] == []
    assert allowed["released"]["suppressed"] > 0
    assert allowed["released"]["min_count"] == MIN_COUNT
    assert "suppressed" in allowed["decision"]["detail"]
    assert "numbers suppressed as too small" in audit.plain(allowed)
    assert refused["decision"]["reason_code"] == "AGGREGATE_DISCLOSIVE"
    assert "single out a pupil" in audit.plain(refused)
    assert audit.verify_chain(state / "audit.jsonl")["ok"]


def test_every_pair_of_census_columns_respects_k():
    """The whole space the policy allows on the census (two columns, all censuses), for the sensitive measure."""
    columns = sorted(ROWS[0].keys() - {"Psuedo ID"})
    for group_by in itertools.combinations(columns, 2):
        real = truth(list(group_by), IN_CARE)
        for row in answer(list(group_by), IN_CARE):
            cell = real[tuple(row[c] for c in group_by)]
            assert cell["pupils"] >= MIN_COUNT
            assert row["count"] == SUPPRESSED or min(cell["with"], cell["without"]) >= MIN_COUNT
