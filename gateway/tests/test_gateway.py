import asyncio
import base64
import csv
import json
import os
import time
from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient

from gateway import cli, main
from gateway import eval as ev
from gateway.lib import nonce_store
from gateway.lib.budget import parse_budget, pupil_ids
from gateway.lib.common import generate_keypair, priv_from_pem, priv_to_pem, sign_bytes
from gateway.lib.gateway_verify import Request, check_request
from gateway.lib.nonce_store import TS_WINDOW, NonceStore
from mcp_server.api.routes_mcp import mcp


@pytest.fixture
def gw(tmp_path, monkeypatch):
    state = tmp_path / "state"
    cli.main(["--state", str(state), "init"])
    cli.main(
        ["--state", str(state), "issue", "--agent-key", str(state / "agent.pem"), "-o", str(state / "mandate.jwt")]
    )
    monkeypatch.setattr(main, "STATE_DIR", state)
    monkeypatch.setitem(main.MCP_SERVERS, "pupil-data", mcp)  # in-process upstream, no network
    agent_priv = priv_from_pem((state / "agent.pem").read_bytes())
    mandate = (state / "mandate.jwt").read_text()

    def call(client, tool, body=None, **arguments):
        body = body or cli.sign_request(
            agent_priv, server="pupil-data", tool=tool, arguments=arguments, mandate=mandate
        )
        return client.post("/tools/call", json=body), body

    with TestClient(main.app) as client:
        yield client, call, state


def test_allow_deny_replay_revoke(gw):
    client, call, state = gw

    r, body = call(client, "search", query=ev.PUPIL, urn="SCH01")
    assert r.status_code == 200, r.text
    assert r.json()["decision"]["decision"] == "ALLOW"
    assert {row["URN"] for row in r.json()["result"]} == {"SCH01"}

    # get is limited to the two files with no pupil data, so the names file is refused
    r, _ = call(client, "get", path="synthetic/synthetic_display_names.csv")
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CONSTRAINT_VIOLATED")

    r, _ = call(client, "search", body=body)  # replay of the first signed request
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "POP_FAILED")

    cli.main(["--state", str(state), "revoke", "--idx", "0"])
    r, _ = call(client, "search", query=ev.PUPIL, urn="SCH01")
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "REVOKED")


def test_bulk_export_is_denied(gw):
    client, call, _ = gw
    for arguments in (
        {"query": ""},
        {"query": "  "},
        {"query": "SPR", "limit": 101},
        {"query": "SPR", "limit": "5"},
        {"query": "SPR", "limit": -1},
        {"query": "SPR", "limit": True},
    ):
        r, _ = call(client, "search", urn="SCH01", **arguments)
        assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "TOO_MUCH"), arguments
    r, _ = call(client, "search", urn="SCH01", query="SPR", limit=100)
    assert r.status_code == 200, r.text


def test_path_spellings(gw):
    client, call, _ = gw
    for path in ("./" + ev.SCHOOLS, ev.SCHOOLS.replace("/", "//"), "synthetic/x/../synthetic_schools.csv/"):
        r, _ = call(client, "get", path=path)
        assert r.status_code == 200, path
        assert r.json()["result"][0]["URN"] == "SCH01"
    for path in (
        "synthetic/../synthetic/synthetic_display_names.csv",
        "/" + ev.SCHOOLS,
        "../data/" + ev.SCHOOLS,
        ev.SCHOOLS + "/../synthetic_display_names.csv",
        ev.SCHOOLS.upper(),
        ev.SCHOOLS + "\x00",
        "",
        123,
        [ev.SCHOOLS],
    ):
        r, _ = call(client, "get", path=path)
        assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CONSTRAINT_VIOLATED"), path


def test_any_scope_entry_may_allow_but_entries_do_not_mix():
    def check(tool="t", **arguments):
        req = Request("s", tool, arguments, mandate="", nonce="", ts=0, sig="")
        scope = [
            {"server": "s", "tools": ["t"], "constraints": {"urn": ["SCH01"], "path": ["a"]}},
            {"server": "s", "tools": ["t"], "constraints": {"urn": ["SCH02"], "path": ["b"]}},
        ]
        return check_request(req, scope, deny=[], step_up_patterns=[])[:2]

    assert check(urn="SCH01", path="a") == ("ALLOW", "IN_SCOPE")
    assert check(urn="SCH02", path="b") == ("ALLOW", "IN_SCOPE")  # the second entry is tried
    assert check(urn="SCH01", path="b") == ("DENY", "CONSTRAINT_VIOLATED")  # urn from one, path from the other
    assert check(urn="SCH03", path="a") == ("DENY", "CONSTRAINT_VIOLATED")
    assert check(path="a") == ("DENY", "CONSTRAINT_MISSING")
    assert check(urn="SCH02", path="b", limit=101) == ("DENY", "TOO_MUCH")
    assert check(tool="other", urn="SCH01", path="a") == ("DENY", "OUT_OF_SCOPE")


def test_issue_warns_when_entries_for_one_tool_constrain_different_arguments():
    def entry(**constraints):
        return {"server": "pupil-data", "tools": ["pupil"], "constraints": constraints}

    assert cli.scope_warnings(cli.DEFAULT_SCOPE) == []
    assert cli.scope_warnings(ev.TWO_SCHOOLS_SCOPE) == []  # same argument in both entries: a plain second grant
    (warning,) = cli.scope_warnings([entry(urn=["SCH01"]), entry(pupil_id=["P0011"])])
    assert "pupil-data.pupil" in warning
    assert len(cli.scope_warnings([entry(urn=["SCH01"]), entry()])) == 1  # an unconstrained entry beside a narrow one


def test_tampered_mandate_is_denied(gw):
    client, call, state = gw
    mandate = (state / "mandate.jwt").read_text()
    header, payload, sig = mandate.split(".")
    claims = json.loads(cli.b64u_decode(payload))
    claims["scope"][0]["constraints"]["urn"] = ["SCH01", "SCH02"]
    forged = ".".join([header, cli.b64u(json.dumps(claims).encode()), sig])
    body = cli.sign_request(
        priv_from_pem((state / "agent.pem").read_bytes()),
        server="pupil-data",
        tool="search",
        arguments={"query": "SPR", "urn": "SCH02"},
        mandate=forged,
    )
    r, _ = call(client, "search", body=body)
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "SIG_INVALID")


def test_demo_routes_are_off_unless_gateway_demo_is_set(gw):
    client, _, _ = gw
    assert client.post("/demo/mandate", json={"urn": "SCH02"}).status_code == 404
    assert client.post("/demo/revoke", json={"idx": 0}).status_code == 404
    assert client.post("/demo/call", json={"tool": "search", "arguments": {}}).status_code == 404


def test_demo_walkthrough(gw, monkeypatch):
    monkeypatch.setattr(main, "DEMO", True)
    client, _, _ = gw
    m = client.post("/demo/mandate", json={"urn": "SCH01"}).json()
    assert m["header"]["typ"] == "mandate+jwt"
    assert m["claims"]["scope"][0]["constraints"] == {"urn": ["SCH01"]}

    issuer = client.get("/demo/issuer").json()["issuer"]
    assert (issuer["iss"], issuer["kid"]) == (m["claims"]["iss"], m["header"]["kid"])
    assert "d" not in issuer["public_jwk"]  # the private half never leaves the state dir

    r = client.post("/demo/call", json={"tool": "search", "arguments": {"query": "SPR", "urn": "SCH01"}}).json()
    assert (r["status"], r["response"]["decision"]["decision"]) == (200, "ALLOW")

    t = client.post("/demo/revoke", json={"idx": m["status_idx"]}).json()
    assert t["status_list"]["revoked"] == [m["status_idx"]]
    r = client.post("/demo/call", json={"tool": "search", "arguments": {"query": "SPR", "urn": "SCH01"}}).json()
    assert (r["status"], r["response"]["decision"]["reason_code"]) == (403, "REVOKED")


def test_describe_and_issue_to_public_jwk(gw, tmp_path, capsys):
    client, call, state = gw

    desc = client.get("/describe").json()
    assert [t["name"] for t in desc["servers"]["pupil-data"]] == [
        "search",
        "get",
        "aggregate",
        "classification",
        "roster",
        "pupil",
        "draft",
        "write",
    ]
    ex = desc["signing"]["example"]
    assert Request(**ex["request"]).signing_input().decode() == ex["signing_input"]

    # team runs keygen and sends only the public JWK; issuer never sees the private key
    team_key = tmp_path / "team.pem"
    cli.main(["keygen", "-o", str(team_key)])
    (tmp_path / "team.jwk").write_text(capsys.readouterr().out)
    cli.main(["--state", str(state), "issue", "--agent-key", str(tmp_path / "team.jwk"), "-o", str(tmp_path / "m.jwt")])
    body = cli.sign_request(
        priv_from_pem(team_key.read_bytes()),
        server="pupil-data",
        tool="search",
        arguments={"query": "SPR", "urn": "SCH01"},
        mandate=(tmp_path / "m.jwt").read_text(),
    )
    r, _ = call(client, "search", body=body)
    assert (r.status_code, r.json()["decision"]["decision"]) == (200, "ALLOW")


def test_issue_with_claims_of_your_own(gw, tmp_path, capsys):
    client, call, state = gw
    out = tmp_path / "m.jwt"
    issue = ["--state", str(state), "issue", "--agent-key", str(state / "agent.pem"), "-o", str(out)]

    cli.main([*issue, "--claims", '{"clearance": 2}'])
    capsys.readouterr()
    cli.main(["decode", str(out)])
    assert json.loads(capsys.readouterr().out)["clearance"] == 2

    # the starter gateway ignores a claim it does not read, so the mandate still works
    body = cli.sign_request(
        priv_from_pem((state / "agent.pem").read_bytes()),
        server="pupil-data",
        tool="search",
        arguments={"query": "SPR", "urn": "SCH01"},
        mandate=out.read_text(),
    )
    r, _ = call(client, "search", body=body)
    assert (r.status_code, r.json()["decision"]["decision"]) == (200, "ALLOW")

    with pytest.raises(ValueError, match="scope"):
        cli.main([*issue, "--claims", '{"scope": []}'])


def test_eval_set_passes_against_template_gateway(gw, tmp_path):
    client, _, state = gw
    ev.main(["build", "--state", str(state), "-o", str(tmp_path / "pack")])

    def post(body):
        r = client.post("/tools/call", json=body)
        return r.status_code, r.json()

    results = ev.run_cases(tmp_path / "pack", post)
    # questions 3 to 5 are the teams' build work, so only the starter's questions 0 to 2 must pass
    assert [line for ok, line in results if not ok and line[:2] in {"Q0", "Q1", "Q2"}] == []
    assert len(results) == len(ev.VALID) + len(ev.INVALID) + len(ev.BUILD)


# ---------------------------------------------------------------- question 11: run budgets

ROOT = Path(__file__).resolve().parents[2]
FEATURE_Q11 = ROOT / "day_2_attack" / "feature_q11"
ELMWOOD_SCOPE = json.loads((FEATURE_Q11 / "feature_scope.json").read_text())
ELMWOOD = "SCH05"
ELMWOOD_Y11 = 38  # spring 2023/24 roster
ROSTER = {"urn": ELMWOOD, "year_group": 11, "academic_year": "2023/24", "term": "SPR"}


def elmwood_pupils() -> set[str]:
    """Every pupil ever on Elmwood's census (121), read from the data the MCP server serves."""
    with (ROOT / "mcp_server/data/synthetic/synthetic_personal_data_school_census.csv").open(newline="") as f:
        return {row["Psuedo ID"] for row in csv.DictReader(f) if row["URN"] == ELMWOOD}


@pytest.fixture
def issue(gw):
    """issue(budget, scope=ELMWOOD_SCOPE) -> call(tool, client=..., **arguments) -> response, under a new mandate."""
    client, _, state = gw
    agent_priv = priv_from_pem((state / "agent.pem").read_bytes())

    def issue(budget=None, scope=ELMWOOD_SCOPE, extra=None, principal="officer:jsmith"):
        extra = extra if extra is not None else ({} if budget is None else {"budget": budget})
        token, _ = cli.issue_mandate(
            state,
            agent_priv.public_key(),
            scope=scope,
            deny=cli.DEFAULT_DENY,
            ttl=600,
            purpose="Elmwood Y11 free school meals",
            principal=principal,
            org=f"school:{ELMWOOD}",
            extra=extra,
        )

        def call(tool, client=client, **arguments):
            body = cli.sign_request(agent_priv, server="pupil-data", tool=tool, arguments=arguments, mandate=token)
            return client.post("/tools/call", json=body)

        return call

    return issue


@pytest.fixture
def forwarded(monkeypatch):
    """Tool names that reached the MCP server, in order."""
    seen = []
    upstream = main.call_upstream

    async def counting(target, body):
        seen.append(body.tool)
        return await upstream(target, body)

    monkeypatch.setattr(main, "call_upstream", counting)
    return seen


def reason(r):
    return r.status_code, r.json()["decision"]["reason_code"]


def used(r):
    b = r.json()["budget"]
    return b["pupils_used"], b["calls_used"]


def test_feature_mandate_files():
    claims = json.loads((FEATURE_Q11 / "feature_claims.json").read_text())
    b = parse_budget({"iss": "i", "jti": "j", "delegator": {"principal": "attacker:team"}, **claims})
    assert (b.pupils, b.calls, b.key) == (40, 100, ("i", "attacker:team", "j"))
    assert "id" not in claims["budget"]  # each attacking team gets its own budget
    roster = next(e for e in ELMWOOD_SCOPE if e["tools"] == ["roster"])
    assert roster["constraints"] == {k: [str(v)] for k, v in ROSTER.items()}


def test_no_budget_claim_is_unlimited_as_before(gw, issue):
    _, _, state = gw
    call = issue(budget=None)
    for query in ("SPR", "AUT", "2022/23", "2021/22", "2020/21"):  # well over 40 distinct Elmwood pupils
        r = call("search", query=query, urn=ELMWOOD)
        assert r.status_code == 200, r.text
        assert "budget" not in r.json()
    assert not (state / "budget_ledger.json").exists()


def test_elmwood_run_fits_and_the_gateway_stops_it_when_full(issue, forwarded):
    call = issue(budget={"pupils": 40, "calls": 100})

    r = call("roster", **ROSTER)
    assert r.status_code == 200, r.text
    cohort = [row["Psuedo ID"] for row in r.json()["result"]]
    assert len(cohort) == ELMWOOD_Y11
    assert r.json()["budget"] == {"pupils_used": 38, "pupils_limit": 40, "calls_used": 1, "calls_limit": 100}

    for pupil in cohort:  # "go through them one at a time": every pupil already counted, so free
        r = call("search", query=pupil, urn=ELMWOOD)
        assert r.status_code == 200, r.text
        assert {row["Psuedo ID"] for row in r.json()["result"]} == {pupil}
        assert {row["URN"] for row in r.json()["result"]} == {ELMWOOD}
    assert used(call("roster", **ROSTER)) == (38, 40)  # the same roster again: free

    outside = sorted(elmwood_pupils() - set(cohort))
    for pupil in outside[:2]:  # the slack
        assert call("search", query=pupil, urn=ELMWOOD).status_code == 200
    assert len(forwarded) == 42

    r = call("search", query=outside[2], urn=ELMWOOD)  # a 41st pupil: refused on the arguments alone
    assert reason(r) == (403, "BUDGET_EXHAUSTED")
    assert used(r) == (40, 42)
    assert len(forwarded) == 42  # not forwarded, not counted

    r = call("roster", **ROSTER)  # full: a tool that lists pupils is refused whatever it would hold
    assert reason(r) == (403, "BUDGET_EXHAUSTED")
    r = call("search", query=cohort[0], urn=ELMWOOD)  # full: pupils already counted are still free
    assert r.status_code == 200
    assert used(r) == (40, 43)


@pytest.mark.parametrize(
    "query",
    [
        "2023/24",
        "P0542,M,WHIT,1_ENG,0,1",  # red team: tested a row's contents through withheld vs empty
        "P0542,",
        "p0542",
        " P0542",
        "P0542 ",
        "P0542\n",
        "P054",
        "P05x2",
        "P\uff10\uff15\uff14\uff12",  # full-width digits match \d but are not an ID
        "",
        5420,
        ["P0542"],
        None,
    ],
)
def test_budgeted_search_takes_one_pupil_id_only(issue, forwarded, query):
    call = issue(budget={"pupils": 40})
    status, code = reason(call("search", query=query, urn=ELMWOOD))
    assert status == 403
    assert code in {"BUDGET_QUERY", "TOO_MUCH"}  # "" is already refused by the starter's empty-query rule
    assert forwarded == []


def test_budgeted_mandate_cannot_use_aggregate(issue, forwarded):
    scope = [{"server": "pupil-data", "tools": ["aggregate"], "constraints": {"measure": ["FSMeligible"]}}]
    counts = {"table": "personal_data_school_census", "group_by": ["URN"], "measure": "FSMeligible"}
    assert issue(budget=None, scope=scope)("aggregate", **counts).status_code == 200  # as before without a budget
    r = issue(budget={"pupils": 40}, scope=scope)("aggregate", **counts)
    assert reason(r) == (403, "BUDGET_QUERY")
    assert forwarded == ["aggregate"]


def test_named_pupils_are_charged_found_or_not(issue, forwarded, monkeypatch):
    call = issue(budget={"pupils": 2})
    r = call("search", query=ev.PUPIL, urn=ELMWOOD)  # an Ashfield pupil: nothing at Elmwood, still one pupil
    assert (r.status_code, r.json()["result"]) == (200, [])
    assert used(r) == (1, 1)

    async def boom(_target, body):
        forwarded.append(body.tool)
        return False, "upstream failed"

    monkeypatch.setattr(main, "call_upstream", boom)
    r = call("search", query="P0005", urn=ELMWOOD)  # charged and counted before forwarding: an error still costs
    assert r.status_code == 502
    assert used(r) == (2, 2)
    assert reason(call("search", query="P0006", urn=ELMWOOD)) == (403, "BUDGET_EXHAUSTED")
    assert forwarded == ["search", "search"]


def test_listed_result_over_budget_is_withheld_and_not_charged(issue):
    call = issue(budget={"pupils": 30})
    r = call("roster", **ROSTER)  # 38 pupils: the backstop withholds all of them
    assert reason(r) == (403, "BUDGET_EXHAUSTED")
    assert "result" not in r.json()
    assert "38" not in r.json()["decision"]["detail"]  # no count oracle
    assert used(r) == (0, 1)
    r = call("search", query="P1022", urn=ELMWOOD)  # nothing from the roster was charged
    assert r.status_code == 200
    assert used(r) == (1, 2)


def test_calls_cap_is_refused_before_forwarding(issue, forwarded):
    call = issue(budget={"pupils": 40, "calls": 2})
    assert call("search", query="P1022", urn=ELMWOOD).status_code == 200
    assert call("search", query="P1022", urn=ELMWOOD).status_code == 200
    r = call("search", query="P1022", urn=ELMWOOD)
    assert reason(r) == (403, "BUDGET_EXHAUSTED")
    assert used(r) == (1, 2)
    assert forwarded == ["search", "search"]


@pytest.mark.parametrize(
    "budget",
    [
        True,
        40,
        [40],
        {},  # pupils missing
        {"calls": 10},
        {"pupils": True},
        {"pupils": -1},
        {"pupils": "40"},
        {"pupils": 40.0},
        {"pupils": None},
        {"pupils": 40, "calls": False},
        {"pupils": 40, "calls": -1},
        {"pupils": 40, "id": ""},
        {"pupils": 40, "id": 7},
        {"pupils": 40, "rows": 100},  # unknown key: refused, not ignored
    ],
)
def test_malformed_budget_is_denied(issue, budget):
    call = issue(extra={"budget": budget})
    assert reason(call("roster", **ROSTER)) == (403, "BUDGET_INVALID")


def test_budget_without_a_principal_is_invalid():
    with pytest.raises(ValueError, match="principal"):
        parse_budget({"iss": "i", "jti": "j", "budget": {"pupils": 1}})


def test_budget_ledger_key_is_issuer_principal_and_id(issue):
    parent = issue(budget={"pupils": 40, "id": "elmwood-y11-fsm"})
    child = issue(budget={"pupils": 40, "id": "elmwood-y11-fsm"})  # same person, same id: one budget
    other_person = issue(budget={"pupils": 40, "id": "elmwood-y11-fsm"}, principal="attacker:team-b")
    other_job = issue(budget={"pupils": 40})  # no id: its own jti

    assert used(parent("roster", **ROSTER)) == (38, 1)
    assert used(child("roster", **ROSTER)) == (38, 2)
    assert used(child("search", query="P0001", urn=ELMWOOD)) == (39, 3)
    assert used(parent("search", query="P0002", urn=ELMWOOD)) == (40, 4)
    assert reason(child("search", query="P0003", urn=ELMWOOD)) == (403, "BUDGET_EXHAUSTED")

    assert used(other_person("search", query="P0003", urn=ELMWOOD)) == (1, 1)
    assert used(other_job("search", query="P0003", urn=ELMWOOD)) == (1, 1)

    claims = {"jti": "urn:uuid:1", "delegator": {"principal": "p"}, "budget": {"pupils": 1, "id": "job"}}
    a = parse_budget({**claims, "iss": "https://a.example"})
    b = parse_budget({**claims, "iss": "https://b.example"})
    assert a.key != b.key  # another issuer's "job" is another budget


def test_budget_survives_a_gateway_restart(gw, issue):
    _, _, state = gw
    call = issue(budget={"pupils": 40, "calls": 100})
    call("roster", **ROSTER)

    saved = json.loads((state / "budget_ledger.json").read_text())["budgets"]
    assert [(b["principal"], len(b["pupils"]), b["calls"]) for b in saved] == [("officer:jsmith", 38, 1)]

    with TestClient(main.app) as restarted:  # lifespan runs again: state is reloaded from disk
        assert used(call("search", client=restarted, query="P0001", urn=ELMWOOD)) == (39, 2)


@pytest.mark.parametrize(
    "content",
    [
        "{not json",
        "[]",
        '{"budgets": [{"iss": "i", "principal": "p", "id": "j", "calls": "1", "pupils": []}]}',
        '{"budgets": [{"iss": "i", "principal": "p", "id": "j", "calls": 1, "pupils": "P0001"}]}',
    ],
)
def test_corrupt_ledger_fails_closed(gw, issue, content):
    _, _, state = gw
    budgeted, plain = issue(budget={"pupils": 40}), issue(budget=None)
    (state / "budget_ledger.json").write_text(content)
    with TestClient(main.app) as restarted:
        r = budgeted("search", client=restarted, query="P1022", urn=ELMWOOD)
        assert reason(r) == (403, "BUDGET_UNAVAILABLE")
        assert plain("search", client=restarted, query="P1022", urn=ELMWOOD).status_code == 200  # no budget: as before
    assert (state / "budget_ledger.json").read_text() == content  # not reset


@pytest.mark.skipif(os.geteuid() == 0, reason="root writes to read-only dirs")
def test_unwritable_state_dir_fails_the_healthcheck_not_the_gateway(gw, issue, forwarded):
    client, _, state = gw
    budgeted, plain = issue(budget={"pupils": 40}), issue(budget=None)
    assert client.get("/healthcheck").json() == {"status": "ok"}
    state.chmod(0o555)
    try:
        with TestClient(main.app) as restarted:
            r = restarted.get("/healthcheck")
            assert r.status_code == 503
            assert "not writable" in r.json()["reason"]
            # nonces cannot be recorded, so a replay could not be stopped: every call is refused, budget or not
            assert reason(plain("search", client=restarted, query="P1022", urn=ELMWOOD)) == (403, "NONCE_UNAVAILABLE")
            r = budgeted("search", client=restarted, query="P1022", urn=ELMWOOD)
            assert reason(r) == (403, "NONCE_UNAVAILABLE")
    finally:
        state.chmod(0o755)
    assert forwarded == []
    assert not (state / "budget_ledger.json").exists()


@pytest.mark.usefixtures("gw")
def test_ledger_that_cannot_be_saved_fails_closed(issue, forwarded, tmp_path):
    call = issue(budget={"pupils": 40})
    main.state["ledger"].path = tmp_path / "missing-dir" / "budget_ledger.json"
    assert reason(call("search", query="P1022", urn=ELMWOOD)) == (403, "BUDGET_UNAVAILABLE")
    assert reason(call("search", query="P1022", urn=ELMWOOD)) == (403, "BUDGET_UNAVAILABLE")
    assert forwarded == []


def test_concurrent_calls_cannot_both_take_the_last_call(gw):
    _, _, state = gw
    agent_priv = priv_from_pem((state / "agent.pem").read_bytes())
    token, _ = cli.issue_mandate(
        state,
        agent_priv.public_key(),
        scope=ELMWOOD_SCOPE,
        deny=[],
        ttl=600,
        purpose="q11",
        principal="officer:jsmith",
        org="school:SCH05",
        extra={"budget": {"pupils": 40, "calls": 1}},
    )

    async def both():
        bodies = [
            main.CallBody(
                **cli.sign_request(
                    agent_priv,
                    server="pupil-data",
                    tool="search",
                    arguments={"query": q, "urn": ELMWOOD},
                    mandate=token,
                )
            )
            for q in ("P1022", "P1023")
        ]
        return await asyncio.gather(*(main.tools_call(b) for b in bodies))

    statuses = sorted(getattr(r, "status_code", 200) for r in asyncio.run(both()))
    assert statuses == [200, 403]


def test_pupil_ids_are_found_anywhere_in_a_result():
    result = [
        {"Psuedo ID": "P0004", "note": "with P0005P0006 and p0007"},
        {"P0008": 1, "nested": [("P0009",), {"x": {"P0010"}}]},
        {"count": 1234, "total": 5, "ok": True, "none": None, "school": "SCH05"},
    ]
    assert pupil_ids(result) == {f"P{n:04d}" for n in range(4, 11)}
    assert pupil_ids("no pupils, SCH01, 2023/24") == set()


# ---------------------------------------------------------------- malformed requests are denied, never a 500


def resign(state, mandate: str, **changes) -> str:
    """The mandate with `changes` to its claims (None deletes), signed again with the real issuer key."""
    header = jwt.get_unverified_header(mandate)
    claims = jwt.decode(mandate, options={"verify_signature": False})
    claims.update(changes)
    claims = {k: v for k, v in claims.items() if v is not None}
    key = priv_to_pem(priv_from_pem((state / "issuer_key.pem").read_bytes()))
    return jwt.encode(claims, key, algorithm="EdDSA", headers={"typ": header["typ"], "kid": header["kid"]})


def raw_jwt(header: dict, claims: dict, priv) -> str:
    """A JWT signed by hand, for claims PyJWT refuses to encode (an iss that is a list)."""

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    signing_input = f"{b64(json.dumps({'alg': 'EdDSA', **header}).encode())}.{b64(json.dumps(claims).encode())}"
    return f"{signing_input}.{b64(priv.sign(signing_input.encode()))}"


def test_malformed_mandates_are_denied(gw):
    client, _, state = gw
    agent_priv = priv_from_pem((state / "agent.pem").read_bytes())
    mandate = (state / "mandate.jwt").read_text()
    unsigned = {"typ": "mandate+jwt", "kid": "issuer-2026-11"}
    cases = {
        "x": "MANDATE_MALFORMED",
        "a.b.c": "MANDATE_MALFORMED",
        "": "MANDATE_MALFORMED",
        raw_jwt(unsigned, {"jti": "j"}, agent_priv): "MANDATE_MALFORMED",  # no iss
        raw_jwt(unsigned, {"iss": ["a"]}, agent_priv): "MANDATE_MALFORMED",
        raw_jwt({**unsigned, "kid": ["k"]}, {"iss": "a"}, agent_priv): "MANDATE_MALFORMED",
        resign(state, mandate, exp="never"): "MANDATE_MALFORMED",
        resign(state, mandate, status=None): "MANDATE_MALFORMED",
        resign(state, mandate, status={"status_list": {"uri": "u", "idx": "0"}}): "MANDATE_MALFORMED",
        resign(state, mandate, status={"status_list": {"uri": ["u"], "idx": 0}}): "MANDATE_MALFORMED",
        resign(state, mandate, status={"status_list": {"uri": "u", "idx": -1}}): "MANDATE_MALFORMED",
        resign(state, mandate, cnf={"jwk": "x"}): "MANDATE_MALFORMED",
        resign(state, mandate, cnf={"jwk": {"kty": "OKP", "crv": "Ed25519", "x": "short"}}): "MANDATE_MALFORMED",
        resign(state, mandate, scope={"server": "pupil-data"}): "MANDATE_MALFORMED",
        resign(state, mandate, scope=[{"server": "pupil-data", "tools": "search"}]): "MANDATE_MALFORMED",
        resign(state, mandate, deny="*.write"): "MANDATE_MALFORMED",
        resign(state, mandate, agent_id=None): "MANDATE_MALFORMED",
    }
    for token, code in cases.items():
        body = cli.sign_request(
            agent_priv, server="pupil-data", tool="search", arguments={"query": "SPR", "urn": "SCH01"}, mandate=token
        )
        r = client.post("/tools/call", json=body)
        assert reason(r) == (403, code), token
    # the status idx is the mandate's own: a huge one is read as "list unavailable", not a crash
    token = resign(state, mandate, status={"status_list": {"uri": main.state["status_uri"], "idx": 10**9}})
    body = cli.sign_request(agent_priv, server="pupil-data", tool="search", arguments={"query": "SPR"}, mandate=token)
    assert reason(client.post("/tools/call", json=body)) == (403, "STATUS_UNAVAILABLE")


def test_malformed_requests_are_denied(gw, monkeypatch):
    client, call, _ = gw
    _, body = call(client, "search", query="SPR", urn="SCH01")
    for ts in (10**400, -1, 2**41 + 1, "soon"):
        r = client.post("/tools/call", json={**body, "ts": ts})
        assert r.status_code == 422, ts

    def nested(depth):
        value = "SPR"
        for _ in range(depth):
            value = {"a": value}
        return value

    r, _ = call(client, "search", query=nested(8), urn="SCH01")  # arguments itself is the 9th level
    assert reason(r) == (403, "ARGS_TOO_LARGE")
    r, _ = call(client, "search", query="S" * 17_000, urn="SCH01")
    assert reason(r) == (403, "ARGS_TOO_LARGE")
    deep = '{"a":' * 5000 + "1" + "}" * 5000
    raw = json.dumps({**body, "arguments": {}}).replace('"arguments": {}', f'"arguments": {deep}')
    r = client.post("/tools/call", content=raw, headers={"content-type": "application/json"})
    assert r.status_code in {400, 403, 422}, r.text
    r = client.post(
        "/tools/call",
        content=json.dumps({**body, "mandate": "\ud800"}).encode(),
        headers={"content-type": "application/json"},
    )
    assert r.status_code in {400, 403, 422}, r.text

    async def broken(_target, _body):
        msg = "upstream exploded"
        raise RuntimeError(msg)

    monkeypatch.setattr(main, "call_upstream", broken)
    r, _ = call(client, "search", query="SPR", urn="SCH01")
    assert reason(r) == (400, "GATEWAY_ERROR")
    assert "exploded" not in r.text


# ---------------------------------------------------------------- replay after restart, and the forwarded path


def test_replay_after_a_restart_is_denied(gw):
    client, call, state = gw
    r, body = call(client, "search", query="P0004", urn="SCH01")
    assert r.status_code == 200
    assert reason(client.post("/tools/call", json=body)) == (403, "POP_FAILED")  # same process
    with TestClient(main.app) as restarted:  # lifespan reloads state: the nonce must come back from disk
        r = restarted.post("/tools/call", json=body)
        assert reason(r) == (403, "POP_FAILED")
        assert r.json()["decision"]["detail"] == "replayed nonce"
    lines = (state / "nonces.jsonl").read_text().splitlines()
    assert [json.loads(line)["nonce"] for line in lines] == [body["nonce"]]


def test_unsigned_request_cannot_burn_a_nonce(gw):
    client, _, state = gw
    agent_priv = priv_from_pem((state / "agent.pem").read_bytes())
    body = cli.sign_request(
        agent_priv,
        server="pupil-data",
        tool="search",
        arguments={"query": "P0004", "urn": "SCH01"},
        mandate=(state / "mandate.jwt").read_text(),
    )
    other_priv, _ = generate_keypair()
    forged = {**body, "sig": sign_bytes(other_priv, main.Request(**body).signing_input())}
    assert reason(client.post("/tools/call", json=forged)) == (403, "POP_FAILED")
    assert client.post("/tools/call", json=body).status_code == 200  # the real request, same nonce, still works


@pytest.mark.parametrize("nonce", ["", "n" * 129])
def test_nonce_length_is_bounded(gw, nonce):
    client, _, state = gw
    agent_priv = priv_from_pem((state / "agent.pem").read_bytes())
    body = cli.sign_request(
        agent_priv,
        server="pupil-data",
        tool="search",
        arguments={"query": "P0004", "urn": "SCH01"},
        mandate=(state / "mandate.jwt").read_text(),
    )
    body = {**body, "nonce": nonce}
    body["sig"] = sign_bytes(agent_priv, main.Request(**body).signing_input())  # validly signed, just too long
    r = client.post("/tools/call", json=body)
    assert reason(r) == (403, "POP_FAILED")
    assert "nonce" in r.json()["decision"]["detail"]
    assert not (state / "nonces.jsonl").exists()


def test_old_nonces_are_pruned_on_load(tmp_path):
    path = tmp_path / "nonces.jsonl"
    now = int(time.time())
    entries = [("old", now - TS_WINDOW - 1), ("edge", now - TS_WINDOW + 5), ("future", now + 200)]
    path.write_text("".join(json.dumps({"nonce": n, "ts": ts}) + "\n" for n, ts in entries))
    store = NonceStore.load(path)
    assert (store.error, store.seen("old"), store.seen("edge"), store.seen("future")) == (None, False, True, True)
    assert sorted(json.loads(line)["nonce"] for line in path.read_text().splitlines()) == ["edge", "future"]


def test_nonce_file_is_compacted_as_it_grows(tmp_path, monkeypatch):
    monkeypatch.setattr(nonce_store, "COMPACT_MIN_LINES", 10)
    path = tmp_path / "nonces.jsonl"
    store = NonceStore.load(path)
    now = int(time.time())
    for i in range(25):
        store.add(f"stale{i}", now - TS_WINDOW - 10)  # accepted earlier, now outside the window
    store.add("fresh", now)
    assert len(path.read_text().splitlines()) < 10
    assert store.seen("fresh")
    assert not store.seen("stale0")


@pytest.mark.parametrize(
    "content",
    ["{not json\n", '{"nonce": 1, "ts": 1}\n', '{"nonce": "n", "ts": "1"}\n', '{"nonce": "n"}\n', "[]\n"],
)
def test_corrupt_nonce_file_fails_closed(gw, content):
    _, call, state = gw
    (state / "nonces.jsonl").write_text(content)
    with TestClient(main.app) as restarted:
        r, _ = call(restarted, "search", query="P0004", urn="SCH01")
        assert reason(r) == (403, "NONCE_UNAVAILABLE")
        assert restarted.get("/healthcheck").status_code == 503
    assert (state / "nonces.jsonl").read_text() == content  # not reset


def test_nonce_file_that_cannot_be_saved_fails_closed(gw, tmp_path):
    client, call, _ = gw
    main.state["gateway"].nonces.path = tmp_path / "missing-dir" / "nonces.jsonl"
    for _ in range(2):
        r, _ = call(client, "search", query="P0004", urn="SCH01")
        assert reason(r) == (403, "NONCE_UNAVAILABLE")
    assert client.get("/healthcheck").status_code == 503


@pytest.mark.parametrize(
    "spelling",
    ["./synthetic/synthetic_schools.csv", "synthetic//synthetic_schools.csv", "synthetic/x/../synthetic_schools.csv"],
)
def test_the_checked_path_is_the_forwarded_path(gw, monkeypatch, spelling):
    client, call, _ = gw
    sent = []
    upstream = main.call_upstream

    async def recording(target, body):
        sent.append(body.arguments)
        return await upstream(target, body)

    monkeypatch.setattr(main, "call_upstream", recording)
    r, body = call(client, "get", path=spelling)
    assert r.status_code == 200, r.text
    assert body["arguments"]["path"] == spelling  # the agent signed its own spelling, and that verified
    assert sent == [{"path": "synthetic/synthetic_schools.csv"}]
