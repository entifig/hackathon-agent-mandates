"""Question 7: an agent hands a helper a narrower child of its mandate, signed with its own key (delegation.py)."""

import csv
import json
import time
from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient

from gateway import cli, main
from gateway.lib import audit, delegation
from gateway.lib.common import b64u, generate_keypair, jwk_thumbprint, priv_from_pem, priv_to_pem, pub_to_jwk
from gateway.lib.delegation import check_narrower
from mcp_server.api.routes_mcp import mcp

ROOT = Path(__file__).resolve().parents[2]
DUNMORE = "SCH04"
PERSON = "officer:jsmith"
Y11 = {"urn": DUNMORE, "year_group": 11, "academic_year": "2023/24", "term": "SPR"}
# the agent: Dunmore's lists, pupils and letters
PARENT_SCOPE = [
    {"server": "pupil-data", "tools": ["roster", "search", "pupil", "draft"], "constraints": {"urn": [DUNMORE]}}
]
# the helper: the Year 11 list and absence letters, nothing else
CHILD_SCOPE = [
    {
        "server": "pupil-data",
        "tools": ["roster"],
        "constraints": {"urn": [DUNMORE], "year_group": ["11"], "academic_year": ["2023/24"], "term": ["SPR"]},
    },
    {"server": "pupil-data", "tools": ["draft"], "constraints": {"urn": [DUNMORE], "kind": ["absence"]}},
]


def dunmore_pupils() -> list[str]:
    with (ROOT / "mcp_server/data/synthetic/synthetic_personal_data_school_census.csv").open(newline="") as f:
        return sorted({row["Psuedo ID"] for row in csv.DictReader(f) if row["URN"] == DUNMORE})


@pytest.fixture
def gw(tmp_path, monkeypatch):
    state = tmp_path / "state"
    cli.main(["--state", str(state), "init"])
    monkeypatch.setattr(main, "STATE_DIR", state)
    monkeypatch.setitem(main.MCP_SERVERS, "pupil-data", mcp)
    monkeypatch.delenv("GATEWAY_AUDIT_LOG", raising=False)
    with TestClient(main.app) as client:
        yield client, state


class Chain:
    """A Dunmore parent mandate held by the agent, and a helper key to hand a child to."""

    def __init__(self, client, state, *, scope=PARENT_SCOPE, ttl=600, extra=None, deny=None):
        self.client, self.state = client, state
        self.agent, _ = generate_keypair()
        self.helper, _ = generate_keypair()
        self.parent, self.idx = cli.issue_mandate(
            state,
            self.agent.public_key(),
            scope=scope,
            deny=cli.DEFAULT_DENY if deny is None else deny,
            ttl=ttl,
            purpose="Dunmore absence letters",
            principal=PERSON,
            org=f"school:{DUNMORE}",
            extra=extra,
        )
        self.parent_claims = jwt.decode(self.parent, options={"verify_signature": False})

    def child(self, scope=CHILD_SCOPE, **kwargs) -> str:
        return delegation.delegate(self.parent, self.agent, self.helper.public_key(), scope=scope, **kwargs)

    def mint(self, *, signer=None, header=None, drop=(), **claims) -> str:
        """A child built by hand, for what delegate() refuses to make: any claim, header or signing key."""
        now = int(time.time())
        helper_jwk = pub_to_jwk(self.helper.public_key())
        body = {
            "iss": delegation.issuer_uri(self.parent_claims["cnf"]["jwk"]),
            "jti": "urn:uuid:hand-made",
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "vct": delegation.VCT,
            "parent": self.parent,
            "cnf": {"jwk": helper_jwk},
            "agent_id": jwk_thumbprint(helper_jwk),
            "scope": CHILD_SCOPE,
            "deny": cli.DEFAULT_DENY,
            **claims,
        }
        for name in drop:
            body.pop(name)
        return jwt.encode(
            body,
            priv_to_pem(signer or self.agent),
            algorithm="EdDSA",
            headers=header or {"typ": delegation.DELEGATED_TYP},
        )

    def call(self, tool, token=None, key=None, **arguments):
        return self.send(self.sign(tool, token, key, **arguments))

    def sign(self, tool, token=None, key=None, server="pupil-data", **arguments):
        token = token if token is not None else self.child()
        return cli.sign_request(key or self.helper, server=server, tool=tool, arguments=arguments, mandate=token)

    def send(self, body):
        return self.client.post("/tools/call", json=body)


@pytest.fixture
def chain(gw):
    return Chain(*gw)


def reason(r):
    return r.status_code, r.json()["decision"]["reason_code"]


# ---------------------------------------------------------------- the question


def test_helper_gets_the_year_11_list_and_its_letters_are_held_for_approval(chain):
    r = chain.call("roster", **Y11)
    assert reason(r) == (200, "IN_SCOPE")
    assert r.json()["decision"]["agent_id"] == jwk_thumbprint(pub_to_jwk(chain.helper.public_key()))
    rows = r.json()["result"]
    assert len(rows) == 41
    assert rows[0]["Psuedo ID"].startswith("P")
    # drafting letters is a step-up tool on this gateway: a helper cannot escape that
    r = chain.call("draft", urn=DUNMORE, pupil_ids=[rows[0]["Psuedo ID"]], kind="absence")
    assert reason(r) == (202, "SENSITIVE_TOOL")


def test_helper_cannot_reach_past_its_child(chain):
    child = chain.child()
    assert reason(chain.call("roster", child, **{**Y11, "year_group": 10})) == (403, "CONSTRAINT_VIOLATED")
    assert reason(chain.call("search", child, query="P1017", urn=DUNMORE)) == (403, "OUT_OF_SCOPE")  # parent's only
    assert reason(chain.call("draft", child, urn=DUNMORE, pupil_ids=["P1017"], kind="attendance_meeting")) == (
        403,
        "CONSTRAINT_VIOLATED",
    )
    assert reason(chain.call("roster", child, **{**Y11, "urn": "SCH05"})) == (403, "CONSTRAINT_VIOLATED")
    # the parent still has what it had
    assert reason(chain.call("search", chain.parent, chain.agent, query="P1017", urn=DUNMORE)) == (200, "IN_SCOPE")


def roster_entry(**constraints):
    return {"server": "pupil-data", "tools": ["roster"], "constraints": constraints}


@pytest.mark.parametrize(
    ("what", "claims"),
    [
        ("wider tools", {"scope": [{**CHILD_SCOPE[0], "tools": ["roster", "aggregate"]}]}),
        ("another server", {"scope": [{**CHILD_SCOPE[0], "server": "pii"}]}),
        ("wider values", {"scope": [roster_entry(urn=[DUNMORE, "SCH05"], year_group=["11"])]}),
        ("dropped constraint", {"scope": [roster_entry(year_group=["11"])]}),
        ("no constraints", {"scope": [{"server": "pupil-data", "tools": ["roster"]}]}),
        ("dropped deny", {"deny": ["pii.*"]}),
        ("no deny", {"deny": []}),
        ("longer exp", {"exp": "parent+3600"}),
        ("earlier nbf", {"nbf": "parent-3600"}),
    ],
)
def test_a_child_wider_than_its_parent_is_denied(chain, what, claims):
    if claims.get("exp") == "parent+3600":
        claims = {"exp": chain.parent_claims["exp"] + 3600}
    if claims.get("nbf") == "parent-3600":
        claims = {"nbf": chain.parent_claims["nbf"] - 3600}
    r = chain.call("roster", chain.mint(**claims), **Y11)
    assert reason(r) == (403, "DELEGATION_WIDER"), what
    if "scope" in claims:  # and the holder's own tool refuses to make it (it sets exp, nbf and deny itself)
        with pytest.raises(ValueError, match="DELEGATION_WIDER"):
            chain.child(scope=claims["scope"])


def test_delegate_keeps_the_parents_deny_and_never_outlives_it(chain):
    claims = jwt.decode(chain.child(deny=["pupil-data.pupil"], ttl=10**9), options={"verify_signature": False})
    assert claims["deny"] == [*cli.DEFAULT_DENY, "pupil-data.pupil"]
    assert claims["exp"] == chain.parent_claims["exp"]


def test_narrower_is_decided_per_entry():
    parent = {
        "scope": [
            {"server": "s", "tools": ["get"], "constraints": {"urn": ["A"], "path": ["a"]}},
            {"server": "s", "tools": ["get"], "constraints": {"urn": ["B"], "path": ["b"]}},
        ],
        "deny": [],
        "exp": 100,
    }

    def child(*entries, **extra):
        return {"scope": list(entries), "deny": [], "exp": 100, "nbf": 0, **extra}

    def entry(**constraints):
        return {"server": "s", "tools": ["get"], "constraints": constraints}

    check_narrower(parent, child(entry(urn=["A"], path=["a"])))
    check_narrower(parent, child(entry(urn=["B"], path=["b"], limit=["5"])))  # a child may add a constraint
    check_narrower(parent, child(entry(urn=["A"], path=["a"]), entry(urn=["B"], path=["b"])))
    check_narrower(parent, child(entry(urn=[], path=["a"])))  # an empty list allows nothing: still narrower
    check_narrower(parent, child())  # an empty scope: a child that can do nothing
    for wider in (
        entry(urn=["A"], path=["b"]),  # urn from one entry, path from the other
        entry(urn=["A", "B"], path=["a"]),
        entry(urn=["A"]),
        {"server": "s", "tools": ["get", "put"], "constraints": {"urn": ["A"], "path": ["a"]}},
    ):
        with pytest.raises(delegation.Reject) as e:
            check_narrower(parent, child(wider))
        assert e.value.code == "DELEGATION_WIDER", wider


# ---------------------------------------------------------------- who may make a child


def test_a_child_signed_by_any_other_key_is_invalid(chain):
    stranger, _ = generate_keypair()
    for signer in (stranger, chain.helper):  # a stranger, or the helper making its own
        r = chain.call("roster", chain.mint(signer=signer), **Y11)
        assert reason(r) == (403, "DELEGATION_INVALID")
    with pytest.raises(ValueError, match="only its holder"):
        delegation.delegate(chain.parent, stranger, chain.helper.public_key(), scope=CHILD_SCOPE)


def test_a_child_must_name_its_parents_key_as_issuer(chain):
    r = chain.call("roster", chain.mint(iss="https://issuer.hack.local"), **Y11)
    assert reason(r) == (403, "DELEGATION_INVALID")


def test_a_child_cannot_pass_as_issuer_signed(chain):
    meta = json.loads((chain.state / "status_list.json").read_text())
    header = {"typ": "mandate+jwt", "kid": meta["kid"]}
    r = chain.call("roster", chain.mint(header=header, iss=meta["issuer"]), **Y11)
    assert reason(r) == (403, "SIG_INVALID")  # the ordinary path: the issuer never signed it


def test_an_issuer_signed_mandate_may_not_carry_a_parent(chain):
    other = Chain(chain.client, chain.state, extra={"parent": chain.parent})
    r = other.call("roster", other.parent, other.agent, **Y11)
    assert reason(r) == (403, "MANDATE_MALFORMED")


def test_revoking_the_parent_kills_the_child_at_once(chain):
    child = chain.child()
    assert chain.call("roster", child, **Y11).status_code == 200
    cli.main(["--state", str(chain.state), "revoke", "--idx", str(chain.idx)])
    r = chain.call("roster", child, **Y11)
    assert reason(r) == (403, "REVOKED")
    assert r.json()["decision"]["detail"].startswith("parent mandate:")


def test_a_child_of_an_expired_parent_is_expired(gw):
    expired = Chain(*gw, ttl=-120)
    r = expired.call("roster", expired.child(), **Y11)
    assert reason(r) == (403, "EXPIRED")


def test_an_expired_child_of_a_live_parent_is_expired(chain, monkeypatch):
    now = int(time.time())
    r = chain.call("roster", chain.mint(nbf=now + 300), **Y11)
    assert reason(r) == (403, "NOT_YET_VALID")
    short = chain.mint(nbf=chain.parent_claims["nbf"], exp=now + 60)
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 200)  # the parent (600 s) still runs, the child (60 s) has not
    r = chain.call("roster", short, **Y11)
    assert reason(r) == (403, "EXPIRED")
    assert reason(chain.call("roster", chain.parent, chain.agent, **Y11)) == (200, "IN_SCOPE")


def test_a_child_cannot_delegate_again(chain):
    child = chain.child()
    grand_helper, _ = generate_keypair()
    with pytest.raises(ValueError, match="depth"):
        delegation.delegate(child, chain.helper, grand_helper.public_key(), scope=CHILD_SCOPE)
    # by hand: the child's holder signs a grandchild whose parent is the child
    child_jwk = pub_to_jwk(chain.helper.public_key())
    grand_jwk = pub_to_jwk(grand_helper.public_key())
    grandchild = chain.mint(
        signer=chain.helper,
        parent=child,
        iss=delegation.issuer_uri(child_jwk),
        cnf={"jwk": grand_jwk},
        agent_id=jwk_thumbprint(grand_jwk),
    )
    r = chain.call("roster", grandchild, grand_helper, **Y11)
    assert reason(r) == (403, "DELEGATION_INVALID")
    assert "depth" in r.json()["decision"]["detail"]


def test_a_forged_or_unaccredited_parent_is_refused(chain, tmp_path):
    rogue = tmp_path / "rogue"
    cli.main(["--state", str(rogue), "init", "--issuer", "https://rogue.example"])
    unaccredited = Chain(chain.client, rogue)  # issued by an issuer this gateway does not trust
    r = unaccredited.call("roster", unaccredited.child(), **Y11)
    assert reason(r) == (403, "ISSUER_NOT_ACCREDITED")

    header, payload, sig = chain.parent.split(".")
    claims = json.loads(cli.b64u_decode(payload))
    claims["scope"][0]["constraints"]["urn"] = [DUNMORE, "SCH05"]  # widen the parent itself
    chain.parent = ".".join([header, b64u(json.dumps(claims).encode()), sig])
    chain.parent_claims = claims
    child = chain.child(scope=[{**CHILD_SCOPE[0], "constraints": {**CHILD_SCOPE[0]["constraints"], "urn": ["SCH05"]}}])
    r = chain.call("roster", child, **{**Y11, "urn": "SCH05"})
    assert reason(r) == (403, "SIG_INVALID")


# ---------------------------------------------------------------- budgets


def test_a_helper_is_charged_to_the_parents_budget(gw):
    budgeted = Chain(*gw, extra={"budget": {"pupils": 2, "calls": 10}})
    a, b, c = dunmore_pupils()[:3]
    child = budgeted.child()  # no budget of its own: the parent's still applies
    scope = [{"server": "pupil-data", "tools": ["search", "pupil"], "constraints": {"urn": [DUNMORE]}}]
    searcher = budgeted.child(scope=scope)

    assert budgeted.call("search", budgeted.parent, budgeted.agent, query=a, urn=DUNMORE).status_code == 200
    r = budgeted.call("search", searcher, query=b, urn=DUNMORE)
    assert r.status_code == 200
    assert r.json()["budget"] == {"pupils_used": 2, "pupils_limit": 2, "calls_used": 2, "calls_limit": 10}
    r = budgeted.call("search", searcher, query=c, urn=DUNMORE)
    assert reason(r) == (403, "BUDGET_EXHAUSTED")
    assert "parent mandate's budget" in r.json()["decision"]["detail"]
    # the helper's pupil counts against the parent too, and a listing over budget is withheld from the helper
    assert reason(budgeted.call("search", budgeted.parent, budgeted.agent, query=c, urn=DUNMORE))[1] == (
        "BUDGET_EXHAUSTED"
    )
    assert reason(budgeted.call("roster", child, **Y11)) == (403, "BUDGET_EXHAUSTED")
    # a budgeted parent's rules hold for its children: one pupil ID per search
    assert reason(budgeted.call("search", searcher, query="SPR", urn=DUNMORE)) == (403, "BUDGET_QUERY")


def test_a_childs_own_budget_is_also_charged_and_cannot_exceed_the_parents(gw):
    budgeted = Chain(*gw, extra={"budget": {"pupils": 3, "calls": 10}})
    a, b = dunmore_pupils()[:2]
    scope = [{"server": "pupil-data", "tools": ["search"], "constraints": {"urn": [DUNMORE]}}]
    with pytest.raises(ValueError, match="DELEGATION_WIDER"):
        budgeted.child(scope=scope, budget={"pupils": 4})
    wider = budgeted.child(scope=scope, budget={"pupils": 4}, check=False)
    assert reason(budgeted.call("search", wider, query=a, urn=DUNMORE)) == (403, "DELEGATION_WIDER")
    sneaky = budgeted.mint(scope=scope, budget={"pupils": 1, "id": "shared-with-someone"})
    assert reason(budgeted.call("search", sneaky, query=a, urn=DUNMORE)) == (403, "DELEGATION_INVALID")

    small = budgeted.child(scope=scope, budget={"pupils": 1})
    r = budgeted.call("search", small, query=a, urn=DUNMORE)
    assert r.status_code == 200
    assert [(x["of"], x["pupils_used"], x["pupils_limit"]) for x in r.json()["budgets"]] == [
        ("child", 1, 1),
        ("parent", 1, 3),
    ]
    r = budgeted.call("search", small, query=b, urn=DUNMORE)
    assert reason(r) == (403, "BUDGET_EXHAUSTED")
    assert "child mandate's budget" in r.json()["decision"]["detail"]


# ---------------------------------------------------------------- what a child can never be


def test_a_child_cannot_be_granted_the_request_log(gw):
    grant = {"server": "gateway", "tools": ["audit"], "constraints": {"principal": [PERSON]}}
    person = Chain(*gw, scope=[grant], deny=[])
    child = person.child(scope=[grant], check=False)
    with pytest.raises(ValueError, match="DELEGATION_INVALID"):
        person.child(scope=[grant])
    r = person.call("audit", child, server="gateway", principal=PERSON)
    assert reason(r) == (403, "DELEGATION_INVALID")
    # the person's own mandate still reads it
    assert person.call("audit", person.parent, person.agent, server="gateway", principal=PERSON).status_code == 200


@pytest.mark.parametrize(
    "parent",
    ["garbage", 5, None, ["x"], {"a": 1}, "a.b.c", "", "x" * 5000, True],
)
def test_a_malformed_parent_is_denied_not_a_500(chain, parent):
    r = chain.call("roster", chain.mint(parent=parent), **Y11)
    assert reason(r) == (403, "DELEGATION_INVALID")


def test_a_parent_that_is_not_a_mandate_is_denied(chain):
    status_list = (chain.state / "status_list.jwt").read_text().strip()
    assert reason(chain.call("roster", chain.mint(parent=status_list), **Y11)) == (403, "WRONG_TOKEN_TYPE")
    assert reason(chain.call("roster", chain.mint(drop=["parent"]), **Y11)) == (403, "DELEGATION_INVALID")


@pytest.mark.parametrize(
    "claims",
    [
        {"purpose": "anything I like"},
        {"delegator": {"principal": "officer:someone-else", "org": "x"}},
        {"status": {"status_list": {"uri": "u", "idx": 9999}}},
        {"clearance": 3},
        {"scope": "everything"},
        {"scope": [{"server": "pupil-data"}]},
        {"deny": "none"},
        {"exp": "never"},
        {"nbf": None},
        {"cnf": {"jwk": {"kty": "RSA"}}},
        {"cnf": "helper"},
        {"agent_id": "someone-else"},
        {"vct": "urn:hack:mandate:v1"},
        {"budget": "lots"},
        {"budget": {"pupils": -1}},
    ],
)
def test_a_malformed_child_is_denied_not_a_500(chain, claims):
    r = chain.call("roster", chain.mint(**claims), **Y11)
    assert reason(r) == (403, "DELEGATION_INVALID"), claims


def test_garbage_with_a_delegated_header_is_denied(chain):
    header = b64u(json.dumps({"alg": "EdDSA", "typ": delegation.DELEGATED_TYP}).encode())
    for payload in (b"not json", b"[1, 2]", b'"str"'):
        r = chain.call("roster", f"{header}.{b64u(payload)}.c2ln", **Y11)
        assert r.status_code == 403
        assert r.json()["decision"]["reason_code"] in {"DELEGATION_INVALID", "MANDATE_MALFORMED"}


def test_replay_and_the_wrong_key_are_refused(chain):
    child = chain.child()
    body = chain.sign("roster", child, **Y11)
    assert chain.send(body).status_code == 200
    assert reason(chain.send(body)) == (403, "POP_FAILED")  # the same signed request again
    assert reason(chain.call("roster", child, chain.agent, **Y11)) == (403, "POP_FAILED")  # parent's key, child token
    # the helper lifts the parent out of the child: it does not hold the parent's key
    assert reason(chain.call("roster", chain.parent, chain.helper, **Y11)) == (403, "POP_FAILED")


def test_the_parent_scope_is_checked_again(chain, monkeypatch):
    """Defence in depth: if the narrower check let a wide child through, the parent's own scope still refuses."""
    monkeypatch.setattr(delegation, "check_narrower", lambda *_: None)
    wide = chain.mint(scope=[{"server": "pupil-data", "tools": ["roster"], "constraints": {"urn": ["SCH05"]}}])
    r = chain.call("roster", wide, **{**Y11, "urn": "SCH05"})
    assert reason(r) == (403, "DELEGATION_WIDER")
    assert "parent mandate refuses" in r.json()["decision"]["detail"]


# ---------------------------------------------------------------- the audit log and the CLI


def test_helper_calls_are_logged_under_the_parent(chain, capsys):
    child = chain.child()
    child_jti = jwt.decode(child, options={"verify_signature": False})["jti"]
    parent_jti = chain.parent_claims["jti"]
    assert chain.call("search", chain.parent, chain.agent, query="P1017", urn=DUNMORE).status_code == 200
    assert chain.call("roster", child, **Y11).status_code == 200
    assert chain.call("roster", child, **{**Y11, "year_group": 10}).status_code == 403

    entries = audit.read_entries(chain.state / "audit.jsonl")
    found = audit.select(entries, jti=parent_jti)
    assert len(found) == 3  # the parent's own call and both of the helper's
    assert audit.select(entries, jti=child_jti) == found[1:]
    helper = found[1]["mandate"]
    assert helper["verified"] is True
    assert helper["delegated"] is True
    assert (helper["jti"], helper["parent_jti"], helper["chain"]) == (child_jti, parent_jti, [parent_jti, child_jti])
    assert helper["principal"] == PERSON  # the person who granted the parent, so their own log shows it
    assert helper["jkt"] == jwk_thumbprint(pub_to_jwk(chain.helper.public_key()))
    assert found[1]["released"]["rows"] == 41
    assert "a helper" in audit.plain(found[1])

    capsys.readouterr()
    cli.main(["--state", str(chain.state), "audit", "--jti", parent_jti])
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 3
    assert f"parent={parent_jti}" in lines[1]
    assert audit.verify_chain(chain.state / "audit.jsonl")["ok"]


def test_a_forged_child_is_logged_unverified(chain):
    stranger, _ = generate_keypair()
    chain.call("roster", chain.mint(signer=stranger), **Y11)
    (entry,) = audit.read_entries(chain.state / "audit.jsonl")
    assert entry["mandate"]["verified"] is False
    assert entry["mandate"]["delegated"] is True


def test_cli_delegate_and_decode(chain, tmp_path, capsys):
    (tmp_path / "parent.jwt").write_text(chain.parent)
    (tmp_path / "agent.pem").write_bytes(priv_to_pem(chain.agent))
    helper_key = tmp_path / "helper.pem"
    cli.main(["keygen", "-o", str(helper_key)])
    (tmp_path / "helper.jwk").write_text(capsys.readouterr().out)
    base = ["delegate", "--mandate", str(tmp_path / "parent.jwt"), "--agent-key", str(tmp_path / "agent.pem")]
    base += ["--helper-key", str(tmp_path / "helper.jwk")]
    cli.main([*base, "--scope", json.dumps(CHILD_SCOPE), "--ttl", "300", "-o", str(tmp_path / "child.jwt")])
    child = (tmp_path / "child.jwt").read_text()

    capsys.readouterr()
    cli.main(["decode", str(tmp_path / "child.jwt")])
    decoded = json.loads(capsys.readouterr().out)
    assert decoded["parent"]["jti"] == chain.parent_claims["jti"]  # the parent is shown decoded
    assert decoded["scope"] == CHILD_SCOPE

    r = chain.call("roster", child, priv_from_pem(helper_key.read_bytes()), **Y11)
    assert reason(r) == (200, "IN_SCOPE")

    wider = [{"server": "pupil-data", "tools": ["roster"], "constraints": {"urn": [DUNMORE, "SCH05"]}}]
    with pytest.raises(SystemExit, match="DELEGATION_WIDER"):
        cli.main([*base, "--scope", json.dumps(wider)])
