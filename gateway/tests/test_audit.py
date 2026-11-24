"""Questions 14 and 16: the audit log, the person's view of it, and the operator's CLI."""

import json

import pytest
from fastapi.testclient import TestClient

from gateway import cli, main
from gateway import eval as ev
from gateway.lib import audit
from gateway.lib.common import priv_from_pem
from mcp_server.api.routes_mcp import mcp

PERSON = "officer:jsmith"
AUDIT_SCOPE = [{"server": "gateway", "tools": ["audit"], "constraints": {"principal": [PERSON]}}]


@pytest.fixture
def gw(tmp_path, monkeypatch):
    state = tmp_path / "state"
    cli.main(["--state", str(state), "init"])
    cli.main(
        ["--state", str(state), "issue", "--agent-key", str(state / "agent.pem"), "-o", str(state / "mandate.jwt")]
    )
    monkeypatch.setattr(main, "STATE_DIR", state)
    monkeypatch.setitem(main.MCP_SERVERS, "pupil-data", mcp)
    monkeypatch.delenv("GATEWAY_AUDIT_LOG", raising=False)
    agent_priv = priv_from_pem((state / "agent.pem").read_bytes())
    mandate = (state / "mandate.jwt").read_text()

    def call(client, tool, server="pupil-data", key=agent_priv, token=mandate, **arguments):
        body = cli.sign_request(key, server=server, tool=tool, arguments=arguments, mandate=token)
        return client.post("/tools/call", json=body)

    with TestClient(main.app, raise_server_exceptions=False) as client:
        yield client, call, state


def entries(state):
    return audit.read_entries(state / "audit.jsonl")


def issue(state, key_path, out, *extra):
    cli.main(["--state", str(state), "issue", "--agent-key", str(key_path), "-o", str(out), *extra])
    return out.read_text()


def person_mandate(state, tmp_path, scope=AUDIT_SCOPE):
    """The person's own key and a mandate that lets it read only their own log."""
    token = issue(state, tmp_path / "person.pem", tmp_path / "person.jwt", "--scope", json.dumps(scope), "--deny", "[]")
    return priv_from_pem((tmp_path / "person.pem").read_bytes()), token


def test_allowed_and_denied_calls_are_both_recorded(gw):
    client, call, state = gw
    assert call(client, "search", query=ev.PUPIL, urn="SCH01").status_code == 200
    assert call(client, "search", query="SPR", urn="SCH02").status_code == 403

    allowed, denied = entries(state)
    assert (allowed["decision"]["decision"], denied["decision"]["reason_code"]) == ("ALLOW", "CONSTRAINT_VIOLATED")
    for e in (allowed, denied):
        assert e["mandate"]["verified"] is True
        assert e["mandate"]["principal"] == PERSON
        assert e["mandate"]["jkt"] == e["decision"]["agent_id"]
        assert e["client"]["addr"] == "testclient"
        assert (e["server"], e["tool"]) == ("pupil-data", "search")
    assert allowed["arguments"] == {"query": ev.PUPIL, "urn": "SCH01"}
    assert allowed["status"] == 200
    assert denied["released"] is None  # nothing was sent


def test_summary_lists_pupils_but_stores_no_row_values(gw):
    client, call, state = gw
    rows = call(client, "search", query="SPR", urn="SCH01", limit=5).json()["result"]
    schools = call(client, "get", path=ev.SCHOOLS).json()["result"]

    search, get = entries(state)
    assert search["released"]["rows"] == 5
    assert search["released"]["pupils"] == sorted({r["Psuedo ID"] for r in rows})
    assert search["released"]["columns"] == sorted(rows[0])
    assert get["released"]["schools"] == sorted({s["URN"] for s in schools})

    text = (state / "audit.jsonl").read_text()
    for value in {rows[0]["AcademicYear"], schools[0].get("SchoolName", "")} - {""}:
        assert value not in text
    names = {v for s in schools for k, v in s.items() if k != "URN" and isinstance(v, str) and len(v) > 6}
    assert names, "the schools file should have long text values to look for"
    assert not [n for n in names if n in text]


def test_forged_and_garbage_mandates_are_recorded_unverified(gw):
    client, call, state = gw
    header, payload, sig = (state / "mandate.jwt").read_text().split(".")
    claims = json.loads(cli.b64u_decode(payload))
    claims["scope"][0]["constraints"]["urn"] = ["SCH04"]
    forged = ".".join([header, cli.b64u(json.dumps(claims).encode()), sig])

    r = call(client, "search", token=forged, query="P0011", urn="SCH04")
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "SIG_INVALID")
    call(client, "search", token="not-a-mandate", query="P0011", urn="SCH04")  # 403 or 500: either way, logged

    forged_entry, garbage_entry = entries(state)
    assert forged_entry["mandate"]["verified"] is False
    assert forged_entry["mandate"]["principal"] == PERSON  # what it claims, marked as unverified
    assert garbage_entry["mandate"]["verified"] is False
    assert "unreadable" in garbage_entry["mandate"]["error"]
    assert garbage_entry["arguments"] == {"query": "P0011", "urn": "SCH04"}
    assert audit.verify_chain(state / "audit.jsonl")["ok"]


def test_chain_detects_edited_and_deleted_entries(gw, capsys):
    client, call, state = gw
    for q in ("P0004", "P0005", "P0006", "P0007"):
        call(client, "search", query=q, urn="SCH01")
    log = state / "audit.jsonl"
    good = log.read_text()
    assert audit.verify_chain(log) == {
        "ok": True,
        "entries": 4,
        "head": json.loads(good.splitlines()[-1])["hash"],
        "broken_at": None,
        "reason": "",
    }
    cli.main(["audit", "--state", str(state), "--verify"])
    assert capsys.readouterr().out.startswith("chain OK: 4 entries")

    lines = good.splitlines()
    log.write_text("\n".join([lines[0], lines[1].replace("P0005", "P0099"), *lines[2:]]) + "\n")
    edited = audit.verify_chain(log)
    assert (edited["ok"], edited["broken_at"]) == (False, 1)
    assert "edited" in edited["reason"]

    log.write_text("\n".join([lines[0], *lines[2:]]) + "\n")  # delete entry 1
    deleted = audit.verify_chain(log)
    assert (deleted["ok"], deleted["broken_at"]) == (False, 1)
    with pytest.raises(SystemExit):
        cli.main(["audit", "--state", str(state), "--verify"])
    assert "BROKEN at line 1" in capsys.readouterr().out


def test_person_reads_only_their_own_log(gw, tmp_path):
    client, call, state = gw
    call(client, "search", query=ev.PUPIL, urn="SCH01")
    call(client, "search", query="SPR", urn="SCH02")
    # someone else's mandate, someone else's activity
    other = issue(state, state / "agent.pem", tmp_path / "other.jwt", "--principal", "officer:other")
    call(client, "search", token=other, query="P0005", urn="SCH01")

    key, token = person_mandate(state, tmp_path)
    r = call(client, "audit", server="gateway", key=key, token=token, principal=PERSON)
    assert r.status_code == 200, r.text
    result = r.json()["result"]
    assert result["total"] == 2
    assert {e["mandate"]["principal"] for e in result["entries"]} == {PERSON}
    assert result["chain"]["ok"]
    assert "1 allowed, 1 refused" in result["summary"][0]
    assert f"Pupils whose data was sent: 1 ({ev.PUPIL})." in result["summary"]
    assert result["lines"][0].endswith("allowed")
    assert ev.PUPIL in result["lines"][0]
    assert "refused (outside the mandate)" in result["lines"][1]

    r = call(client, "audit", server="gateway", key=key, token=token, principal="officer:other")
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CONSTRAINT_VIOLATED")
    assert "result" not in r.json()
    r = call(client, "audit", server="gateway", key=key, token=token)
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CONSTRAINT_MISSING")

    # the reads are in the person's own log too, the refused attempt at officer:other's log included
    r = call(client, "audit", server="gateway", key=key, token=token, principal=PERSON, limit=3)
    shown = r.json()["result"]["entries"]
    assert [(e["tool"], e["decision"]["reason_code"]) for e in shown] == [
        ("audit", "IN_SCOPE"),
        ("audit", "CONSTRAINT_VIOLATED"),
        ("audit", "CONSTRAINT_MISSING"),
    ]
    assert shown[1]["arguments"] == {"principal": "officer:other"}
    assert r.json()["result"]["total"] == 5
    # reading the log is not "being sent pupil data": the entry counts log lines, not the pupils inside them
    first_read = shown[0]["released"]
    assert (first_read["pupils"], first_read["log_entries"]) == ([], 2)


def test_agent_data_mandate_cannot_read_the_log(gw):
    client, call, state = gw
    r = call(client, "audit", server="gateway", principal=PERSON)
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "OUT_OF_SCOPE")
    assert "result" not in r.json()
    (refusal,) = entries(state)
    assert (refusal["server"], refusal["tool"], refusal["decision"]["decision"]) == ("gateway", "audit", "DENY")


def test_unconstrained_audit_grant_is_refused(gw, tmp_path):
    client, call, state = gw
    key, token = person_mandate(state, tmp_path, scope=[{"server": "gateway", "tools": ["audit"]}])
    r = call(client, "audit", server="gateway", key=key, token=token, principal="officer:other")
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CONSTRAINT_MISSING")
    assert "result" not in r.json()


def test_audit_requires_a_matching_pinned_grant(gw, tmp_path):
    client, call, state = gw
    call(client, "search", query=ev.PUPIL, urn="SCH01")
    logged_jti = entries(state)[0]["mandate"]["jti"]
    scope = [
        {"server": "gateway", "tools": ["audit"], "constraints": {"principal": [PERSON], "jti": ["allowed"]}},
        {"server": "gateway", "tools": ["audit"]},
    ]
    key, token = person_mandate(state, tmp_path, scope=scope)
    r = call(client, "audit", server="gateway", key=key, token=token, principal=PERSON, jti=logged_jti)
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CONSTRAINT_VIOLATED")
    assert "result" not in r.json()


def test_cli_finds_flag_pupil(gw, capsys):
    client, call, state = gw
    call(client, "search", query="P0006", urn="SCH01")
    call(client, "search", query=ev.PUPIL, urn="SCH01")
    call(client, "search", query="P0011", urn="SCH04")  # refused attempt that names the pupil
    capsys.readouterr()

    cli.main(["audit", "--state", str(state), "--pupil", ev.PUPIL])
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 1
    assert "ALLOW IN_SCOPE officer:jsmith" in out[0]
    assert f"pupils={ev.PUPIL}" in out[0]

    cli.main(["audit", "--file", str(state / "audit.jsonl"), "--pupil", "P0011", "--decision", "DENY", "--plain"])
    out = capsys.readouterr().out
    assert "refused (outside the mandate)" in out


def test_unwritable_log_fails_closed(gw, monkeypatch):
    client, call, state = gw
    monkeypatch.setenv("GATEWAY_AUDIT_LOG", str(state / "mandate.jwt" / "audit.jsonl"))  # parent is a file
    r = call(client, "search", query=ev.PUPIL, urn="SCH01")
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "AUDIT_UNAVAILABLE")
    assert "result" not in r.json()


def test_healthcheck_reports_unwritable_log(tmp_path, monkeypatch):
    state = tmp_path / "state"
    cli.main(["--state", str(state), "init"])
    monkeypatch.setattr(main, "STATE_DIR", state)
    monkeypatch.delenv("GATEWAY_AUDIT_LOG", raising=False)
    with TestClient(main.app) as client:
        assert client.get("/healthcheck").status_code == 200

    monkeypatch.setenv("GATEWAY_AUDIT_LOG", str(state / "trusted_list.json" / "audit.jsonl"))
    with TestClient(main.app) as client:
        r = client.get("/healthcheck")
    assert r.status_code == 503
    assert "cannot be written" in r.json()["reason"]
