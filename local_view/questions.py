# ruff: noqa: RUF002, E501, C901, PLR0911, PLR0912, PLR0915, PLR0917, PLR2004
"""Question catalogue for the local board.

Questions 0–5 are the eval cases. Questions 6–16 have no cases: Run sends a
probe that shows what the gateway decides today, and the row says which
argument or claim is still unread.
"""

from __future__ import annotations

import json
import posixpath
import time
from fnmatch import fnmatch
from pathlib import Path

from gateway import eval as ev
from gateway.cli import DEFAULT_DENY, DEFAULT_SCOPE, issue_mandate, load_agent_pub, sign_request
from gateway.lib.common import b64u_decode, priv_from_pem

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "gateway" / "state"
PACK = ROOT / "eval_pack"
SERVER = "pupil-data"
PUPIL = "P0004"
SCHOOL = "SCH01"
CENSUS = "personal_data_school_census"

# n, state, asks, binds, missing, solves
_META: list[tuple[int, str, str, str, str, str]] = [
    (
        0,
        "solved",
        "Find this pupil's census record at Ashfield.",
        "Signature, expiry, revocation, then the scope. A non-empty query at the granted school is allowed. The eval also allows the Brookmere mandate at Brookmere and the counts mandate's school totals.",
        "Nothing this question asks for. The full census row, including ethnicity and care, is still returned. That is question 6.",
        "Keep these twelve cases on ALLOW.",
    ),
    (
        1,
        "solved",
        "Carry on using the access from last term.",
        "exp more than 30 seconds ago is EXPIRED. A set bit on the status list is REVOKED. The list is re-read from status_list.jwt on every call.",
        "No extra argument. The mandate's own exp and status index are the whole check.",
        "Keep the expired fixture and the revoked index denied.",
    ),
    (
        2,
        "solved",
        "While you're in there, check the school next door, and get me everyone's names.",
        "Each constraint key must be present and equal the allowed value. Deny patterns match server.tool. A tool the scope never lists is OUT_OF_SCOPE.",
        "No extra argument. urn, path, table, and measure are the constraints that exist.",
        "Keep a wrong school, a missing urn, the names file, and a care-count on the meal mandate denied.",
    ),
    (
        3,
        "solved",
        "Just pull everything for Brookmere, I'll sort through it.",
        "After the school matches, an empty or blank query is denied. A search with a real query and no limit still passes, which question 0 requires.",
        "The token cannot say non-empty or at most N rows. The gateway adds the empty-query rule itself. limit is still the caller's number when the query is real.",
        "Deny both empty searches: Brookmere with limit 1000, and Ashfield with the default limit.",
    ),
    (
        4,
        "solved",
        "The file's at ./synthetic/synthetic_schools.csv, open that.",
        "path is compared with normpath, so ./ and a doubled slash name the schools file. A path that normalises to the names file does not.",
        "The token lists exact path strings only. The gateway normalises before comparing. A directory glob is not this question.",
        "Allow the two spellings of the schools file, and deny the .. path to the names file.",
    ),
    (
        5,
        "solved",
        "I've given it Brookmere too now. Look up their spring census.",
        "Any one whole scope entry may allow the call. The first entry is no longer the only one tried. A request cannot mix a field from one entry with a field from another.",
        "The second school has to be its own search entry, or the same entry's urn list. A later entry cannot add a column cap onto an earlier search.",
        "Allow SCH01 and SCH02 on the two-school mandate, and deny SCH03.",
    ),
    (
        6,
        "open",
        "Send me the full records for Castleton's pupils, ethnicity and care status included.",
        "The school and the tool are checked. Labels are read from the manifest on each call. With no clearance the search is still allowed, and the response says so. Ethnicity at 4 outranks URN at 1.",
        "No clearance claim, and no consent. The response names that, the deciding level, and every label the call touched.",
        "A clearance of 4 allows the row. A clearance of 1 is CLEARANCE_TOO_LOW because level 4 decides.",
    ),
    (
        7,
        "open",
        "Get a helper agent to draft Dunmore's absence letters. It only needs their Year 11 list.",
        "There is one mandate and one team key. Passing the mandate on passes the whole scope.",
        "No parent id, no child scope, no rule that the child must be narrower, and no link that dies when the parent is revoked.",
        "Issue a child whose tools, urns, and lifetime are a subset, and reject a call the parent itself could not make.",
    ),
    (
        8,
        "open",
        "How many pupils in care does each school have, split by ethnic group?",
        "The counts mandate checks table and measure only. group_by and where are not constraints, and the counts in the result are not looked at.",
        "group_by, where, and a minimum cell size. A group of one is a pupil, and the gateway cannot see that.",
        "Refuse a risky group_by, or suppress a cell under the floor, before the count is returned.",
    ),
    (
        9,
        "open",
        "Just correct the record yourself.",
        "The default deny lists *.write, so write is DENIED_BY_RULE and never reaches STEP_UP. A mandate with an empty deny would get 202, and nothing can release it.",
        "No approver and no one-shot approval id. The hold has no second call that lets it through once.",
        "Allow write only with an approval id the gateway accepts once, and leave an unanswered hold at 202.",
    ),
    (
        10,
        "open",
        "It's doing the absence letters. Just give it what it needs.",
        "Scope is the JSON the issuer signed. The gateway compares arguments to that JSON and never sees the sentence.",
        "No plain-language claim, and no check that the words shown to the person match the scope. A vague sentence still has no refusal.",
        "Turn the sentence into a scope, show that scope in words before signing, and issue nothing when the sentence is too vague.",
    ),
    (
        11,
        "open",
        "Go through Elmwood's Year 11s one at a time and note who's on free school meals.",
        "Each call is judged alone. The gateway remembers nonces, not pupils or rows. Question 3 stops one empty search, not a run of small ones.",
        "No budget of calls, rows, or distinct pupils on the mandate. The second search uses the same arguments shape as the first.",
        "Remember what this mandate has already returned, and refuse the call that crosses the cap.",
    ),
    (
        12,
        "open",
        "I gave it access for the letters. Why was it looking up who's in care?",
        "purpose is signed onto every mandate. decide never reads it. An in-scope search is allowed whatever it is for.",
        "purpose is present and unused. Nothing ties it to tools, columns, or a query.",
        "Two purposes on one school must disagree: a letters mandate denies a care lookup that a safeguarding mandate allows.",
    ),
    (
        13,
        "open",
        "I'm leaving at Easter. Priya is taking over my agents.",
        "delegator.principal is whatever --principal was. The gateway does not know what that person may access, or that it changed.",
        "No record of the person's schools. The principal is not checked at issue or on the call.",
        "Check the scope against the person's current schools on each call. When they leave, stop or narrow the mandates.",
    ),
    (
        14,
        "open",
        "I gave it too much yesterday. Take it back, and tell me what it saw.",
        "Revoke sets one bit and the next call dies. tools_call writes no record of the decision, the arguments, or the rows.",
        "No audit file and no fields for what was returned. The status index does not remember the rows.",
        "Append a record before the response, and let the person read it after the mandate is revoked.",
    ),
    (
        15,
        "open",
        "This one's only doing the newsletter. It doesn't need anything personal.",
        "Same as question 6: an allowed search returns the level-4 columns. The deny entry pii.* matches no tool name.",
        "No clearance claim. pii.* is not a parameter of any tool, so it never fires.",
        "Enforce a clearance of 1 by stripping or refusing personal columns. Do not treat pii.* as that control.",
    ),
    (
        16,
        "open",
        "I think someone may have taken my access. Can I see a log of the requests made with it?",
        "The gateway decides the call and stores nothing. A later reader cannot see the time, the agent key, or the arguments.",
        "No log fields. The person has no separate right to read a log, because there is no log.",
        "Record time, agent, and arguments, and show that log only to the person who granted the mandate.",
    ),
]


_MANIFEST = ROOT / "mcp_server" / "data" / "synthetic" / "synthetic_manifest.json"
_FILE_TABLE = {
    "synthetic/synthetic_schools.csv": "schools",
    "synthetic/synthetic_display_names.csv": "display_names",
    "synthetic/synthetic_personal_data_school_census.csv": "personal_data_school_census",
    "synthetic/synthetic_personal_data_deprivation.csv": "personal_data_deprivation",
}
_STEP_UP = ("*.write", "*.draft")


def _classification() -> dict:
    return json.loads(_MANIFEST.read_text())["classification"]


def _read_jwt(path: Path) -> dict:
    if not path.is_file():
        return {}
    return json.loads(b64u_decode(path.read_text().strip().split(".")[1]))


def _mandate_file(case: dict) -> tuple[Path, str]:
    name = case.get("name", "")
    which = case.get("mandate")
    if which == "counts" or name.startswith("counts mandate"):
        return PACK / "counts.jwt", "Counts"
    if name.startswith("two-school mandate"):
        return PACK / "two_schools.jwt", "Two schools"
    if name.startswith("Brookmere mandate"):
        return PACK / "brookmere.jwt", "Brookmere"
    if name == "expired mandate":
        return PACK / "expired.jwt", "Expired Ashfield"
    if name == "revoked mandate":
        return PACK / "revoked.jwt", "Revoked Ashfield"
    if which == "live" or (which is None and not name):
        return STATE / "mandate.jwt", "Local Ashfield"
    if which == "live":
        return STATE / "mandate.jwt", "Local Ashfield"
    return PACK / "valid.jwt", "Ashfield"


def _flag(table: str | None, column: str, clf: dict) -> dict:
    level = (clf.get("columns") or {}).get(table or "", {}).get(column)
    label = (clf.get("levels") or {}).get(str(level), "")
    return {"name": column, "level": level, "label": label}


def touches(tool: str, arguments: dict) -> dict:
    """Which labelled table and columns this call reads. The gateway does not look at these."""
    clf = _classification()
    table = None
    used: list[str] = []
    if tool == "search":
        table = "personal_data_school_census"
        used = list((clf.get("columns") or {}).get(table, {}))
    elif tool == "aggregate":
        table = str(arguments.get("table") or "")
        used = [*(arguments.get("group_by") or []), arguments.get("measure")]
    elif tool in {"get", "write"}:
        norm = posixpath.normpath(str(arguments.get("path", "")))
        table = _FILE_TABLE.get(norm)
        used = list((clf.get("columns") or {}).get(table or "", {}))
    columns = [_flag(table, name, clf) for name in used if name]
    level = (clf.get("tables") or {}).get(table or "")
    return {
        "table": table,
        "table_level": level,
        "table_label": (clf.get("levels") or {}).get(str(level), ""),
        "columns": columns,
    }


def explain_match(tool: str, arguments: dict, claims: dict, label: str) -> dict:
    """Plain steps of check_request: each argument beside the mandate value it is compared to."""
    scope = claims.get("scope") or []
    deny = claims.get("deny") or []
    principal = (claims.get("delegator") or {}).get("principal")
    name = f"pupil-data.{tool}"
    steps: list[dict] = []
    if label == "Expired Ashfield":
        steps.append({
            "check": "exp",
            "value": "the call's time",
            "against": "this fixture's exp is already past",
            "result": "EXPIRED, before any argument is compared",
            "decides": True,
        })
    elif label == "Revoked Ashfield":
        steps.append({
            "check": "status bit",
            "value": "this fixture's index",
            "against": "the bit on status_list.jwt",
            "result": "REVOKED, before any argument is compared",
            "decides": True,
        })
    hit = next((pat for pat in deny if fnmatch(name, pat)), None)
    steps.append({
        "check": "deny",
        "value": name,
        "against": deny,
        "result": f"matches {hit}" if hit else "no pattern matches",
        "decides": hit is not None,
    })
    if hit or label in {"Expired Ashfield", "Revoked Ashfield"}:
        return _match_tail(label, claims, principal, scope, deny, steps, decided=True)
    decided = False
    for index, entry in enumerate(scope):
        tools = entry.get("tools") or []
        if entry.get("server") != "pupil-data" or tool not in tools:
            steps.append({
                "check": f"entry {index} tools",
                "value": tool,
                "against": tools,
                "result": "this entry does not list the tool",
                "decides": False,
            })
            continue
        constraints = entry.get("constraints") or {}
        failed = False
        for key, allowed in constraints.items():
            if key not in arguments:
                steps.append({
                    "check": key,
                    "value": "absent",
                    "against": allowed,
                    "result": "argument missing",
                    "decides": True,
                })
                failed = True
                break
            raw = arguments[key]
            if key == "path":
                got = posixpath.normpath(str(raw))
                allowed_n = [posixpath.normpath(str(item)) for item in allowed]
                ok = got in allowed_n
                steps.append({
                    "check": "path",
                    "value": f"{raw} → {got}",
                    "against": allowed_n,
                    "result": "equal" if ok else "not in the list",
                    "decides": not ok,
                })
            else:
                ok = str(raw) in {str(item) for item in allowed}
                steps.append({
                    "check": key,
                    "value": raw,
                    "against": list(allowed),
                    "result": "equal" if ok else "not in the list",
                    "decides": not ok,
                })
            if not ok:
                failed = True
                break
        if failed:
            continue
        for key, raw in arguments.items():
            if key in constraints:
                continue
            if tool == "search" and key == "query" and not str(raw).strip():
                steps.append({
                    "check": "query",
                    "value": raw,
                    "against": "must be non-empty (not a list on the mandate)",
                    "result": "empty query is refused",
                    "decides": True,
                })
                return _match_tail(label, claims, principal, scope, deny, steps, decided=True)
            steps.append({
                "check": key,
                "value": raw,
                "against": "not on this entry",
                "result": "not compared",
                "decides": False,
            })
        held = next((pat for pat in _STEP_UP if fnmatch(name, pat)), None)
        if held:
            steps.append({
                "check": "step-up",
                "value": name,
                "against": held,
                "result": "held for a person; nothing releases it",
                "decides": True,
            })
        else:
            steps.append({
                "check": f"entry {index}",
                "value": tool,
                "against": constraints,
                "result": "this entry allows the call",
                "decides": True,
            })
        decided = True
        break
    if not decided:
        steps.append({
            "check": "scope",
            "value": tool,
            "against": [entry.get("tools") for entry in scope],
            "result": "no entry allows it",
            "decides": True,
        })
    return _match_tail(label, claims, principal, scope, deny, steps, decided=True)


def _match_tail(label: str, claims: dict, principal: object, scope: list, deny: list, steps: list, *, decided: bool) -> dict:
    del decided
    steps.append({
        "check": "purpose",
        "value": "not an argument",
        "against": claims.get("purpose"),
        "result": "signed, not read",
        "decides": False,
    })
    steps.append({
        "check": "principal",
        "value": "not an argument",
        "against": principal,
        "result": "signed, not read",
        "decides": False,
    })
    return {"label": label, "deny": deny, "scope": scope, "steps": steps}


def _annotate(case: dict) -> dict:
    path, label = _mandate_file(case)
    claims = _read_jwt(path)
    return {
        **case,
        "match": explain_match(case["tool"], case["arguments"], claims, label),
        "sensitivity": touches(case["tool"], case["arguments"]),
    }


def _eval_cases(n: int) -> list[dict]:
    rows: list[dict] = []
    if n == 0:
        for name, tool, args in ev.VALID:
            rows.append({"name": name, "tool": tool, "arguments": args, "expect": "ALLOW"})
    for question, name, tool, args, code in ev.INVALID:
        if question == n:
            rows.append({"name": name, "tool": tool, "arguments": args, "expect": code})
    for question, name, tool, args, expect in ev.BUILD:
        if question == n:
            rows.append({"name": name, "tool": tool, "arguments": args, "expect": expect})
    return rows


def _open_cases(n: int) -> list[dict]:
    live = {"mandate": "live"}
    if n == 6:
        return [{
            **live,
            "name": "in-scope search returns the census row",
            "tool": "search",
            "arguments": {"query": PUPIL, "urn": SCHOOL},
            "today": "ALLOW. The decision says there is no clearance, and level 4 decides over level 1.",
        }]
    if n == 7:
        return [{
            **live,
            "name": "the only grant is the whole mandate",
            "tool": "search",
            "arguments": {"query": "Y11", "urn": SCHOOL},
            "today": "ALLOW. Nothing on the token is a narrower grant for a helper.",
        }]
    if n == 8:
        return [{
            "mandate": "counts",
            "name": "counts grouped by school and ethnicity",
            "tool": "aggregate",
            "arguments": {
                "table": CENSUS,
                "group_by": ["URN", "Ethnicity"],
                "measure": "FSMeligible",
            },
            "today": "ALLOW. group_by is not a constraint, and small cells are returned.",
        }]
    if n == 9:
        return [{
            **live,
            "name": "write under the default deny",
            "tool": "write",
            "arguments": {"path": "synthetic/synthetic_schools.csv"},
            "today": "DENIED_BY_RULE. STEP_UP is never reached, and nothing could release a hold.",
        }]
    if n == 10:
        return [{
            **live,
            "name": "a scoped search the sentence never mentioned",
            "tool": "search",
            "arguments": {"query": PUPIL, "urn": SCHOOL},
            "today": "ALLOW, because the JSON scope says so. The sentence is not an input.",
        }]
    if n == 11:
        return [
            {
                **live,
                "name": "first pupil search",
                "tool": "search",
                "arguments": {"query": PUPIL, "urn": SCHOOL, "limit": 1},
                "today": "ALLOW.",
            },
            {
                **live,
                "name": "second pupil search, same mandate",
                "tool": "search",
                "arguments": {"query": "Y11", "urn": SCHOOL, "limit": 1},
                "today": "ALLOW again. No budget was consumed by the first call.",
            },
        ]
    if n == 12:
        return [{
            **live,
            "name": "care lookup on a letters-shaped purpose",
            "tool": "search",
            "arguments": {"query": "InCare", "urn": SCHOOL},
            "today": "ALLOW. purpose is on the token and is not read.",
        }]
    if n == 13:
        return [{
            **live,
            "name": "call after the named person would have left",
            "tool": "search",
            "arguments": {"query": PUPIL, "urn": SCHOOL},
            "today": "ALLOW. The principal is a label, and there is no later change to read.",
        }]
    if n == 14:
        return [{
            **live,
            "name": "one allowed call, then look for a record",
            "tool": "search",
            "arguments": {"query": PUPIL, "urn": SCHOOL, "limit": 1},
            "today": "ALLOW, and gateway/state has no audit file of what was returned.",
        }]
    if n == 15:
        return [{
            **live,
            "name": "newsletter-wide search",
            "tool": "search",
            "arguments": {"query": PUPIL, "urn": SCHOOL},
            "today": "ALLOW with personal columns. pii.* did not match the tool.",
        }]
    if n == 16:
        return [{
            **live,
            "name": "a call that should have been logged",
            "tool": "search",
            "arguments": {"query": PUPIL, "urn": SCHOOL, "limit": 1},
            "today": "ALLOW, and nothing was appended for the person to read later.",
        }]
    return []


def _question(n: int) -> dict | None:
    for item in _META:
        if item[0] == n:
            number, state, asks, binds, missing, solves = item
            cases = _eval_cases(number) if state == "solved" else _open_cases(number)
            cases = [_annotate(case) for case in cases]
            return {
                "n": number,
                "state": state,
                "asks": asks,
                "binds": binds,
                "missing": missing,
                "solves": solves,
                "cases": cases,
            }
    return None


def catalog() -> list[dict]:
    return [row for n in range(17) if (row := _question(n)) is not None]


def _result_flags(columns: list[str], sensitivity: dict) -> list[dict]:
    known = {col["name"]: col for col in sensitivity.get("columns") or []}
    flags = []
    for name in columns:
        if name in known:
            flags.append(known[name])
            continue
        flags.append({"name": name, "level": None, "label": "not a source column"})
    return flags


def _summarize(status: int, payload: dict) -> dict:
    decision = payload.get("decision") or {}
    result = payload.get("result")
    columns: list[str] = []
    count = None
    if isinstance(result, list):
        count = len(result)
        if result and isinstance(result[0], dict):
            columns = list(result[0])
    elif isinstance(result, dict):
        columns = list(result)
    return {
        "status": status,
        "got": decision.get("decision"),
        "reason": decision.get("reason_code"),
        "count": count,
        "columns": columns,
    }


def _sign(which: str, tool: str, arguments: dict) -> dict:
    if which == "counts":
        key = PACK / "agent.pem"
        mandate = (PACK / "counts.jwt").read_text().strip()
    else:
        key = STATE / "agent.pem"
        mandate = (STATE / "mandate.jwt").read_text().strip()
    return sign_request(
        priv_from_pem(key.read_bytes()),
        server=SERVER,
        tool=tool,
        arguments=arguments,
        mandate=mandate,
    )


def _claims() -> dict:
    token = (STATE / "mandate.jwt").read_text().strip()
    return json.loads(b64u_decode(token.split(".")[1]))


def ensure_local_mandate() -> None:
    """Replace mandate.jwt when it has expired. The cli default lifetime is two hours."""
    path = STATE / "mandate.jwt"
    if path.is_file():
        exp = _claims().get("exp", 0)
        if exp > time.time() + 60:
            return
    token, _idx = issue_mandate(
        STATE,
        load_agent_pub(STATE / "agent.pem"),
        scope=DEFAULT_SCOPE,
        deny=DEFAULT_DENY,
        ttl=3 * 86400,
        purpose="Pupil-data lookups for school SCH01",
        principal="officer:jsmith",
        org="school:SCH01",
    )
    path.write_text(token)


def _run_eval(question: dict, post) -> dict:
    def one(body: dict) -> tuple[int, dict]:
        status, payload = post(body)
        return status, payload if isinstance(payload, dict) else {}

    results = [(ok, line) for ok, line in ev.run_cases(PACK, one) if line.startswith(f"Q{question['n']} ")]
    if len(results) != len(question["cases"]):
        return {
            **question,
            "error": f"eval returned {len(results)} lines for {len(question['cases'])} cases",
        }
    cases = []
    for case, (ok, line) in zip(question["cases"], results, strict=True):
        cases.append({**case, "ok": ok, "report": line})
    passed = sum(1 for case in cases if case.get("ok"))
    return {**question, "cases": cases, "passed": passed, "total": len(cases)}


def _run_open(question: dict, post) -> dict:
    ensure_local_mandate()
    claims = _claims() if (STATE / "mandate.jwt").is_file() else {}
    cases = []
    for case in question["cases"]:
        signed = _sign(case.get("mandate", "live"), case["tool"], case["arguments"])
        status, payload = post(signed)
        shown = _summarize(status, payload if isinstance(payload, dict) else {})
        shown["result_flags"] = _result_flags(shown.get("columns") or [], case.get("sensitivity") or {})
        extra = {}
        if question["n"] in {12, 13}:
            extra["ignored_claim"] = {
                "purpose": claims.get("purpose"),
                "principal": (claims.get("delegator") or {}).get("principal"),
            }
        if question["n"] in {14, 16}:
            extra["audit_file"] = (STATE / "audit.jsonl").is_file()
        cases.append({**case, **shown, **extra})
    return {**question, "cases": cases, "passed": None, "total": len(cases)}


def execute(n: int, post) -> dict:
    question = _question(n)
    if question is None:
        return {"error": "no such question"}
    if question["state"] == "solved":
        if not PACK.is_dir():
            return {**question, "error": "eval_pack is missing"}
        return _run_eval(question, post)
    if not (STATE / "agent.pem").is_file():
        return {**question, "error": "team key is missing"}
    return _run_open(question, post)
