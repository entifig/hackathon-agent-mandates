"""HTTP wrapper around the gateway pipeline.

POST /tools/call  {server, tool, arguments, mandate, nonce, ts, sig}
  -> verify mandate + proof of possession (gateway/lib/gateway_verify.py)
  -> ALLOW: forward to the MCP server, DENY: 403, STEP_UP: 202
  -> a mandate with a `budget` claim (gateway/lib/budget.py): the request is charged before forwarding and the
     result is checked before release; over budget is DENY BUDGET_EXHAUSTED, 403, and nothing is returned
  -> a delegated child mandate (question 7, gateway/lib/delegation.py) is charged to its own budget and its parent's
  -> `aggregate`, any mandate (gateway/lib/disclosure.py): forwarded grouped by pupil, summed back to the groups asked
     for, small counts suppressed and the rest rounded before release, with a `disclosure` note

GATEWAY_DEMO=1 turns on the /demo walkthrough routes (404 otherwise). They hold the issuer key and an agent key, so
anyone who can reach them can mint and revoke mandates: a deployed gateway runs with GATEWAY_DEMO unset or 0.

Seen nonces (nonces.jsonl) and the budget ledger live in GATEWAY_STATE_DIR. If that dir is not writable, /healthcheck
answers 503 with the reason so a bad deploy fails `docker compose up --wait` (calls are refused NONCE_UNAVAILABLE).
Mandates without a budget never touch the ledger.
"""

import contextlib
import dataclasses
import json
import logging
import os
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi import Request as HTTPRequest
from fastapi.responses import JSONResponse
from fastmcp import Client
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gateway.cli import sign_request
from gateway.lib import (
    audit,  # AUDIT(q14/q16)
    disclosure,  # [q8]
)
from gateway.lib.budget import ID_BOUNDED_TOOLS, Budget, Ledger, LedgerUnavailable, chain_budgets, pupil_ids
from gateway.lib.common import generate_keypair, pub_to_jwk
from gateway.lib.gateway_verify import MAX_TS, Decision, Gateway, Request, normalised_arguments
from gateway.lib.nonce_store import NonceStore
from gateway.lib.trust_registry import TrustedList

STATE_DIR = Path(os.environ.get("GATEWAY_STATE_DIR", "gateway/state"))
# name -> URL (or an in-process FastMCP instance in tests); fastmcp.Client accepts both
MCP_SERVERS: dict[str, object] = dict(
    kv.split("=", 1) for kv in os.environ.get("MCP_SERVERS", "pupil-data=http://backend:8080/mcp/").split(",")
)
# the /demo routes answer only when this is "1" (off by default, also in docker-compose: see README to turn it on)
DEMO = os.environ.get("GATEWAY_DEMO") == "1"
state: dict = {}
log = logging.getLogger("gateway")


class CallBody(BaseModel):
    server: str
    tool: str
    arguments: dict
    mandate: str
    nonce: str
    ts: int = Field(ge=0, le=MAX_TS)
    sig: str


def load_state(state_dir: Path) -> None:
    registry = TrustedList(json.loads((state_dir / "trusted_list.json").read_text()))
    # [q11 replay] seen nonces persist in the state dir, so a restart does not reopen the replay window
    # shortcut: one process; share the nonce store (and the ledger) before running more than one replica or worker
    state["gateway"] = Gateway(registry, status_lists={}, nonces=NonceStore.load(state_dir / "nonces.jsonl"))
    state["status_uri"] = json.loads((state_dir / "status_list.json").read_text())["uri"]
    state["dir"] = state_dir
    # run budgets survive a restart: usage is re-read here, so restarting does not hand out fresh budgets
    state["ledger"] = Ledger.load(state_dir / "budget_ledger.json")
    state["state_dir_error"] = state_dir_unwritable(state_dir)
    if state["state_dir_error"]:
        log.error("state dir not writable: %s; every call is refused NONCE_UNAVAILABLE", state["state_dir_error"])
        state["ledger"].error = state["ledger"].error or state["state_dir_error"]


def state_dir_unwritable(state_dir: Path) -> str | None:
    """Why the budget ledger cannot be saved in `state_dir` (a probe file is created and removed), or None."""
    try:
        fd, probe = tempfile.mkstemp(dir=state_dir, prefix=".write_probe.")
        os.close(fd)
        Path(probe).unlink()
    except OSError as e:
        return f"GATEWAY_STATE_DIR {state_dir} is not writable ({type(e).__name__}: {e.strerror or e})"
    return None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    load_state(STATE_DIR)
    state["audit_error"] = audit.startup_check(STATE_DIR)  # AUDIT(q14/q16): unwritable log -> /healthcheck 503
    yield


app = FastAPI(title="mandate gateway", lifespan=lifespan)
app.add_middleware(audit.ClientAddress)  # AUDIT(q14/q16): source address for the audit entry


@app.middleware("http")
async def no_500(request: HTTPRequest, call_next):
    """Anything the pipeline did not turn into a decision is still refused as JSON, never a 500 with a traceback."""
    try:
        return await call_next(request)
    except Exception:
        log.exception("unhandled error on %s", request.url.path)
        return JSONResponse(
            {"decision": {"decision": "DENY", "reason_code": "GATEWAY_ERROR"}, "error": "request not processed"},
            status_code=400,
        )


@app.get("/healthcheck")
def healthcheck():
    # 503 fails `docker compose up --wait`: a gateway that cannot record nonces refuses every call
    gateway = state.get("gateway")
    if reason := state.get("state_dir_error") or (gateway and gateway.nonces.error):
        return JSONResponse({"status": "error", "reason": reason}, status_code=503)
    if state.get("audit_error"):  # AUDIT(q14/q16): fail visibly, the gateway would deny every call
        return JSONResponse({"status": "error", "reason": state["audit_error"]}, status_code=503)
    return {"status": "ok"}


@app.get("/describe")
async def describe() -> dict:
    """Discovery for bring-your-own agents: what can be called and how a request must be signed."""
    servers = {}
    for name, target in MCP_SERVERS.items():
        async with Client(target) as client:
            servers[name] = [
                {"name": t.name, "description": t.description, "input_schema": t.input_schema}
                for t in await client.list_tools()
            ]
    priv, pub = generate_keypair()
    example = sign_request(
        priv,
        server="pupil-data",
        tool="search",
        arguments={"query": "P0004", "urn": "SCH01"},
        mandate="<compact mandate JWT>",
    )
    return {
        "servers": servers,
        "step_up_patterns": state["gateway"].step_up,
        "signing": {
            "alg": "Ed25519 by the key in the mandate's cnf.jwk; sig is base64url without padding",
            "signing_input": "canonical JSON (sorted keys, separators ',' and ':', ensure_ascii=False) of "
            "{server, tool, arguments, mandate_hash, nonce, ts}",
            "mandate_hash": "'sha256:' + hex sha256 of the compact mandate JWT",
            "ts": "unix seconds, within 300s of gateway time; nonce must be unique per request",
            "example": {
                "agent_jwk": pub_to_jwk(pub),
                "signing_input": Request(**example).signing_input().decode(),
                "request": example,
            },
        },
    }


@app.post("/tools/call")
@audit.audited(state)  # AUDIT(q14/q16): answers gateway.audit, logs every call before its response goes out
async def tools_call(body: CallBody):
    gateway: Gateway = state["gateway"]
    # re-read the published status list each request so `cli revoke` applies without a restart
    gateway.status_lists[state["status_uri"]] = (state["dir"] / "status_list.jwt").read_text().strip()

    decision, claims = gateway.decide_with_claims(Request(**body.model_dump()))
    record = decision.to_dict()
    # audit trail: written by @audit.audited (gateway/lib/audit.py) after this returns, before the response

    if decision.decision == "DENY":
        return JSONResponse({"decision": record}, status_code=403)
    if decision.decision == "STEP_UP":  # not forwarded, so it costs no budget
        return JSONResponse({"decision": record}, status_code=202)

    # [q11 path] forward exactly the arguments the scope check approved (the signature covered the original spelling)
    body = body.model_copy(update={"arguments": normalised_arguments(body.arguments)})
    target = MCP_SERVERS.get(body.server)
    if target is None:
        raise HTTPException(404, f"no MCP server configured for {body.server!r}")
    if body.tool == disclosure.TOOL:  # [q8] every aggregate result is checked; a budgeted mandate never gets here
        return await _forward_aggregate(target, body, decision, disclosure.parse_disclosure(claims))
    budgets = chain_budgets(claims)  # validated in decide; a delegated child: its own and its parent's
    if not budgets:
        return await _forward(target, body, record)
    ledger: Ledger = state["ledger"]
    # held across forward and charge, so two concurrent calls cannot both fit into the last of the budget.
    # Several keys (a child and its parent) are locked in one global order, so two calls cannot deadlock.
    async with contextlib.AsyncExitStack() as held:
        for key in sorted({b.key for b in budgets}):
            await held.enter_async_context(ledger.lock(key))
        return await _forward_budgeted(target, body, decision, budgets, ledger)


async def call_upstream(target, body: CallBody) -> tuple[bool, object]:
    """(ok, result data or error text)."""
    try:
        async with Client(target) as client:
            return True, (await client.call_tool(body.tool, body.arguments)).data
    except ToolError as e:
        return False, str(e)


async def _forward(target, body: CallBody, record: dict):
    ok, payload = await call_upstream(target, body)
    if ok:
        return {"decision": record, "result": payload}
    return JSONResponse({"decision": record, "error": payload}, status_code=502)


def _whose(budget: Budget) -> str:
    return "" if budget.label == "mandate" else f"{budget.label} mandate's budget: "  # [q7] which one in a chain


async def _forward_aggregate(target, body: CallBody, decision: Decision, policy: disclosure.Policy):
    """[q8] Ask for the counts per pupil, release the counts per group with small ones suppressed."""
    upstream = body.model_copy(update={"arguments": disclosure.upstream_arguments(body.arguments)})
    ok, payload = await call_upstream(target, upstream)
    if not ok:
        return JSONResponse({"decision": decision.to_dict(), "error": payload}, status_code=502)
    try:
        result, note = disclosure.protect(body.arguments, payload, policy)
    except disclosure.UncheckableResult as e:
        refusal = dataclasses.replace(decision, decision="DENY", reason_code="AGGREGATE_UNCHECKABLE", detail=str(e))
        return JSONResponse({"decision": refusal.to_dict()}, status_code=403)
    detail = f"min {note['min_count']} pupils, rounded to {note['round_to']}, {note['suppressed']} numbers suppressed"
    record = dataclasses.replace(decision, detail=detail).to_dict()
    return {"decision": record, "result": result, "disclosure": note}


def _pupils_detail(ledger: Ledger, budget: Budget, what: str) -> str:
    used = len(ledger.usage(budget.key).pupils)
    return f"{_whose(budget)}pupils: {what}; {used} of {budget.pupils} distinct pupils used"


def _reports(ledger: Ledger, budgets: list[Budget]) -> dict:
    """`budget`: the first budget's usage (the mandate's own, as before). A delegated child charged to more than one
    budget also gets `budgets`, each labelled child or parent."""
    out = {"budget": ledger.report(budgets[0])}
    if len(budgets) > 1:
        out["budgets"] = [{"of": b.label, **ledger.report(b)} for b in budgets]
    return out


def _admit(tool: str, named: set[str], budgets: list[Budget], ledger: Ledger) -> tuple[str, str] | None:
    """Charge a budgeted request before forwarding, or say why not as (reason_code, detail). Depends only on the
    arguments and the ledger, never on the data, so a refusal is not an oracle (budget.py). A delegated child's call
    must fit every budget in its chain, and is charged to all of them."""
    try:
        ledger.check_available()
        for budget in budgets:
            if not ledger.calls_left(budget):
                return "BUDGET_EXHAUSTED", f"{_whose(budget)}calls: all {budget.calls} used, not forwarded"
            if not ledger.fits(budget, named):
                new = len(ledger.new_pupils(budget, named))
                return "BUDGET_EXHAUSTED", _pupils_detail(
                    ledger, budget, f"the {new} new pupil(s) named do not fit, not forwarded"
                )
            if tool not in ID_BOUNDED_TOOLS and ledger.full(budget):
                only = f"budget full, only {sorted(ID_BOUNDED_TOOLS)} for pupils already seen; not forwarded"
                return "BUDGET_EXHAUSTED", _pupils_detail(ledger, budget, only)
        ledger.charge(budgets, named, calls=1)  # persisted before forwarding: an error or a withheld result still costs
    except LedgerUnavailable as e:
        return "BUDGET_UNAVAILABLE", str(e)
    return None


async def _forward_budgeted(target, body: CallBody, decision: Decision, budgets: list[Budget], ledger: Ledger):
    """Charge the request, forward, then check the result (the backstop)."""

    def refuse(code: str, detail: str) -> JSONResponse:
        refusal = dataclasses.replace(decision, decision="DENY", reason_code=code, detail=detail)
        return JSONResponse({"decision": refusal.to_dict(), **_reports(ledger, budgets)}, status_code=403)

    # pupils the request names are charged whether or not they are found
    if refusal := _admit(body.tool, pupil_ids(body.arguments), budgets, ledger):
        return refuse(*refusal)

    ok, payload = await call_upstream(target, body)
    if ok and body.tool == "search":
        if not isinstance(payload, list):
            return refuse("BUDGET_RESULT", "search result could not be checked")
        # upstream search is a substring match: release only the rows of the one pupil named (and charged)
        named = body.arguments["query"].upper()
        payload = [
            row
            for row in payload
            if isinstance(row, dict) and str(row.get("Psuedo ID", "")).upper() == named and pupil_ids(row) <= {named}
        ]
    # backstop for tools that list pupils without naming them (roster, get). An upstream error is upstream data too.
    returned = pupil_ids(payload)
    if over := next((b for b in budgets if not ledger.fits(b, returned)), None):
        # says nothing about how many pupils the withheld result held: that would be a count oracle
        withheld = "result withheld, it does not fit; its pupils were not charged"
        return refuse("BUDGET_EXHAUSTED", _pupils_detail(ledger, over, withheld))
    try:
        ledger.charge(budgets, returned)
    except LedgerUnavailable as e:
        return refuse("BUDGET_UNAVAILABLE", str(e))
    record = decision.to_dict()
    if ok:
        return {"decision": record, "result": payload, **_reports(ledger, budgets)}
    return JSONResponse({"decision": record, "error": payload, **_reports(ledger, budgets)}, status_code=502)


def _demo_enabled() -> None:
    if not DEMO:
        raise HTTPException(404, "Not Found")


from gateway.demo import router as demo_router  # noqa: E402  (demo imports main lazily)

app.include_router(demo_router, dependencies=[Depends(_demo_enabled)])
