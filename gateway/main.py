"""HTTP wrapper around the gateway pipeline.

POST /tools/call  {server, tool, arguments, mandate, nonce, ts, sig}
  -> verify mandate + proof of possession (gateway/lib/gateway_verify.py)
  -> ALLOW: forward to the MCP server, DENY: 403, STEP_UP: 202
"""

import json
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastmcp import Client
from fastmcp.exceptions import ToolError
from pydantic import BaseModel

from gateway.cli import sign_request
from gateway.lib.common import generate_keypair, pub_to_jwk
from gateway.lib.gateway_verify import (
    IDENTIFIERS,
    PRIVATE_LEVEL,
    PRIVATE_ROLES,
    SMALL_COUNT,
    Gateway,
    Request,
    request_levels,
    result_levels,
    round_counts,
    sensitivity_maps,
    sensitivity_record,
)
from gateway.lib.trust_registry import TrustedList

STATE_DIR = Path(os.environ.get("GATEWAY_STATE_DIR", "gateway/state"))
_CLASSIFICATION_CANDIDATES = [
    os.environ.get("CLASSIFICATION_MANIFEST", ""),
    "gateway/manifest.json",
    "mcp_server/data/synthetic/synthetic_manifest.json",
]
# name -> URL (or an in-process FastMCP instance in tests); fastmcp.Client accepts both
MCP_SERVERS: dict[str, object] = dict(
    kv.split("=", 1) for kv in os.environ.get("MCP_SERVERS", "pupil-data=http://backend:8080/mcp/").split(",")
)
state: dict = {}


class CallBody(BaseModel):
    server: str
    tool: str
    arguments: dict
    mandate: str
    nonce: str
    ts: int
    sig: str


def load_state(state_dir: Path) -> None:
    registry = TrustedList(json.loads((state_dir / "trusted_list.json").read_text()))
    # accepted nonces are kept in the state dir, so a restart or a reload does not reopen the replay window.
    # shortcut: one file for one process; share it before multi-replica
    state["gateway"] = Gateway(registry, status_lists={}, nonce_log=state_dir / "seen_nonces.log")
    state["status_uri"] = json.loads((state_dir / "status_list.json").read_text())["uri"]
    state["dir"] = state_dir
    # Q6 labels live with the data; the gateway enforces them against results (deny on max)
    load_labels()
    state["small_count"] = small_count_setting()
    state["private_roles"] = private_roles_setting()


def small_count_setting() -> int:
    value = int(os.environ.get("GATEWAY_SMALL_COUNT", SMALL_COUNT))
    if value < 1:
        msg = f"GATEWAY_SMALL_COUNT must be at least 1, got {value}"
        raise ValueError(msg)
    return value


def private_roles_setting() -> frozenset[str]:
    raw = os.environ.get("GATEWAY_PRIVATE_ROLES")
    roles = PRIVATE_ROLES if raw is None else frozenset(filter(None, map(str.strip, raw.split(","))))
    if not roles:
        msg = "GATEWAY_PRIVATE_ROLES must name at least one role"
        raise ValueError(msg)
    return roles


def load_labels() -> None:
    """Read the first manifest found. Called on each forwarded call too, so a changed label needs no restart."""
    manifest = next((Path(p) for p in _CLASSIFICATION_CANDIDATES if p and Path(p).is_file()), None)
    if manifest is None:
        msg = f"no classification manifest under {_CLASSIFICATION_CANDIDATES}"
        raise FileNotFoundError(msg)
    classification = json.loads(manifest.read_text())["classification"]
    state["columns"], state["tables"] = sensitivity_maps(classification)
    state["table_columns"] = classification["columns"]
    state["max_level"] = max(map(int, classification["levels"]))
    state["level_names"] = {int(level): name for level, name in classification["levels"].items()}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    load_state(STATE_DIR)
    yield


app = FastAPI(title="mandate gateway", lifespan=lifespan)


@app.get("/healthcheck")
def healthcheck() -> dict:
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
        "disclosure": {
            "small_count": state["small_count"],
            "rule": "aggregate totals and counts are rounded to the nearest multiple of small_count",
            "refused_in_aggregates": sorted(IDENTIFIERS),
        },
        "private_data": {
            "level": PRIVATE_LEVEL,
            "roles": sorted(state["private_roles"]),
            "rule": "a call that can return this level needs the clearance and one of these roles in the mandate's "
            "role claim; if the mandate has a role_exp, the role stops opening this level at that time",
        },
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


def refuse_on_labels(decision, levels: dict[str, int], subject: str) -> JSONResponse | None:
    """Record the labels on the decision. A 403 if they are above the clearance or need a role it lacks."""
    decision.sensitivity = sensitivity_record(levels, state["level_names"], decision.clearance)
    level = decision.sensitivity["level"]
    decided_by = ", ".join(decision.sensitivity["decided_by"])
    if decision.clearance is not None and level > decision.clearance:
        decision.decision, decision.reason_code = "DENY", "CLEARANCE_TOO_LOW"
        decision.detail = f"{subject} sensitivity {level} above clearance {decision.clearance} ({decided_by})"
        return JSONResponse({"decision": decision.to_dict()}, status_code=403)
    if level >= PRIVATE_LEVEL and decision.role not in state["private_roles"]:
        decision.decision, decision.reason_code = "DENY", "ROLE_REQUIRED"
        roles = ", ".join(sorted(state["private_roles"]))
        held = f"the role {decision.role}" if decision.role else "no role"
        decision.detail = f"{subject} sensitivity {level} ({decided_by}), open to {roles}; the mandate has {held}"
        return JSONResponse({"decision": decision.to_dict()}, status_code=403)
    # the role can end before the mandate does; the rest of the mandate keeps working below PRIVATE_LEVEL
    if level >= PRIVATE_LEVEL and decision.role_exp is not None and time.time() >= decision.role_exp:
        decision.decision, decision.reason_code = "DENY", "ROLE_EXPIRED"
        decision.detail = (
            f"{subject} sensitivity {level} ({decided_by}); the role {decision.role} ended at {decision.role_exp}"
        )
        return JSONResponse({"decision": decision.to_dict()}, status_code=403)
    return None


@app.post("/tools/call")
async def tools_call(body: CallBody):
    gateway: Gateway = state["gateway"]
    # re-read the published status list each request so `cli revoke` applies without a restart
    gateway.status_lists[state["status_uri"]] = (state["dir"] / "status_list.jwt").read_text().strip()

    decision = gateway.decide(Request(**body.model_dump()))
    record = decision.to_dict()
    # no audit trail: teams write their own decision record here (e.g. state["dir"] / "audit.jsonl")

    if decision.decision == "DENY":
        return JSONResponse({"decision": record}, status_code=403)
    if decision.decision == "STEP_UP":
        return JSONResponse({"decision": record}, status_code=202)

    target = MCP_SERVERS.get(body.server)
    if target is None:
        raise HTTPException(404, f"no MCP server configured for {body.server!r}")
    # Q6 deny on max, decided before the call from everything the tool can return. A refusal that waited for
    # the result would tell the agent whether a row matched: 403 if one did, 200 [] if none.
    load_labels()
    levels = request_levels(
        body.tool,
        body.arguments,
        state["table_columns"],
        state["columns"],
        state["tables"],
        state["max_level"],
    )
    refusal = refuse_on_labels(decision, levels, "the call can return")
    if refusal is not None:
        return refusal
    try:
        async with Client(target) as client:
            result = await client.call_tool(body.tool, body.arguments)
    except ToolError as e:
        return JSONResponse({"decision": decision.to_dict(), "error": str(e)}, status_code=502)
    # second layer: the labels on what actually came back, in case the result carries a key the shape did not
    levels |= result_levels(
        body.tool, body.arguments, result.data, state["columns"], state["tables"], state["max_level"]
    )
    refusal = refuse_on_labels(decision, levels, "the result reaches")
    if refusal is not None:
        return refusal
    data = result.data
    if body.tool == "aggregate":
        data = round_counts(data, state["small_count"])
        decision.disclosure = {"rounded_to": state["small_count"]}
    return {"decision": decision.to_dict(), "result": data}


from gateway.demo import admin_router as demo_admin_router  # noqa: E402  (demo imports main lazily)
from gateway.demo import router as demo_router  # noqa: E402

app.include_router(demo_router)
# The walkthrough's write routes sign a mandate for any school with the issuer key, revoke any mandate and sign
# calls with a key the gateway holds, for whoever asks. They exist for the local demo UI only: off unless asked for.
if os.environ.get("GATEWAY_DEMO") == "1":
    app.include_router(demo_admin_router)
