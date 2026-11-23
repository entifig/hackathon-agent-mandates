"""HTTP wrapper around the gateway pipeline.

POST /tools/call  {server, tool, arguments, mandate, nonce, ts, sig}
  -> verify mandate + proof of possession (gateway/lib/gateway_verify.py)
  -> ALLOW: forward to the MCP server, DENY: 403, STEP_UP: 202
"""

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastmcp import Client
from fastmcp.exceptions import ToolError
from pydantic import BaseModel

from gateway.cli import sign_request
from gateway.lib.common import generate_keypair, pub_to_jwk
from gateway.lib.gateway_verify import Gateway, Request, result_max_level, sensitivity_maps
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
    # shortcut: nonce replay set lives in Gateway._seen_nonces, in-memory per process; share it before multi-replica
    state["gateway"] = Gateway(registry, status_lists={})
    state["status_uri"] = json.loads((state_dir / "status_list.json").read_text())["uri"]
    state["dir"] = state_dir
    # Q6 labels live with the data; the gateway enforces them against results (deny on max)
    manifest = next((Path(p) for p in _CLASSIFICATION_CANDIDATES if p and Path(p).is_file()), None)
    if manifest is None:
        msg = f"no classification manifest under {_CLASSIFICATION_CANDIDATES}"
        raise FileNotFoundError(msg)
    classification = json.loads(manifest.read_text())["classification"]
    state["columns"], state["tables"] = sensitivity_maps(classification)
    state["max_level"] = max(map(int, classification["levels"]))


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
    try:
        async with Client(target) as client:
            result = await client.call_tool(body.tool, body.arguments)
    except ToolError as e:
        return JSONResponse({"decision": record, "error": str(e)}, status_code=502)
    # Q6 deny on max: the most sensitive column in the result decides, against the mandate's clearance
    level = result_max_level(
        body.tool, body.arguments, result.data, state["columns"], state["tables"], state["max_level"]
    )
    if decision.clearance is not None and level > decision.clearance:
        decision.decision, decision.reason_code = "DENY", "CLEARANCE_TOO_LOW"
        decision.detail = f"result reaches sensitivity {level} above clearance {decision.clearance}"
        return JSONResponse({"decision": decision.to_dict()}, status_code=403)
    return {"decision": record, "result": result.data}


from gateway.demo import router as demo_router  # noqa: E402  (demo imports main lazily)

app.include_router(demo_router)
