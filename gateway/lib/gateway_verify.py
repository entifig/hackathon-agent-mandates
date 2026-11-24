"""Gateway verification pipeline.

    receive (request, mandate)
      -> verify mandate: issuer accredited / signature / time / revocation
      -> verify proof of possession (request signed by cnf key, fresh nonce and ts; nonces persist: nonce_store.py)
      -> check request against scope, deny and constraints
      -> (budgeted mandates) only requests whose cost is countable; main.tools_call charges the budget (budget.py)
      -> decision record {ALLOW | DENY | STEP_UP, reason_code, ...}

Reason codes are stable strings so the audit log and Day 2 scorecard can
count them. Order of checks is deliberate: cheapest and most definitive first.
"""
from __future__ import annotations

import fnmatch
import math
import posixpath
import time
from dataclasses import asdict, dataclass

import jwt

from .budget import BudgetInvalid, parse_budget, request_refusal
from .common import canonical, jwk_thumbprint, jwk_to_pub, pub_to_pem, sha256_hex, verify_bytes
from .nonce_store import MAX_NONCE_LEN, TS_WINDOW, NonceStore, NonceStoreUnavailable
from .status_list import is_revoked

POLICY_VERSION = "2026-11-18.1"
CLOCK_SKEW = 30
# Most rows one call may ask for (the MCP server's own default).
# Per call only: many small calls still add up (question 11). A mandate's `budget` claim (budget.py) bounds the run.
MAX_ROWS = 100
# Arguments are hashed and matched before anything else reads them: bound them so that cannot crash (RecursionError).
MAX_ARGS_DEPTH = 8
MAX_ARGS_BYTES = 16 * 1024
MAX_TS = 2**41  # unix seconds; far beyond any real clock, far below anything that overflows a float


class Reject(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


@dataclass
class Decision:
    decision: str            # ALLOW | DENY | STEP_UP
    reason_code: str
    policy_version: str
    mandate_hash: str
    request_hash: str
    agent_id: str | None
    ts: float
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Request:
    """What the agent sends to the gateway for a tools/call."""
    server: str
    tool: str
    arguments: dict
    mandate: str             # compact JWT
    nonce: str
    ts: int
    sig: str                 # Ed25519 over canonical(signing_input()) by cnf key

    def signing_input(self) -> bytes:
        return canonical({
            "server": self.server, "tool": self.tool, "arguments": self.arguments,
            "mandate_hash": sha256_hex(self.mandate.encode()), "nonce": self.nonce, "ts": self.ts,
        })


# ---------------------------------------------------------------- mandate

def _number(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def _strings(value) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


def _scope_entry(entry) -> bool:
    constraints = entry.get("constraints", {}) if isinstance(entry, dict) else None
    return (
        isinstance(entry, dict)
        and isinstance(entry.get("server"), str)
        and _strings(entry.get("tools"))
        and isinstance(constraints, dict)
        and all(isinstance(v, list) for v in constraints.values())
    )


def check_claims_shape(claims: dict) -> None:
    """Every claim the gateway reads has the type it is read as. A signed mandate can still be malformed (an issuer's
    mistake, or a key that signs anything): refuse it rather than crash on it."""
    status = claims.get("status")
    sl = status.get("status_list") if isinstance(status, dict) else None
    cnf = claims.get("cnf")
    checks = {
        "jti": isinstance(claims.get("jti"), str),
        "exp": _number(claims.get("exp")),
        "nbf": "nbf" not in claims or _number(claims["nbf"]),
        "status": isinstance(sl, dict) and isinstance(sl.get("uri"), str)
        and type(sl.get("idx")) is int and sl["idx"] >= 0,
        "cnf": isinstance(cnf, dict) and isinstance(cnf.get("jwk"), dict),
        "agent_id": isinstance(claims.get("agent_id"), str),
        "scope": isinstance(claims.get("scope"), list) and all(map(_scope_entry, claims["scope"])),
        "deny": _strings(claims.get("deny")),
    }
    if bad := [name for name, ok in checks.items() if not ok]:
        raise Reject("MANDATE_MALFORMED", f"bad or missing claims {bad}")


def verify_mandate(token: str, registry, status_lists: dict[str, str]) -> dict:
    """Returns the verified claims. Raises Reject."""
    try:
        hdr = jwt.get_unverified_header(token)
        unverified = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError as e:
        raise Reject("MANDATE_MALFORMED", str(e))
    if hdr.get("typ") != "mandate+jwt":
        raise Reject("WRONG_TOKEN_TYPE", str(hdr.get("typ")))
    iss, kid = unverified.get("iss"), hdr.get("kid", "")
    if not isinstance(iss, str) or not isinstance(kid, str):
        raise Reject("MANDATE_MALFORMED", "iss and kid must be strings")

    pub = registry.issuer_key(iss, kid)
    if pub is None:
        raise Reject("ISSUER_NOT_ACCREDITED", iss)
    try:
        claims = jwt.decode(token, pub_to_pem(pub), algorithms=["EdDSA"],
                            options={"verify_exp": False, "verify_nbf": False, "require": ["exp", "iss", "jti"]})
    except jwt.PyJWTError as e:
        raise Reject("SIG_INVALID", str(e))
    check_claims_shape(claims)

    now = time.time()
    if claims.get("nbf", 0) > now + CLOCK_SKEW:
        raise Reject("NOT_YET_VALID", claims["jti"])
    if claims["exp"] < now - CLOCK_SKEW:
        raise Reject("EXPIRED", claims["jti"])

    sl = claims["status"]["status_list"]
    sl_jwt = status_lists.get(sl["uri"])
    if sl_jwt is None:
        raise Reject("STATUS_UNAVAILABLE", sl["uri"])     # fail closed
    try:
        revoked = is_revoked(sl_jwt, sl["idx"], pub, sl["uri"])
    except Exception as e:  # noqa: BLE001  (a list the gateway cannot read is no list: fail closed)
        raise Reject("STATUS_UNAVAILABLE", str(e))
    if revoked:
        raise Reject("REVOKED", claims["jti"])
    return claims


def check_arguments_size(arguments) -> None:
    """Refuse arguments nested deeper than MAX_ARGS_DEPTH or longer than MAX_ARGS_BYTES. Iterative, so it cannot
    hit the recursion limit itself; after it, hashing and matching the arguments are safe."""
    stack = [(arguments, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict | list):
            if depth > MAX_ARGS_DEPTH:
                raise Reject("ARGS_TOO_LARGE", f"nested deeper than {MAX_ARGS_DEPTH}")
            stack.extend((child, depth + 1) for child in (item.values() if isinstance(item, dict) else item))
    if len(canonical(arguments)) > MAX_ARGS_BYTES:
        raise Reject("ARGS_TOO_LARGE", f"more than {MAX_ARGS_BYTES} bytes")


# ---------------------------------------------------------------- scope

def normalised_arguments(arguments: dict) -> dict:
    """[q11 path] The arguments as the scope check reads them, and as main.tools_call forwards them: `path` in one
    spelling ("./a//b" and "a/x/../b" are "a/b"), so the gateway and the MCP server cannot disagree about which file.
    shortcut: lexical only, agrees with the MCP server's resolve() while the data dir has no symlinks"""
    if isinstance(arguments.get("path"), str):
        return {**arguments, "path": posixpath.normpath(arguments["path"])}
    return arguments


def check_request(req: Request, scope: list[dict], deny: list[str], step_up_patterns: list[str]) -> tuple[str, str, str]:
    name = f"{req.server}.{req.tool}"
    for pat in deny:
        if fnmatch.fnmatch(name, pat):
            return "DENY", "DENIED_BY_RULE", pat
    # Each entry is a whole grant: the call is allowed if any one entry accepts every argument it constrains,
    # so a request cannot take urn from one entry and path from another.
    refused = None  # the first matching entry's reason, reported when no entry accepts the call
    arguments = normalised_arguments(req.arguments)  # [q11 path] exactly what will be forwarded
    for entry in scope:
        if entry["server"] != req.server or req.tool not in entry["tools"]:
            continue
        for k, allowed in entry.get("constraints", {}).items():
            if k not in arguments:
                refused = refused or ("DENY", "CONSTRAINT_MISSING", k)
                break
            # a normalised path still starting with ".." or "/" cannot equal an allowed relative path: denied
            value = arguments[k]
            if str(value) not in set(map(str, allowed)):
                refused = refused or ("DENY", "CONSTRAINT_VIOLATED", f"{k}={req.arguments[k]!r}")
                break
        else:
            limit = req.arguments.get("limit", MAX_ROWS)
            if type(limit) is not int or not 0 <= limit <= MAX_ROWS:
                return "DENY", "TOO_MUCH", f"limit={limit!r}, at most {MAX_ROWS}"
            if req.tool == "search" and not str(req.arguments.get("query", "")).strip():
                return "DENY", "TOO_MUCH", "empty query matches every row"
            for pat in step_up_patterns:
                if fnmatch.fnmatch(name, pat):
                    return "STEP_UP", "SENSITIVE_TOOL", pat
            return "ALLOW", "IN_SCOPE", ""
    return refused or ("DENY", "OUT_OF_SCOPE", name)


# ---------------------------------------------------------------- the pipeline

class Gateway:
    def __init__(self, registry, status_lists: dict[str, str], step_up_patterns: list[str] | None = None,
                 nonces: NonceStore | None = None):
        self.registry = registry
        self.status_lists = status_lists
        self.step_up = step_up_patterns or ["*.write", "*.draft"]
        # [q11 replay] seen nonces; main.py passes one persisted under GATEWAY_STATE_DIR, default in memory
        self.nonces = nonces if nonces is not None else NonceStore()

    def decide(self, req: Request) -> Decision:
        return self.decide_with_claims(req)[0]

    def decide_with_claims(self, req: Request) -> tuple[Decision, dict | None]:
        """The decision, plus the verified claims when the mandate verified (None on any rejection before that).
        Claims are returned only for what follows the decision, e.g. charging the mandate's run budget."""
        base = dict(policy_version=POLICY_VERSION, mandate_hash="", request_hash="", ts=time.time())
        try:
            check_arguments_size(req.arguments)
            base.update(mandate_hash=sha256_hex(req.mandate.encode()), request_hash=sha256_hex(req.signing_input()))
            claims = verify_mandate(req.mandate, self.registry, self.status_lists)
            try:
                budget = parse_budget(claims)  # a malformed budget is a DENY here, so tools_call only sees valid ones
            except BudgetInvalid as e:
                raise Reject("BUDGET_INVALID", str(e))
            jwk = claims["cnf"]["jwk"]
            try:
                agent_pub = jwk_to_pub(jwk)
            except (ValueError, KeyError, TypeError) as e:
                raise Reject("MANDATE_MALFORMED", f"cnf.jwk: {e}")
            # integer arithmetic: a huge ts cannot overflow, it is just outside the window
            if type(req.ts) is not int or not 0 <= req.ts <= MAX_TS or abs(req.ts - int(time.time())) > TS_WINDOW:
                raise Reject("POP_FAILED", "request timestamp outside window")
            # [q11 replay] begin: bounded nonce; recorded durably only after the signature verifies, so an unsigned
            # request cannot burn a real agent's nonce; recorded before main.tools_call forwards anything
            if not isinstance(req.nonce, str) or not 0 < len(req.nonce) <= MAX_NONCE_LEN:
                raise Reject("POP_FAILED", f"nonce must be 1 to {MAX_NONCE_LEN} characters")
            if self.nonces.seen(req.nonce):
                raise Reject("POP_FAILED", "replayed nonce")
            if not verify_bytes(agent_pub, req.signing_input(), req.sig):
                raise Reject("POP_FAILED", f"bad signature for jkt {jwk_thumbprint(jwk)}")
            try:
                self.nonces.add(req.nonce, req.ts)
            except NonceStoreUnavailable as e:
                raise Reject("NONCE_UNAVAILABLE", str(e))
            # [q11 replay] end

            decision, code, detail = check_request(req, claims["scope"], claims["deny"], self.step_up)
            if budget is not None and decision != "DENY" and (why := request_refusal(req.tool, req.arguments)):
                decision, code, detail = "DENY", "BUDGET_QUERY", why
            return Decision(decision, code, agent_id=claims["agent_id"], detail=detail, **base), claims
        except Reject as r:
            return Decision("DENY", r.code, agent_id=None, detail=r.detail, **base), None
        except Exception as e:  # noqa: BLE001  (fail closed: a request the pipeline cannot read is refused, not a 500)
            return Decision("DENY", "MALFORMED_REQUEST", agent_id=None, detail=type(e).__name__, **base), None
