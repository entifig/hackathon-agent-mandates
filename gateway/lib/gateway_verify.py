"""Gateway verification pipeline.

    receive (request, mandate)
      -> verify mandate: issuer accredited / signature / time / revocation
      -> verify proof of possession (request signed by cnf key, fresh nonce and ts)
      -> check request against scope, deny and constraints
      -> decision record {ALLOW | DENY | STEP_UP, reason_code, ...}

Reason codes are stable strings so the audit log and Day 2 scorecard can
count them. Order of checks is deliberate: cheapest and most definitive first.
"""
from __future__ import annotations

import fnmatch
import posixpath
import time
from dataclasses import asdict, dataclass

import jwt

from .common import canonical, jwk_thumbprint, jwk_to_pub, pub_to_pem, sha256_hex, verify_bytes
from .status_list import is_revoked

POLICY_VERSION = "2026-11-18.1"
CLOCK_SKEW = 30


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

def verify_mandate(token: str, registry, status_lists: dict[str, str]) -> dict:
    """Returns the verified claims. Raises Reject."""
    hdr = jwt.get_unverified_header(token)
    if hdr.get("typ") != "mandate+jwt":
        raise Reject("WRONG_TOKEN_TYPE", hdr.get("typ"))
    unverified = jwt.decode(token, options={"verify_signature": False})

    pub = registry.issuer_key(unverified["iss"], hdr.get("kid", ""))
    if pub is None:
        raise Reject("ISSUER_NOT_ACCREDITED", unverified["iss"])
    try:
        claims = jwt.decode(token, pub_to_pem(pub), algorithms=["EdDSA"],
                            options={"verify_exp": False, "verify_nbf": False, "require": ["exp", "iss", "jti"]})
    except jwt.PyJWTError as e:
        raise Reject("SIG_INVALID", str(e))

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
        if is_revoked(sl_jwt, sl["idx"], pub, sl["uri"]):
            raise Reject("REVOKED", claims["jti"])
    except ValueError as e:
        raise Reject("STATUS_UNAVAILABLE", str(e))
    return claims


# ---------------------------------------------------------------- scope

# A wrong value is more useful than a missing one when several entries all fail.
_FAIL_RANK = {"CONSTRAINT_VIOLATED": 2, "CONSTRAINT_MISSING": 1}


def _norm_path(value: str) -> str:
    """Same file, different spelling. `..` and absolute paths stay visibly out of the tree."""
    return posixpath.normpath(value)


def _constraint_holds(key: str, raw, allowed) -> bool:
    if key == "path":
        return _norm_path(str(raw)) in {_norm_path(str(item)) for item in allowed}
    return str(raw) in {str(item) for item in allowed}


def check_request(req: Request, scope: list[dict], deny: list[str], step_up_patterns: list[str]) -> tuple[str, str, str]:
    name = f"{req.server}.{req.tool}"
    for pat in deny:
        if fnmatch.fnmatch(name, pat):
            return "DENY", "DENIED_BY_RULE", pat
    failure: tuple[str, str, str] | None = None
    for entry in scope:
        if entry["server"] != req.server or req.tool not in entry["tools"]:
            continue
        entry_fail: tuple[str, str, str] | None = None
        for key, allowed in entry.get("constraints", {}).items():
            if key not in req.arguments:
                entry_fail = ("DENY", "CONSTRAINT_MISSING", key)
                break
            if not _constraint_holds(key, req.arguments[key], allowed):
                entry_fail = ("DENY", "CONSTRAINT_VIOLATED", f"{key}={req.arguments[key]!r}")
                break
        if entry_fail is not None:
            if failure is None or _FAIL_RANK.get(entry_fail[1], 0) > _FAIL_RANK.get(failure[1], 0):
                failure = entry_fail
            continue
        # An empty search matches every row of the granted school. Question 0 searches all have a query.
        if req.tool == "search" and not str(req.arguments.get("query", "")).strip():
            return "DENY", "CONSTRAINT_VIOLATED", "query"
        for pat in step_up_patterns:
            if fnmatch.fnmatch(name, pat):
                return "STEP_UP", "SENSITIVE_TOOL", pat
        return "ALLOW", "IN_SCOPE", ""
    if failure is not None:
        return failure
    return "DENY", "OUT_OF_SCOPE", name


# ---------------------------------------------------------------- the pipeline

class Gateway:
    def __init__(self, registry, status_lists: dict[str, str], step_up_patterns: list[str] | None = None):
        self.registry = registry
        self.status_lists = status_lists
        self.step_up = step_up_patterns or ["*.write", "*.draft"]
        self._seen_nonces: set[str] = set()

    def decide(self, req: Request) -> Decision:
        base = dict(policy_version=POLICY_VERSION, mandate_hash=sha256_hex(req.mandate.encode()),
                    request_hash=sha256_hex(req.signing_input()), ts=time.time())
        try:
            claims = verify_mandate(req.mandate, self.registry, self.status_lists)
            jwk = claims["cnf"]["jwk"]
            if abs(req.ts - time.time()) > 300:
                raise Reject("POP_FAILED", "request timestamp outside window")
            if req.nonce in self._seen_nonces:
                raise Reject("POP_FAILED", "replayed nonce")
            if not verify_bytes(jwk_to_pub(jwk), req.signing_input(), req.sig):
                raise Reject("POP_FAILED", f"bad signature for jkt {jwk_thumbprint(jwk)}")
            self._seen_nonces.add(req.nonce)

            decision, code, detail = check_request(req, claims["scope"], claims["deny"], self.step_up)
            return Decision(decision, code, agent_id=claims["agent_id"], detail=detail, **base)
        except Reject as r:
            return Decision("DENY", r.code, agent_id=None, detail=r.detail, **base)
