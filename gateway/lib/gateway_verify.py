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
    clearance: int | None = None  # from the mandate; main.py enforces it against the result
    detail: str = ""
    notice: str = ""  # for the person whose data it is, when an agent asks without clearance
    sensitivity: dict | None = None  # the labels on the result and the ones that decided

    def to_dict(self) -> dict:
        raw = asdict(self)
        for key in ("notice", "sensitivity"):
            if not raw[key]:
                del raw[key]
        return raw


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


# ---------------------------------------------------------------- classification (question 6)

def sensitivity_maps(classification: dict) -> tuple[dict[str, int], dict[str, int]]:
    """Column and table -> PII level, from the manifest's classification block."""
    columns: dict[str, int] = {}
    for cols in classification["columns"].values():
        for col, level in cols.items():
            columns[col] = max(columns.get(col, 0), level)
    return columns, classification["tables"]


def result_max_level(tool: str, arguments: dict, result, columns: dict[str, int],
                     tables: dict[str, int], max_level: int) -> int:
    """The highest sensitivity the result carries. Deny-on-max: this one number decides.

    Unknown column keys fail closed at max_level: a column with no label is not public.
    """
    return max(result_levels(tool, arguments, result, columns, tables, max_level).values(), default=0)


def result_levels(tool: str, arguments: dict, result, columns: dict[str, int],
                  tables: dict[str, int], max_level: int) -> dict[str, int]:
    """Each labelled part of the result and its level: a column, or the whole table for `get`."""
    if result is None:
        return {}
    if tool == "get":
        path = _norm_path(str(arguments.get("path", "")))
        if not path.endswith(".csv"):
            return {path: 1}
        stem = path.rsplit("/", 1)[-1].removeprefix("synthetic_").removesuffix(".csv")
        return {stem: tables.get(stem, max_level)}
    rows = result if isinstance(result, list) else [result]
    return {_key_name(k, arguments): _key_level(k, arguments, columns, max_level)
            for r in rows if isinstance(r, dict) for k in r}


def sensitivity_record(levels: dict[str, int], level_names: dict[int, str], clearance: int | None) -> dict:
    """The decision's account of the result: every label, and the most restrictive ones, which decide."""
    top = max(levels.values(), default=0)
    return {
        "level": top,
        "label": level_names.get(top, "no labelled data"),
        "clearance": clearance,
        "decided_by": sorted(name for name, level in levels.items() if top and level == top),
        "labels": levels,
    }


def _key_name(key: str, arguments: dict) -> str:
    if key == "count":
        return f"count ({arguments.get('measure', '')})"
    if key in ("before", "after"):
        return f"{key} ({arguments.get('column', '')})"
    return key


def _key_level(key: str, arguments: dict, columns: dict[str, int], max_level: int) -> int:
    if key == "total":                                 # aggregate group size
        return 1
    if key == "count":                                 # aggregate: how many match `measure`
        return columns.get(str(arguments.get("measure", "")), max_level)
    if key in ("before", "after"):                     # write result echoes the corrected column
        return columns.get(str(arguments.get("column", "")), max_level)
    if key == "letter":                                # draft text embeds a display name
        return 2
    return columns.get(key, max_level)


def no_clearance_notice(claims: dict, req: Request) -> str:
    """What the person whose data it is should be told. The agent did prove who it is."""
    principal = (claims.get("delegator") or {}).get("principal", "an unnamed principal")
    return (
        f"An authenticated agent ({claims['agent_id']}) acting for {principal} asked for "
        f"{req.server}.{req.tool}. Its mandate has no clearance and no explicit consent from the person "
        "whose data it is, so the gateway refused the call."
    )


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

            # Question 6: no clearance claim is an error, not an assumption. The caller
            # fixes the mandate (re-issue with --claims '{"clearance": N}'), not the gateway.
            clearance = claims.get("clearance")
            if clearance is None:
                return Decision("DENY", "CLEARANCE_MISSING", agent_id=claims["agent_id"],
                                detail="re-issue the mandate with a clearance claim (1-4)",
                                notice=no_clearance_notice(claims, req), **base)
            if not isinstance(clearance, int) or not 1 <= clearance <= 4:
                raise Reject("CLEARANCE_INVALID", f"clearance={clearance!r} outside 1-4")

            decision, code, detail = check_request(req, claims["scope"], claims["deny"], self.step_up)
            return Decision(decision, code, agent_id=claims["agent_id"], clearance=clearance, detail=detail, **base)
        except Reject as r:
            return Decision("DENY", r.code, agent_id=None, detail=r.detail, **base)
