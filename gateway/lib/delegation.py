"""Delegated child mandates (question 7): an agent hands a helper LESS access than it holds, without the issuer.

The holder of a parent mandate signs a child mandate with the parent's cnf (agent) key:

    header  {"alg": "EdDSA", "typ": "delegated-mandate+jwt", "kid": <parent cnf thumbprint>}
    claims  {
      "iss":   "urn:ietf:params:oauth:jwk-thumbprint:sha-256:<parent cnf thumbprint>",   (RFC 9278)
      "jti", "iat", "nbf", "exp",
      "vct":   "urn:hack:mandate:delegated:v1",
      "parent": "<the whole parent mandate, compact JWT>",
      "cnf":   {"jwk": <helper public key>},  "agent_id": <its thumbprint>,
      "scope": [...], "deny": [...],          narrower than the parent's
      "budget": {"pupils": n, "calls": n}     optional, no wider than the parent's
    }

Nothing else may be in it: delegator, purpose, status and every claim of the parent's own are inherited, never set
by the child. The gateway (gateway_verify.Gateway) on every call:

  1. verifies the parent as an ordinary mandate: accredited issuer, signature, time, revocation. Revoking the parent
     kills every child at once; there is no separate status entry for a child;
  2. refuses a parent that is itself a child (depth limit MAX_DEPTH = 1);
  3. verifies the child's signature against the parent's cnf key and checks `iss` names that key, so only the holder
     of the parent can make a child, and a child can never pass as issuer-signed (its typ is not mandate+jwt and its
     iss is not in the trust registry);
  4. requires the child to be no wider than the parent (`check_narrower`): DELEGATION_WIDER otherwise;
  5. then the request is checked against the child's scope AND, again, against the parent's (defence in depth), and a
     budgeted call is charged to the child's budget and to the parent's (budget.chain_budgets), so a helper is not a
     way round the parent's budget.

Narrower means: every child scope entry is covered by ONE parent entry (same server, tools a subset, every constraint
the parent entry has is present in the child entry with allowed values a subset; the child may add constraints);
nbf >= parent nbf and exp <= parent exp; every parent deny rule kept; a budget no bigger than the parent's. A child
may not be granted the gateway's own tools (gateway.audit): the request log is the person's, not a helper's.

Reason codes: DELEGATION_INVALID (not a well-formed child of a mandate its signer holds) and DELEGATION_WIDER (a
well-formed child that asks for more than its parent). Both 403 DENY. A parent that fails its own checks keeps its own
reason code (REVOKED, EXPIRED, SIG_INVALID, ...), with "parent mandate:" in the detail.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable

import jwt

from .common import jwk_thumbprint, jwk_to_pub, priv_to_pem, pub_to_jwk, pub_to_pem

DELEGATED_TYP = "delegated-mandate+jwt"
MANDATE_TYP = "mandate+jwt"
VCT = "urn:hack:mandate:delegated:v1"
THUMBPRINT_URI = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:"
MAX_DEPTH = 1  # a child cannot delegate again
CHILD_CLAIMS = {"iss", "jti", "iat", "nbf", "exp", "vct", "parent", "cnf", "agent_id", "scope", "deny", "budget"}
CHILD_BUDGET_KEYS = {"pupils", "calls"}  # no `id`: a child's own budget is keyed by the gateway, not chosen by it
GATEWAY_SERVER = "gateway"  # the gateway's own tools (audit.SERVER): never delegated


class Reject(Exception):  # noqa: N818  (re-exported as gateway_verify.Reject: one class for every refusal)
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


def invalid(detail: str) -> Reject:
    return Reject("DELEGATION_INVALID", detail)


def wider(detail: str) -> Reject:
    return Reject("DELEGATION_WIDER", detail)


def issuer_uri(jwk: dict) -> str:
    """The child's `iss`: the parent's agent key, as an RFC 9278 thumbprint URI. Never in a trust registry."""
    return THUMBPRINT_URI + jwk_thumbprint(jwk)


def is_delegated(token) -> bool:
    try:
        return isinstance(token, str) and jwt.get_unverified_header(token).get("typ") == DELEGATED_TYP
    except jwt.PyJWTError:
        return False


# ---------------------------------------------------------------- narrower than the parent


def _values(allowed) -> set[str]:
    # the scope check compares str(value) with str(allowed), so subset is decided the same way
    return set(map(str, allowed))


def _covers(parent_entry: dict, child_entry: dict) -> bool:
    if parent_entry["server"] != child_entry["server"]:
        return False
    if not set(child_entry["tools"]) <= set(parent_entry["tools"]):
        return False
    child_constraints = child_entry.get("constraints", {})
    for key, allowed in parent_entry.get("constraints", {}).items():
        if key not in child_constraints or not _values(child_constraints[key]) <= _values(allowed):
            return False
    return True


def check_narrower(parent: dict, child: dict) -> None:
    """Raise DELEGATION_WIDER (or DELEGATION_INVALID for a grant that is never delegable) unless `child` asks for
    no more than `parent`. Both are claim sets whose shape has already been checked."""
    for i, entry in enumerate(child["scope"]):
        if entry["server"] == GATEWAY_SERVER:
            raise invalid(f"scope[{i}]: the gateway's own tools ({GATEWAY_SERVER}.*) cannot be delegated")
        if not any(_covers(p, entry) for p in parent["scope"]):
            raise wider(f"scope[{i}] {entry['server']}.{entry['tools']} is not inside any one parent scope entry")
    if dropped := sorted(set(parent["deny"]) - set(child["deny"])):
        raise wider(f"drops the parent's deny rules {dropped}")
    if child["exp"] > parent["exp"]:
        raise wider("exp is later than the parent's")
    if child["nbf"] < parent.get("nbf", float("-inf")):
        raise wider("nbf is earlier than the parent's")
    budget = child.get("budget")
    if budget is None:
        return  # the parent's budget, if any, is still charged for every call
    if not isinstance(budget, dict) or not budget.keys() <= CHILD_BUDGET_KEYS or "pupils" not in budget:
        raise invalid(f"a child's budget is {{pupils, calls?}} only, got {budget!r}")
    for name in budget:
        if type(budget[name]) is not int or budget[name] < 0:
            raise invalid(f"budget.{name} must be an integer >= 0")
    parent_budget = parent.get("budget")
    if isinstance(parent_budget, dict):
        for name in CHILD_BUDGET_KEYS & budget.keys():
            limit = parent_budget.get(name)
            if type(limit) is int and budget[name] > limit:
                raise wider(f"budget.{name} {budget[name]} is more than the parent's {limit}")


# ---------------------------------------------------------------- minting (the parent's holder)


def delegate(
    parent_token: str,
    parent_agent_priv,
    helper_pub,
    *,
    scope: list[dict],
    deny: list[str] | None = None,
    ttl: int = 3600,
    budget: dict | None = None,
    check: bool = True,
) -> str:
    """A child of `parent_token`, signed with the parent's agent key, for `helper_pub`. The parent's deny rules are
    always kept and exp never outlives the parent. `check=False` skips the local narrower check (red-teaming a
    gateway); the gateway checks anyway."""
    if is_delegated(parent_token):
        raise ValueError(f"the parent is itself delegated: depth is limited to {MAX_DEPTH}")
    parent = jwt.decode(parent_token, options={"verify_signature": False})
    if jwk_thumbprint(parent["cnf"]["jwk"]) != jwk_thumbprint(pub_to_jwk(parent_agent_priv.public_key())):
        raise ValueError("this agent key is not the parent mandate's cnf key: only its holder can delegate")
    now = int(time.time())
    helper_jwk = pub_to_jwk(helper_pub)
    claims = {
        "iss": issuer_uri(parent["cnf"]["jwk"]),
        "jti": f"urn:uuid:{uuid.uuid4()}",
        "iat": now,
        "nbf": max(now, int(parent.get("nbf", now))),
        "exp": min(now + ttl, int(parent["exp"])),
        "vct": VCT,
        "parent": parent_token,
        "cnf": {"jwk": helper_jwk},
        "agent_id": jwk_thumbprint(helper_jwk),
        "scope": scope,
        "deny": list(dict.fromkeys([*parent.get("deny", []), *(deny or [])])),
    }
    if budget is not None:
        claims["budget"] = budget
    if check:
        try:
            check_narrower(parent, claims)
        except Reject as r:
            raise ValueError(f"{r.code}: {r.detail}") from None
    return jwt.encode(
        claims,
        priv_to_pem(parent_agent_priv),
        algorithm="EdDSA",
        headers={"typ": DELEGATED_TYP, "kid": jwk_thumbprint(parent["cnf"]["jwk"])},
    )


# ---------------------------------------------------------------- verifying (the gateway)


def _child_shape(claims: dict) -> None:
    from .gateway_verify import claim_checks  # one definition of what a well-formed claim is

    if unknown := sorted(map(str, claims.keys() - CHILD_CLAIMS)):
        raise invalid(f"claims {unknown} are inherited from the parent or unknown; a child may not set them")
    checks = claim_checks(claims)
    checks.pop("status")  # a child has no status entry of its own: it is revoked with its parent
    checks["nbf"] = type(claims.get("nbf")) in (int, float) and checks["nbf"]  # required for a child
    if bad := [name for name, ok in checks.items() if not ok]:
        raise invalid(f"bad or missing claims {bad}")
    if claims.get("vct", VCT) != VCT:
        raise invalid(f"vct must be {VCT}")
    try:
        jwk_to_pub(claims["cnf"]["jwk"])
        thumbprint = jwk_thumbprint(claims["cnf"]["jwk"])
    except (ValueError, KeyError, TypeError) as e:
        raise invalid(f"cnf.jwk: {e}") from None
    if claims["agent_id"] != thumbprint:
        raise invalid("agent_id is not the thumbprint of cnf.jwk")


def verify_delegated(token: str, verify_parent: Callable[[str], dict], now: float, skew: int) -> dict:
    """The effective claims of a child mandate, or Reject. `verify_parent` is the gateway's ordinary
    verify_mandate (issuer, signature, time, revocation). The effective claims are the parent's, with the child's
    jti, nbf, exp, cnf, agent_id, scope and deny (and budget) over them, plus `parent` (the verified parent claims)
    and `delegation` (the chain)."""
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError as e:
        raise invalid(f"unreadable child mandate: {e}") from None
    parent_token = unverified.get("parent")
    if not isinstance(parent_token, str):
        raise invalid(f"`parent` must be the parent mandate as a compact JWT, got {type(parent_token).__name__}")
    try:
        parent_typ = jwt.get_unverified_header(parent_token).get("typ")
    except jwt.PyJWTError as e:
        raise invalid(f"unreadable parent mandate: {e}") from None
    if parent_typ == DELEGATED_TYP:
        raise invalid(f"the parent is itself delegated: depth is limited to {MAX_DEPTH}")
    try:
        parent = verify_parent(parent_token)
    except Exception as e:
        code, detail = getattr(e, "code", "DELEGATION_INVALID"), getattr(e, "detail", type(e).__name__)
        raise Reject(code, f"parent mandate: {detail}") from None

    parent_jwk = parent["cnf"]["jwk"]
    try:
        parent_pub = jwk_to_pub(parent_jwk)
    except (ValueError, KeyError, TypeError) as e:
        raise Reject("MANDATE_MALFORMED", f"parent mandate cnf.jwk: {e}") from None
    try:
        claims = jwt.decode(
            token,
            pub_to_pem(parent_pub),
            algorithms=["EdDSA"],
            options={"verify_exp": False, "verify_nbf": False, "verify_iat": False, "verify_iss": False},
        )
    except jwt.PyJWTError as e:
        raise invalid(f"child not signed by the parent mandate's agent key ({e})") from None
    if not isinstance(claims, dict):
        raise invalid("claims are not an object")
    if claims.get("iss") != issuer_uri(parent_jwk):
        raise invalid("iss must name the parent mandate's agent key")
    _child_shape(claims)
    check_narrower(parent, claims)
    if claims["nbf"] > now + skew:
        raise Reject("NOT_YET_VALID", claims["jti"])
    if claims["exp"] < now - skew:
        raise Reject("EXPIRED", claims["jti"])

    effective = {k: v for k, v in parent.items() if k != "budget"}  # inherit every restriction of the parent
    effective.update(
        jti=claims["jti"],
        nbf=claims["nbf"],
        exp=claims["exp"],
        cnf=claims["cnf"],
        agent_id=claims["agent_id"],
        scope=claims["scope"],
        deny=claims["deny"],
        parent=parent,
        delegation={"depth": 1, "parent_jti": parent["jti"], "chain": [parent["jti"], claims["jti"]]},
    )
    if "budget" in claims:
        # the gateway keys a child's own budget; it is ALSO charged to the parent's (budget.chain_budgets)
        effective["budget"] = {**claims["budget"], "id": f"delegated:{parent['jti']}:{claims['jti']}"}
    return effective


def child_signature_ok(token: str, parent_claims: dict) -> dict | None:
    """The child's claims if it is signed by the parent's cnf key, else None. For the audit log: never raises."""
    try:
        pub = jwk_to_pub(parent_claims["cnf"]["jwk"])
        claims = jwt.decode(
            token,
            pub_to_pem(pub),
            algorithms=["EdDSA"],
            options={"verify_exp": False, "verify_nbf": False, "verify_iat": False, "verify_iss": False},
        )
        return claims if isinstance(claims, dict) else None
    except Exception:  # noqa: BLE001
        return None
