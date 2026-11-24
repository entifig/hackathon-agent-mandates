"""Audit trail: questions 14 ("tell me what it saw") and 16 ("show me a log of requests made with my access").

Every call to POST /tools/call is recorded, ALLOW, DENY and STEP_UP alike, before the response goes out:

    <state_dir>/audit.jsonl     one JSON object per line, append-only, fsync'd, hash-chained

What an entry holds:
  - the decision record (decision, reason_code, detail, policy_version, mandate_hash, request_hash, ...)
  - who: jti, iss, delegator.principal and the agent key thumbprint (jkt) from the mandate. Read from the verified
    claims when the issuer signature checks out, otherwise read unverified and marked "verified": false.
    A delegated child (question 7): jti and jkt are the child's (the helper's key), iss, principal and purpose are
    the parent's, plus parent_jti and chain [parent jti, child jti]; "verified" needs both the parent's issuer
    signature and the child's signature by the parent's agent key. `select(jti=<parent>)` finds the helper's calls.
  - from where: the client address the gateway saw (and X-Forwarded-For, which anyone can set)
  - what was asked: server, tool, arguments
  - what was released, for forwarded calls: a SUMMARY (HTTP status, row count, column names, the pupil IDs and school
    URNs that appear in the result). Never the row values, so the log is not a second copy of the pupil data. It
    still says whose data went where, so it is level 2 data itself.

Tamper evidence: each entry carries `prev` (the previous entry's hash) and `hash` = sha256 over its canonical JSON
without `hash`. `verify_chain` walks the file and reports the first broken link. Deleting or editing an entry in the
middle breaks the chain; truncating the tail or rewriting the whole chain does not (no external anchor: publish the
head hash somewhere the operator cannot rewrite).

Fail closed: if the entry cannot be written, nothing is released (403 AUDIT_UNAVAILABLE), never a 500.

The person reads their own log through the gateway with the ordinary request shape:

    POST /tools/call {"server": "gateway", "tool": "audit", "arguments": {"principal": "officer:jsmith"}, ...}

signed by a key holding a mandate whose scope grants
    {"server": "gateway", "tools": ["audit"], "constraints": {"principal": ["officer:jsmith"]}}
Scope matching is exact on server and tool name (no globs), so no data mandate reaches it by accident; the handler
also refuses a gateway.audit grant that does not constrain `principal`. Optional arguments: jti, since, limit.
"""
from __future__ import annotations

import contextvars
import functools
import json
import logging
import os
import re
import threading
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jwt
from fastapi import HTTPException
from fastapi.responses import JSONResponse, Response

from . import delegation
from .common import canonical, jwk_thumbprint, pub_to_pem, sha256_hex
from .gateway_verify import MAX_ROWS, POLICY_VERSION, Request, check_request

try:  # Unix: lock the file so two gateway processes sharing a state dir do not fork the chain
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

SERVER, TOOL = "gateway", "audit"  # the gateway's own tool: answered here, never forwarded
LOG_NAME = "audit.jsonl"
GENESIS = "sha256:" + "0" * 64
PUPIL_RE = re.compile(r"\bP\d{4,}\b")
SCHOOL_RE = re.compile(r"\bSCH\d{2,}\b")
MAX_ARGS_BYTES = 4096  # arguments bigger than this are stored as a hash and a preview

# set per HTTP request by ClientAddress, read when the entry is written
_client: contextvars.ContextVar[dict | None] = contextvars.ContextVar("audit_client", default=None)
_lock = threading.Lock()
logger = logging.getLogger("gateway.audit")


class AuditUnavailable(Exception):
    pass


# ---------------------------------------------------------------- where the request came from

class ClientAddress:
    """ASGI middleware: remember the peer address (and X-Forwarded-For, unverified) for the audit entry."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        peer = scope.get("client")
        headers = dict(scope.get("headers") or [])
        info = {"addr": f"{peer[0]}" if peer else None}
        if xff := headers.get(b"x-forwarded-for"):
            info["forwarded_for"] = xff.decode("latin-1")[:200]
        token = _client.set(info)
        try:
            return await self.app(scope, receive, send)
        finally:
            _client.reset(token)


# ---------------------------------------------------------------- the log file

def log_path(state_dir: Path) -> Path:
    return Path(os.environ.get("GATEWAY_AUDIT_LOG") or Path(state_dir) / LOG_NAME)


def startup_check(state_dir: Path) -> str | None:
    """None if the audit log can be written, else why not. The log fails closed, so an unwritable state dir
    would make the gateway refuse every call; /healthcheck reports this as 503 so a bad deploy fails visibly."""
    path = log_path(state_dir)
    probe = path.parent / f".audit-probe-{os.getpid()}"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        probe.write_bytes(b"probe")
        probe.unlink()
        if path.exists() and not os.access(path, os.W_OK):
            raise PermissionError(f"{path} is not writable")
    except Exception as e:  # noqa: BLE001
        msg = f"audit log {path} cannot be written ({type(e).__name__}: {e}); every call would be refused"
        logger.error(msg)
        return msg
    return None


def _entry_hash(entry: dict) -> str:
    return sha256_hex(canonical({k: v for k, v in entry.items() if k != "hash"}))


def _last_line(f) -> bytes:
    """The last non-empty line of an open binary file, read backwards from the end."""
    f.seek(0, os.SEEK_END)
    end = f.tell()
    buf, pos = b"", end
    while pos > 0:
        step = min(4096, pos)
        pos -= step
        f.seek(pos)
        buf = f.read(step) + buf
        stripped = buf.rstrip(b"\n")
        if b"\n" in stripped:
            return stripped.rsplit(b"\n", 1)[1]
    return buf.rstrip(b"\n")


def append(path: Path, entry: dict) -> dict:
    """Chain `entry` onto the log, write it, fsync. Returns it with seq, prev and hash. Raises AuditUnavailable."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with _lock, open(path, "a+b") as f:
            if fcntl:
                fcntl.flock(f, fcntl.LOCK_EX)
            try:
                last = _last_line(f)
                if last:
                    tail = json.loads(last)
                    prev, seq = tail["hash"], tail["seq"] + 1
                else:
                    prev, seq = GENESIS, 0
                entry = {"seq": seq, **entry, "prev": prev}
                entry["hash"] = _entry_hash(entry)
                f.seek(0, os.SEEK_END)
                f.write(canonical(entry) + b"\n")
                f.flush()
                os.fsync(f.fileno())
            finally:
                if fcntl:
                    fcntl.flock(f, fcntl.LOCK_UN)
        return entry
    except Exception as e:  # disk full, read-only mount, unreadable tail, unencodable value: all fail closed
        raise AuditUnavailable(f"{type(e).__name__}: {e}") from e


def read_entries(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_bytes().splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except ValueError:
                out.append({"seq": None, "unreadable": line[:200].decode("utf-8", "replace")})
    return out


def verify_chain(path: Path) -> dict:
    """Walk the chain. {"ok", "entries" (checked), "head" (last good hash), "broken_at" (0-based line), "reason"}."""
    prev, n = GENESIS, 0
    lines = [line for line in path.read_bytes().splitlines() if line.strip()] if path.exists() else []
    for n, line in enumerate(lines):
        try:
            entry = json.loads(line)
            if not isinstance(entry, dict):
                raise ValueError
        except ValueError:
            reason = "line is not a JSON object"
        else:
            if entry.get("seq") != n:
                reason = f"seq {entry.get('seq')!r} where {n} was expected (an entry was removed or inserted)"
            elif entry.get("prev") != prev:
                reason = "prev does not match the previous entry's hash (an entry before it was removed or edited)"
            elif entry.get("hash") != _entry_hash(entry):
                reason = "hash does not match the entry's content (the entry was edited)"
            else:
                prev = entry["hash"]
                continue
        return {"ok": False, "entries": n, "head": prev, "broken_at": n, "reason": reason}
    return {"ok": True, "entries": len(lines), "head": prev, "broken_at": None, "reason": ""}


# ---------------------------------------------------------------- what goes in an entry

def mandate_facts(token: str, registry) -> tuple[dict, dict | None]:
    """Who the mandate names, and the claims if the issuer signature verifies (expiry and revocation aside:
    an expired or revoked mandate still says truthfully whose access it was). Never raises.
    A delegated child: the parent's facts, with the child's jti, key and exp, and the chain; never its claims
    (None), so no grant read from them (gateway.audit) can come from a child."""
    if delegation.is_delegated(token):
        return _child_facts(token, registry), None
    facts: dict[str, Any] = {"verified": False}
    try:
        hdr = jwt.get_unverified_header(token)
        claims = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:  # garbage: record that it was garbage
        facts["error"] = f"unreadable mandate: {type(e).__name__}"
        return facts, None
    if not isinstance(claims, dict):
        return facts, None
    verified = None
    try:
        pub = registry.issuer_key(claims.get("iss"), hdr.get("kid", ""))
        if pub is not None and hdr.get("typ") == "mandate+jwt":
            verified = jwt.decode(token, pub_to_pem(pub), algorithms=["EdDSA"],
                                  options={"verify_exp": False, "verify_nbf": False, "verify_iat": False})
    except Exception:  # noqa: BLE001  bad signature or odd claims: keep the unverified reading
        verified = None
    c = verified or claims

    def text(v):
        return v if isinstance(v, str) else (None if v is None else json.dumps(v)[:200])

    delegator = c.get("delegator") if isinstance(c.get("delegator"), dict) else {}
    try:
        jkt = jwk_thumbprint(c["cnf"]["jwk"])
    except Exception:  # noqa: BLE001
        jkt = text(c.get("agent_id"))
    try:
        idx = c["status"]["status_list"]["idx"]
    except Exception:  # noqa: BLE001
        idx = None
    facts.update(
        verified=verified is not None,
        jti=text(c.get("jti")),
        iss=text(c.get("iss")),
        principal=text(delegator.get("principal")),
        org=text(delegator.get("org")),
        purpose=text(c.get("purpose")),
        jkt=jkt,
        status_idx=idx if isinstance(idx, int) else None,
        exp=c.get("exp") if isinstance(c.get("exp"), int) else None,
    )
    return facts, verified


def _child_facts(token: str, registry) -> dict:
    """[q7] Facts for a delegated child: who granted the access (from the parent) and who used it (the child)."""
    try:
        child = jwt.decode(token, options={"verify_signature": False})
        parent_token = child.get("parent") if isinstance(child, dict) else None
    except Exception as e:  # noqa: BLE001
        return {"verified": False, "error": f"unreadable delegated mandate: {type(e).__name__}"}
    if not isinstance(parent_token, str) or delegation.is_delegated(parent_token):
        return {"verified": False, "error": "delegated mandate without a usable parent", "delegated": True}
    facts, parent = mandate_facts(parent_token, registry)
    signed = delegation.child_signature_ok(token, parent) if parent else None
    c = signed or child
    try:
        jkt = jwk_thumbprint(c["cnf"]["jwk"])
    except Exception:  # noqa: BLE001
        jkt = None
    jti = c.get("jti") if isinstance(c.get("jti"), str) else None
    return {
        **facts,
        "verified": bool(facts.get("verified") and signed),
        "delegated": True,
        "jti": jti,
        "parent_jti": facts.get("jti"),
        "chain": [facts.get("jti"), jti],
        "jkt": jkt,
        "exp": c.get("exp") if isinstance(c.get("exp"), int) else None,
    }


def _strings(obj, depth=0):
    if depth > 20:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _strings(v, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _strings(v, depth + 1)


def summarise_result(data) -> dict:
    """What was released, without the values: row count, column names, pupil IDs and school URNs."""
    pupils, schools = set(), set()
    for s in _strings(data):
        pupils.update(PUPIL_RE.findall(s))
        schools.update(SCHOOL_RE.findall(s))
    if isinstance(data, list):
        rows = len(data)
        columns = sorted({str(k) for row in data if isinstance(row, dict) for k in row})
    elif isinstance(data, dict):
        rows, columns = 1, sorted(map(str, data))
    else:
        rows, columns = (0 if data is None else 1), []
    return {"rows": rows, "columns": columns[:100], "pupils": sorted(pupils), "schools": sorted(schools)}


def _bounded(arguments):
    try:
        raw = canonical(arguments)
    except Exception:  # noqa: BLE001  e.g. a lone surrogate: keep a printable trace instead
        return {"_unencodable": repr(arguments)[:500]}
    if len(raw) <= MAX_ARGS_BYTES:
        return arguments
    return {"_truncated": True, "sha256": sha256_hex(raw), "preview": raw[:500].decode("utf-8", "replace")}


def build_entry(*, record: dict, body, facts: dict, status: int, result_summary: dict | None) -> dict:
    now = time.time()
    return {
        "ts": now,
        "at": datetime.fromtimestamp(now, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "decision": record,
        "mandate": facts,
        "client": _client.get() or {"addr": None},
        "server": body.server,
        "tool": body.tool,
        "arguments": _bounded(body.arguments),
        "status": status,
        "released": result_summary,
    }


# ---------------------------------------------------------------- plain English for the person

_REASONS = {
    "CONSTRAINT_VIOLATED": "outside the mandate",
    "CONSTRAINT_MISSING": "outside the mandate",
    "OUT_OF_SCOPE": "outside the mandate",
    "DENIED_BY_RULE": "a tool the mandate forbids",
    "TOO_MUCH": "asked for too much at once",
    "REVOKED": "the mandate had been cancelled",
    "EXPIRED": "the mandate had expired",
    "NOT_YET_VALID": "the mandate was not valid yet",
    "POP_FAILED": "not signed by the mandate's agent key, or a replayed request: someone else may hold a copy",
    "SIG_INVALID": "the mandate had been altered or forged",
    "ISSUER_NOT_ACCREDITED": "the mandate came from an issuer this gateway does not trust",
    "WRONG_TOKEN_TYPE": "not a mandate",
    "STATUS_UNAVAILABLE": "the cancellation list could not be checked",
    "AUDIT_UNAVAILABLE": "the gateway could not write its log, so it released nothing",
    "DELEGATION_INVALID": "a helper's mandate that was not properly handed on by the agent holding the original",
    "DELEGATION_WIDER": "a helper's mandate asked for more than the one it was handed on from",
}
_SUSPICIOUS = {"POP_FAILED", "SIG_INVALID", "DELEGATION_INVALID"}


def _when(ts) -> str:
    try:
        return datetime.fromtimestamp(float(ts), UTC).strftime("%d %b %H:%M UTC")
    except Exception:  # noqa: BLE001
        return "unknown time"


def _key(entry) -> str:
    m = entry.get("mandate") or {}
    jkt = m.get("jkt") or "unknown"
    helper = " (a helper, handed on by your agent)" if m.get("delegated") else ""
    return f"agent key {jkt[:6]}…{helper}"


def _ids(ids: list[str], show=5) -> str:
    more = f" and {len(ids) - show} more" if len(ids) > show else ""
    return ", ".join(ids[:show]) + more


def _asked(entry) -> str:
    args = entry.get("arguments") if isinstance(entry.get("arguments"), dict) else {}
    server, tool = entry.get("server"), entry.get("tool")
    where = f" at {args['urn']}" if isinstance(args.get("urn"), str) else ""
    if (server, tool) == (SERVER, TOOL):
        return f"read the request log for {args.get('principal')}"
    if tool == "search":
        return f"searched {server} for {str(args.get('query'))[:40]!r}{where}"
    if tool == "get":
        return f"opened {str(args.get('path'))[:80]}"
    if tool == "pupil":
        return f"asked {server} for pupil {args.get('pupil_id')}{where}"
    return f"called {server}.{tool}{where}"


def plain(entry: dict) -> str:
    """One line a non-technical person can read."""
    d = entry.get("decision") or {}
    code = d.get("reason_code", "")
    released = entry.get("released") or {}
    addr = (entry.get("client") or {}).get("addr")
    head = f"{_when(entry.get('ts'))}: {_key(entry)}"
    if addr:
        head += f" from {addr}"
    if not (entry.get("mandate") or {}).get("verified"):
        head += " [mandate not verified]"
    what = _asked(entry)
    if d.get("decision") == "ALLOW" and (entry.get("server"), entry.get("tool")) == (SERVER, TOOL):
        return f"{head} {what}: allowed"
    if d.get("decision") == "ALLOW" and entry.get("status") == 200:
        pupils = released.get("pupils") or []
        rows = released.get("rows", 0)
        sent = f"was sent {rows} row{'s' if rows != 1 else ''}"
        if pupils:
            sent += f" about {len(pupils)} pupil{'s' if len(pupils) != 1 else ''} ({_ids(pupils)})"
        else:
            sent += " with no pupil IDs in it"
        return f"{head} {what} and {sent}: allowed"
    if d.get("decision") == "ALLOW":
        return f"{head} {what}: allowed, but nothing was sent (HTTP {entry.get('status')})"
    if d.get("decision") == "STEP_UP":
        return f"{head} {what}: held for a person's approval, nothing was sent"
    if d.get("decision") == "DENY":
        return f"{head} {what}: refused ({_REASONS.get(code, code)})"
    return f"{head} {what}: the gateway failed (HTTP {entry.get('status')}), nothing was sent"


def overview(entries: list[dict], subject: str = "mandates naming you") -> list[str]:
    """Headline lines over a set of entries: counts, keys, addresses, pupils, warnings."""
    if not entries:
        return [f"No requests have been made with {subject}."]
    decisions = Counter((e.get("decision") or {}).get("decision") for e in entries)
    lines = [
        f"{len(entries)} requests made with {subject}, {_when(entries[0].get('ts'))} to "
        f"{_when(entries[-1].get('ts'))}: {decisions['ALLOW']} allowed, {decisions['DENY']} refused, "
        f"{decisions['STEP_UP']} held for approval."
    ]
    pupils = sorted({p for e in entries for p in (e.get("released") or {}).get("pupils", [])})
    if pupils:
        lines.append(f"Pupils whose data was sent: {len(pupils)} ({_ids(pupils, 20)}).")
    keys = Counter(_key(e) for e in entries)
    lines.append("Agent keys used: " + ", ".join(f"{k} ({n})" for k, n in keys.most_common()) + ".")
    addrs = Counter((e.get("client") or {}).get("addr") or "unknown" for e in entries)
    lines.append("Sent from: " + ", ".join(f"{a} ({n})" for a, n in addrs.most_common()) + ".")
    refused = Counter(
        _REASONS.get(e["decision"]["reason_code"], e["decision"]["reason_code"])
        for e in entries if (e.get("decision") or {}).get("decision") == "DENY"
    )
    if refused:
        lines.append(f"{sum(refused.values())} refused: " + "; ".join(f"{r} ({n})" for r, n in refused.items()) + ".")
    suspicious = sum((e.get("decision") or {}).get("reason_code") in _SUSPICIOUS for e in entries)
    if suspicious:
        lines.append(f"Warning: {suspicious} requests carried a mandate naming you but were not properly signed or "
                     "the mandate was altered. Someone else may hold a copy of it.")
    by_jti: dict[str, set] = {}
    for e in entries:
        m = e.get("mandate") or {}
        if m.get("jti"):
            by_jti.setdefault(m["jti"], set()).add((e.get("client") or {}).get("addr"))
    for jti, seen in by_jti.items():
        if len(seen) > 1:
            lines.append(f"Warning: mandate {jti} was used from {len(seen)} different addresses.")
    unverified = sum(not (e.get("mandate") or {}).get("verified") for e in entries)
    if unverified:
        lines.append(f"{unverified} entries name you in a mandate the gateway could not verify; they may be forged.")
    return lines


# ---------------------------------------------------------------- reading the log

def _since(value) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if re.fullmatch(r"\d+(\.\d+)?", str(value)):
        return float(value)
    t = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return (t if t.tzinfo else t.replace(tzinfo=UTC)).timestamp()  # no zone given: UTC, like the log


def select(entries: list[dict], *, principal=None, jti=None, pupil=None, decision=None, since=None, limit=None):
    out = []
    t0 = _since(since)
    for e in entries:
        m = e.get("mandate") or {}
        if principal is not None and m.get("principal") != principal:
            continue
        if jti is not None and m.get("jti") != jti and jti not in (m.get("chain") or []):
            continue  # [q7] a parent's jti also finds its helpers' calls
        if decision is not None and (e.get("decision") or {}).get("decision") != decision:
            continue
        if t0 is not None and float(e.get("ts") or 0) < t0:
            continue
        if pupil is not None:
            released = (e.get("released") or {}).get("pupils", [])
            if pupil not in released and pupil not in json.dumps(e.get("arguments"), ensure_ascii=False):
                continue
        out.append(e)
    return out[-limit:] if limit else out


# ---------------------------------------------------------------- gateway.audit

def _deny(record: dict, code: str, detail: str) -> JSONResponse:
    return JSONResponse({"decision": {**record, "decision": "DENY", "reason_code": code, "detail": detail}},
                        status_code=403)


def _principal_granted(claims: dict | None, request: Request) -> tuple[bool, str]:
    """Belt and braces after the ordinary scope check: the grant must name gateway.audit exactly and pin
    `principal`, and that same grant must satisfy every other constraint on the request."""
    pinned = [
        entry
        for entry in (claims or {}).get("scope") or []
        if isinstance(entry, dict)
        and entry.get("server") == SERVER
        and TOOL in (entry.get("tools") or [])
        and isinstance(entry.get("constraints"), dict)
        and isinstance(entry["constraints"].get("principal"), list)
    ]
    if not pinned or not isinstance(request.arguments.get("principal"), str):
        return False, "CONSTRAINT_MISSING"
    decision, code, _ = check_request(request, pinned, [], [])
    return decision == "ALLOW", code


def serve_audit(state: dict, body) -> Response | dict:
    """gateway.audit: decided by the ordinary pipeline, answered by the gateway itself, never forwarded."""
    gateway = state["gateway"]
    gateway.status_lists[state["status_uri"]] = (state["dir"] / "status_list.jwt").read_text().strip()
    decision = gateway.decide(Request(**body.model_dump()))
    record = decision.to_dict()
    if decision.decision == "DENY":
        return JSONResponse({"decision": record}, status_code=403)
    if decision.decision == "STEP_UP":
        return JSONResponse({"decision": record}, status_code=202)
    if body.tool != TOOL:
        return _deny(record, "OUT_OF_SCOPE", f"{body.server}.{body.tool}")
    args = body.arguments
    _, claims = mandate_facts(body.mandate, gateway.registry)
    granted, code = _principal_granted(claims, Request(**body.model_dump()))
    if not granted:
        return _deny(record, code, "a matching gateway.audit grant must pin the principal")
    try:
        since = _since(args.get("since"))
    except ValueError:
        return _deny(record, "CONSTRAINT_VIOLATED", f"since={args.get('since')!r}")
    limit = args.get("limit", MAX_ROWS)  # already checked to be an int in 0..MAX_ROWS by check_request
    path = log_path(state["dir"])
    mine = select(read_entries(path), principal=args["principal"], jti=args.get("jti"), since=since)
    shown = mine[-limit:] if limit else []
    chain = verify_chain(path)
    return {
        "decision": record,
        "result": {
            "principal": args["principal"],
            "summary": overview(mine),
            "lines": [plain(e) for e in shown],
            "entries": shown,
            "total": len(mine),
            "shown": len(shown),
            "chain": {"ok": chain["ok"], "entries": chain["entries"], "head": chain["head"]},
        },
    }


# ---------------------------------------------------------------- the hook around POST /tools/call

def _status_and_payload(response) -> tuple[int, Any]:
    if isinstance(response, Response):
        try:
            return response.status_code, json.loads(response.body)
        except Exception:  # noqa: BLE001
            return response.status_code, None
    return 200, response


def _error_record(body, code: str, detail: str) -> dict:
    return {"decision": "ERROR", "reason_code": code, "policy_version": POLICY_VERSION,
            "mandate_hash": sha256_hex(str(body.mandate).encode()), "request_hash": None, "agent_id": None,
            "ts": time.time(), "detail": detail}


def audited(state: dict):
    """Decorator for the tools_call endpoint: answer gateway.audit in the gateway, and write one chained entry per
    call before its response goes out. If the entry cannot be written, release nothing (403 AUDIT_UNAVAILABLE)."""

    def wrap(endpoint):
        @functools.wraps(endpoint)
        async def tools_call(body):
            path = log_path(state["dir"])
            facts, _ = mandate_facts(body.mandate, state["gateway"].registry)
            try:
                response = serve_audit(state, body) if body.server == SERVER else await endpoint(body)
            except HTTPException as e:
                _try_append(path, build_entry(record=_error_record(body, f"HTTP_{e.status_code}", str(e.detail)),
                                              body=body, facts=facts, status=e.status_code, result_summary=None))
                raise
            except Exception as e:
                _try_append(path, build_entry(record=_error_record(body, "GATEWAY_ERROR", type(e).__name__),
                                              body=body, facts=facts, status=500, result_summary=None))
                raise
            status, payload = _status_and_payload(response)
            payload = payload if isinstance(payload, dict) else {}
            record = payload.get("decision") or _error_record(body, "NO_DECISION", "")
            released = None
            if status == 200 and "result" in payload:
                released = summarise_result(payload["result"])
                if body.server == SERVER:  # a log read: the IDs in it are what others asked for, not data sent now
                    released = {**released, "rows": payload["result"].get("shown"), "columns": [], "pupils": [],
                                "schools": [], "log_entries": payload["result"].get("shown")}
            try:
                append(path, build_entry(record=record, body=body, facts=facts, status=status,
                                         result_summary=released))
            except AuditUnavailable as e:
                return _deny(record, "AUDIT_UNAVAILABLE", f"the audit log could not be written ({e}); nothing released")
            return response

        return tools_call

    return wrap


def _try_append(path: Path, entry: dict) -> None:
    try:
        append(path, entry)
    except AuditUnavailable:
        pass  # the call already failed and released nothing; the original error is re-raised
