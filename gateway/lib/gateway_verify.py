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
from pathlib import Path

import jwt

from .common import canonical, jwk_thumbprint, jwk_to_pub, pub_to_pem, sha256_hex, verify_bytes
from .status_list import is_revoked

POLICY_VERSION = "2026-11-18.1"
CLOCK_SKEW = 30
REPLAY_WINDOW = 300  # seconds a request's ts may be from the gateway's clock; a nonce is remembered that long
# Most rows one call may ask for (the MCP server's own default).
# shortcut: per call only, many small calls still add up (question 11); add a per-mandate budget for that
MAX_ROWS = 100
# Smallest count released as itself. Every aggregate total and count is rounded to the nearest multiple, the
# large ones too, so two answers cannot be subtracted to recover a small one. main.py lets GATEWAY_SMALL_COUNT
# replace it; no mandate claim can.
# shortcut: counts are census rows, and one pupil can be five of them
SMALL_COUNT = 10
# Columns that name one pupil: an aggregate grouped or filtered by one is that pupil's record.
IDENTIFIERS = frozenset({"Psuedo ID", "DisplayName"})
# A result at PRIVATE_LEVEL needs one of PRIVATE_ROLES as well as the clearance. The issuer signs the role the person
# holds into the agent's mandate; the gateway says which roles open the data. main.py lets GATEWAY_PRIVATE_ROLES
# replace the list; no mandate claim can.
PRIVATE_LEVEL = 4
PRIVATE_ROLES = frozenset({"safeguarding-lead"})
# The table search and pupil read. The labels themselves are public; any other file without a label is not.
CENSUS_TABLE = "personal_data_school_census"
PUBLIC_FILES = frozenset({"synthetic/synthetic_manifest.json"})


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
    role: str | None = None  # from the mandate; main.py checks it when the result reaches PRIVATE_LEVEL
    role_exp: int | None = None  # from the mandate; when the role ends, which can be before the mandate does
    detail: str = ""
    notice: str = ""  # for the person whose data it is, when an agent asks without clearance
    sensitivity: dict | None = None  # the labels on the result and the ones that decided
    disclosure: dict | None = None  # how the result was changed before release

    def to_dict(self) -> dict:
        raw = asdict(self)
        for key in ("role", "role_exp", "notice", "sensitivity", "disclosure"):
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
    # Nothing here is verified yet, so anyone can send it: a token that does not parse is a denial, not a crash.
    try:
        hdr = jwt.get_unverified_header(token)
        if hdr.get("typ") != "mandate+jwt":
            raise Reject("WRONG_TOKEN_TYPE", str(hdr.get("typ")))
        unverified = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError as e:
        raise Reject("MANDATE_MALFORMED", str(e))
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
    """Same file, different spelling. `..` and absolute paths stay visibly out of the tree.

    Lexical only: it agrees with the data server's resolve() while the data directory has no symlinks.
    """
    return posixpath.normpath(value)


def _constraint_holds(key: str, raw, allowed) -> bool:
    if key == "path":
        return _norm_path(str(raw)) in {_norm_path(str(item)) for item in allowed}
    return str(raw) in {str(item) for item in allowed}


def _identifiers(arguments: dict) -> list[str]:
    group_by, where = arguments.get("group_by"), arguments.get("where")
    fields = [*(group_by if isinstance(group_by, list) else []), *(where if isinstance(where, dict) else [])]
    return [field for field in fields if isinstance(field, str) and field in IDENTIFIERS]


def check_request(req: Request, scope: list[dict], deny: list[str], step_up_patterns: list[str]) -> tuple[str, str, str]:
    name = f"{req.server}.{req.tool}"
    for pat in deny:
        if fnmatch.fnmatch(name, pat):
            return "DENY", "DENIED_BY_RULE", pat
    # Each entry is a whole grant: the call is allowed if any one entry accepts every argument it constrains,
    # so a request cannot take urn from one entry and path from another.
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
        limit = req.arguments.get("limit", MAX_ROWS)
        if type(limit) is not int or not 0 <= limit <= MAX_ROWS:
            return "DENY", "TOO_MUCH", f"limit={limit!r}, at most {MAX_ROWS}"
        # An empty search matches every row of the granted school. Question 0 searches all have a query.
        if req.tool == "search" and not str(req.arguments.get("query", "")).strip():
            return "DENY", "TOO_MUCH", "empty query matches every row"
        named = _identifiers(req.arguments) if req.tool == "aggregate" else []
        if named:
            return "DENY", "TOO_FINE", f"{named[0]} makes each group one pupil"
        for pat in step_up_patterns:
            if fnmatch.fnmatch(name, pat):
                return "STEP_UP", "SENSITIVE_TOOL", pat
        return "ALLOW", "IN_SCOPE", ""
    return failure or ("DENY", "OUT_OF_SCOPE", name)


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
        if path in PUBLIC_FILES:
            return {path: 1}
        if not path.endswith(".csv"):
            return {path: max_level}                   # a file with no label is not public
        stem = path.rsplit("/", 1)[-1].removeprefix("synthetic_").removesuffix(".csv")
        return {stem: tables.get(stem, max_level)}
    rows = result if isinstance(result, list) else [result]
    levels = {_key_name(k, arguments): _key_level(k, arguments, columns, max_level)
              for r in rows if isinstance(r, dict) for k in r}
    where = arguments.get("where") if tool == "aggregate" else None
    if isinstance(where, dict):
        # a count of one ethnic group says as much about ethnicity as grouping by it, with or without rows
        levels.update({f"{k} (filter)": columns.get(k, max_level) for k in where})
    return levels


def expected_shape(tool: str, arguments: dict, table_columns: dict[str, dict[str, int]]) -> object:
    """A result with every key the tool can return, so the labels can be read from the request alone.

    None for a tool the gateway has no shape for.
    """
    census = dict.fromkeys(table_columns.get(CENSUS_TABLE, {}))
    group_by = arguments.get("group_by")
    group_by = [g for g in group_by if isinstance(g, str)] if isinstance(group_by, list) else []
    shapes = {
        "search": [census],
        "pupil": {
            **census,
            "DisplayName": None,
            **dict.fromkeys(table_columns.get("personal_data_deprivation", {})),
        },
        "roster": [{"Psuedo ID": None, "DisplayName": None}],
        "draft": [{"Psuedo ID": None, "letter": None}],
        "aggregate": [{**dict.fromkeys(group_by), "total": 0, "count": 0}],
        "write": dict.fromkeys(("ts", "pupil_id", "urn", "column", "before", "after", "reason")),
        "classification": dict.fromkeys(("levels", "tables", "columns")),
        "get": [],
    }
    return shapes.get(tool)


def request_levels(tool: str, arguments: dict, table_columns: dict[str, dict[str, int]],
                   columns: dict[str, int], tables: dict[str, int], max_level: int) -> dict[str, int]:
    """The labels on everything the call could return, decided before it is forwarded.

    A refusal made after the call depends on what matched, so a 403 against a 200 [] tells the agent whether
    a row exists. Deciding from the request alone gives the same answer whatever the data holds.
    """
    shape = expected_shape(tool, arguments, table_columns)
    if shape is None:
        return {f"{tool} (no labels)": max_level}
    levels = result_levels(tool, arguments, shape, columns, tables, max_level)
    group_by = arguments.get("group_by")
    if tool == "aggregate" and isinstance(group_by, list) and not all(isinstance(g, str) for g in group_by):
        levels["group_by (not column names)"] = max_level  # the arguments are the agent's: label, never crash
    return levels


def round_counts(result, base: int):
    """Every aggregate total and count to the nearest multiple of base, halves up."""
    if not isinstance(result, list):
        return result

    def near(value):
        return (value + base // 2) // base * base if type(value) is int else value

    return [
        {k: near(v) if k in ("total", "count") else v for k, v in row.items()} if isinstance(row, dict) else row
        for row in result
    ]


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
    def __init__(self, registry, status_lists: dict[str, str], step_up_patterns: list[str] | None = None,
                 nonce_log: Path | None = None):
        self.registry = registry
        self.status_lists = status_lists
        self.step_up = step_up_patterns or ["*.write", "*.draft"]
        # nonce digest -> the time its request leaves the window, after which a replay fails on ts anyway
        self._seen_nonces: dict[str, int] = {}
        self._nonce_log = nonce_log
        if nonce_log is not None:
            self._load_nonces(nonce_log)

    def _load_nonces(self, log: Path) -> None:
        """Nonces accepted before a restart or a state reload still count while their request is in the window.

        shortcut: one file, one process. Replicas need a shared store. The file is trimmed here, not while running.
        """
        now = int(time.time())
        for line in log.read_text().splitlines() if log.exists() else []:
            expires, _, digest = line.partition(" ")
            if expires.isdigit() and digest and int(expires) >= now:
                self._seen_nonces[digest] = int(expires)
        # written at start-up so a state dir that cannot be written fails here, not in the middle of a call
        log.write_text("".join(f"{expires} {digest}\n" for digest, expires in self._seen_nonces.items()))

    def _remember_nonce(self, digest: str, expires: int) -> None:
        self._seen_nonces[digest] = expires
        if self._nonce_log is not None:
            with self._nonce_log.open("a") as log:
                log.write(f"{expires} {digest}\n")

    def decide(self, req: Request) -> Decision:
        # Everything in the request is the sender's. Text that cannot be hashed (a lone surrogate) is text no key
        # signed, so it is a denial like any other and never an error page.
        try:
            base = dict(policy_version=POLICY_VERSION, mandate_hash=sha256_hex(req.mandate.encode()),
                        request_hash=sha256_hex(req.signing_input()), ts=time.time())
            nonce = sha256_hex(req.nonce.encode())
        except ValueError as e:
            return Decision("DENY", "REQUEST_MALFORMED", POLICY_VERSION, "", "", None, time.time(),
                            detail=f"the request cannot be hashed: {type(e).__name__}")
        try:
            claims = verify_mandate(req.mandate, self.registry, self.status_lists)
            jwk = claims["cnf"]["jwk"]
            if abs(req.ts - int(time.time())) > REPLAY_WINDOW:      # whole seconds: a huge ts must not overflow
                raise Reject("POP_FAILED", "request timestamp outside window")
            if nonce in self._seen_nonces:
                raise Reject("POP_FAILED", "replayed nonce")
            if not verify_bytes(jwk_to_pub(jwk), req.signing_input(), req.sig):
                raise Reject("POP_FAILED", f"bad signature for jkt {jwk_thumbprint(jwk)}")
            self._remember_nonce(nonce, req.ts + REPLAY_WINDOW)

            # Question 6: no clearance claim is an error, not an assumption. The caller
            # fixes the mandate (re-issue with --clearance N), not the gateway.
            clearance = claims.get("clearance")
            if clearance is None:
                return Decision("DENY", "CLEARANCE_MISSING", agent_id=claims["agent_id"],
                                detail="re-issue the mandate with a clearance claim (1-4)",
                                notice=no_clearance_notice(claims, req), **base)
            if not isinstance(clearance, int) or not 1 <= clearance <= 4:
                raise Reject("CLEARANCE_INVALID", f"clearance={clearance!r} outside 1-4")
            role = claims.get("role")
            if role is not None and not (isinstance(role, str) and role):
                raise Reject("ROLE_INVALID", f"role={role!r} is not a role name")
            # The person can hold the role for less time than the mandate lasts. A date with no role to end, or
            # one that is not a time, is the issuer's mistake: refuse it rather than guess which was meant.
            role_exp = claims.get("role_exp")
            if role_exp is not None and (role is None or type(role_exp) is not int):
                raise Reject("ROLE_INVALID", f"role_exp={role_exp!r} needs a role and a unix time")

            decision, code, detail = check_request(req, claims["scope"], claims["deny"], self.step_up)
            return Decision(decision, code, agent_id=claims["agent_id"], clearance=clearance, role=role,
                            role_exp=role_exp, detail=detail, **base)
        except Reject as r:
            return Decision("DENY", r.code, agent_id=None, detail=r.detail, **base)
