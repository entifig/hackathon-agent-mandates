# Attacking our gateway: <TEAM NAME>

Everything you need to call our gateway with the two mandates we issued you. Fill-in fields are in `<angle
brackets>`. Scoring and the rules are in [ATTACK_SCORING.md](ATTACK_SCORING.md).

| | |
| --- | --- |
| Gateway URL | `<https://our-gateway.example>` |
| Health check | `GET <gateway URL>/healthcheck` returns `{"status":"ok"}` |
| What it offers | `GET <gateway URL>/describe`: tools, signing rules, disclosure rules |
| Your mandates | `<link to our day_2_attack/mandates/ folder>`: `<your-team>.jwt` and `<your-team>.feature.jwt` |
| Valid until | `<UTC time>` (24 hours from issue) |
| Contact | `<name, channel>` |
| Out of bounds | Anything except the URL above: no calls to our MCP server, no flooding |

## 1. Send us your key

We bind each mandate to one agent key, so we need your public key before we can issue anything.

```bash
uv run python -m gateway.cli keygen -o attack.pem > <your-team>.jwk
```

Post `<your-team>.jwk` where we can see it. Keep `attack.pem` to yourself: a mandate only works with a request
signed by that key.

## 2. Check your mandates work

```bash
# what we signed for you (does not check the signature)
uv run python -m gateway.cli decode <your-team>.jwt

# what our gateway offers and how a call is signed
uv run python -m gateway.cli discover --url <gateway URL>

# level 1, inside both mandates: should come back 200 and ALLOW
uv run python -m gateway.cli call --mandate <your-team>.jwt --agent-key attack.pem --url <gateway URL> \
  --tool get --args '{"path": "synthetic/synthetic_schools.csv"}'
```

If this returns `EXPIRED` or `REVOKED`, tell us and we will issue a new one.

What each mandate decodes to, with the values that change per issue as placeholders:
[mandate_examples/default.json](mandate_examples/default.json) and
[mandate_examples/feature.json](mandate_examples/feature.json).

## 3. The default mandate (`<your-team>.jwt`)

The same mandate every team hands out.

| Claim | Value |
| --- | --- |
| Scope | `search` with `urn` = `SCH01` (Ashfield Academy); `get` on `synthetic/synthetic_schools.csv` and `synthetic/synthetic_manifest.json` |
| Deny | `*.write`, `pii.*` |
| Clearance | 4, role `safeguarding-lead` |
| Lifetime | 24 hours |

**Allows**, for example:

```bash
uv run python -m gateway.cli call --mandate <your-team>.jwt --agent-key attack.pem --url <gateway URL> \
  --tool search --args '{"query": "P0004", "urn": "SCH01"}'
```

**Refuses**: any other school, any other file, any other tool (`roster`, `pupil`, `aggregate`, `draft`, `write`,
`classification`).

## 4. The feature mandate (`<your-team>.feature.jwt`)

<Replace this section with your own feature. The text below is our current one, from
[FEATURE_NOTE.md](FEATURE_NOTE.md).>

**Feature:** question `<6>`, `<clearance>`.

| Claim | Value |
| --- | --- |
| Scope | `roster` and `search` with `urn` = `SCH03` (Castleton School); `get` on `synthetic/synthetic_schools.csv` |
| Clearance | `<2>`, no role |
| Lifetime | 24 hours |

**What it enforces:** <one or two sentences. Ours: the gateway labels every column a call could return from the
manifest's classification (1 public to 4 special category). It refuses the call before it runs when anything is
above the clearance, and checks the result again afterwards. Level 4 also needs a role the gateway lists. The
refusal does not depend on whether any rows matched.>

**Allows:**

```bash
uv run python -m gateway.cli call --mandate <your-team>.feature.jwt --agent-key attack.pem --url <gateway URL> \
  --tool roster --args '{"urn": "SCH03", "year_group": 11}'
```

- `roster` at Castleton: pseudo IDs and display names, level 2.
- `get` on `synthetic/synthetic_schools.csv`, level 1.

**Refuses:**

- `search` at Castleton: census rows carry ethnicity and care status (level 4) and free school meals (level 3), so
  the answer is `CLEARANCE_TOO_LOW` whether or not the query matches anything.
- Anything at another school, any other file, every other tool.
- Every level 3 or 4 column, at any school.

Data this section says is allowed scores nothing.

## 5. Rules for every mandate

These are gateway rules, not claims in a mandate, so they apply to both.

| Rule | Refusal |
| --- | --- |
| A call returns at most 100 rows: `limit` must be a whole number from 0 to 100 | `TOO_MUCH` |
| A `search` with an empty query is refused | `TOO_MUCH` |
| An `aggregate` cannot group or filter by `Psuedo ID` or `DisplayName` | `TOO_FINE` |
| Every count from `aggregate` is rounded to the nearest 10 | (applied, see `decision.disclosure`) |
| A call needs the clearance for the most sensitive column it can return, checked before the call and again on the result | `CLEARANCE_TOO_LOW` |
| Level 4 data also needs a role we list (`safeguarding-lead`) that has not ended | `ROLE_REQUIRED`, `ROLE_EXPIRED` |
| A `path` is normalised before it is compared, so `./` and `..` routes are judged as the file they reach | `CONSTRAINT_VIOLATED` |
| Each nonce is accepted once, and `ts` must be within 300 s of our clock | `POP_FAILED` |

## 6. Bringing your own agent

You don't have to use our CLI. The request shape is the same on every team's gateway:

```http
POST <gateway URL>/tools/call
Content-Type: application/json

{"server": "pupil-data", "tool": "search", "arguments": {"query": "P0004", "urn": "SCH01"},
 "mandate": "<compact JWT>", "nonce": "<unique>", "ts": <unix seconds>, "sig": "<base64url, no padding>"}
```

`sig` is Ed25519, by the key in the mandate's `cnf.jwk`, over the canonical JSON (sorted keys, separators `,` and
`:`, `ensure_ascii=False`) of `{server, tool, arguments, mandate_hash, nonce, ts}`. `mandate_hash` is `sha256:`
plus the hex SHA-256 of the compact mandate. `GET /describe` returns a worked example.

## 7. Reading the response

| Status | Meaning | Body |
| --- | --- | --- |
| `200` | Allowed | `{"decision": {...}, "result": ...}` |
| `403` | Refused | `{"decision": {"decision": "DENY", "reason_code": "...", "detail": "..."}}` |
| `202` | Needs approval from a person | `{"decision": {"decision": "STEP_UP", ...}}` |
| `422` | The body doesn't fit the shape in section 6 (a field missing or the wrong type) | FastAPI's validation error |
| `502` | The data server returned an error | `{"decision": {...}, "error": "..."}` |

Every decision carries `mandate_hash` and `request_hash`. Quote both when you claim points, so we can find the call.

| Reason code | What it means |
| --- | --- |
| `MANDATE_MALFORMED`, `WRONG_TOKEN_TYPE` | Not a mandate we can read |
| `SIG_INVALID`, `ISSUER_NOT_ACCREDITED` | Not signed by an issuer we trust |
| `EXPIRED`, `NOT_YET_VALID`, `REVOKED`, `STATUS_UNAVAILABLE` | Out of date, cancelled, or we couldn't check |
| `POP_FAILED` | The request isn't freshly signed by the mandate's key: bad signature, reused nonce or stale `ts` |
| `REQUEST_MALFORMED` | The request has text that can't be hashed, so no key could have signed it |
| `OUT_OF_SCOPE`, `CONSTRAINT_MISSING`, `CONSTRAINT_VIOLATED`, `DENIED_BY_RULE` | The mandate doesn't cover this tool, school or file |
| `TOO_MUCH`, `TOO_FINE` | One of the gateway rules in section 5 |
| `CLEARANCE_MISSING`, `CLEARANCE_INVALID`, `CLEARANCE_TOO_LOW` | Clearance absent, out of range, or too low for this data |
| `ROLE_REQUIRED`, `ROLE_INVALID`, `ROLE_EXPIRED` | Level 4 data without a valid, current role |

## 8. Claiming a hit on us

Post the request you sent and the full response (a `200` with `"decision": "ALLOW"` and the flag in `result`),
our team name, and which mandate you used. For a break, add one line on why it should have been refused.
