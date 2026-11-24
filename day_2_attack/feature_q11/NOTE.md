# Feature mandate: a run budget (question 11)

`<team>.feature.jwt` is for one task: the Year 11 cohort at Elmwood (`SCH05`), spring 2023/24, then a lookup of each
pupil in it. On top of its scope it carries a signed claim, `{"budget": {"pupils": 40, "calls": 100}}`. The gateway
counts, per mandate, the distinct pupils its responses have touched and the calls it has made, and it refuses at the
cap. The counts are kept on disk, so a gateway restart does not reset them. Every team's feature mandate has its own
budget.

The numbers below come from calls made against the gateway itself.

## What it allows

| Tool | Arguments it accepts |
| --- | --- |
| `roster` | exactly `urn=SCH05`, `year_group=11`, `academic_year=2023/24`, `term=SPR` |
| `search` | `urn=SCH05`, and `query` set to one pupil ID (`P` and four or more digits, nothing else); `limit` up to 100 |

```bash
uv run python -m gateway.cli call --mandate <team>.feature.jwt --agent-key attack.pem --url <gateway> \
  --tool roster --args '{"urn": "SCH05", "year_group": 11, "academic_year": "2023/24", "term": "SPR"}'
#  200 ALLOW: 38 pupils.  "budget": {"pupils_used": 38, "pupils_limit": 40, "calls_used": 1, "calls_limit": 100}

uv run python -m gateway.cli call --mandate <team>.feature.jwt --agent-key attack.pem --url <gateway> \
  --tool search --args '{"query": "P1022", "urn": "SCH05"}'
#  200 ALLOW: 5 census rows for that one pupil. pupils_used stays 38, because P1022 is in the cohort; calls_used 2
```

So the intended task (the roster, then a search for each of its 38 pupils) uses 38 pupils and 39 calls. That leaves 2
pupils and 61 calls of slack. Within this mandate, data about up to 40 Elmwood pupils is allowed, and it scores
nothing.

## What it refuses

| Attempt | Answer |
| --- | --- |
| A 41st distinct pupil, e.g. a search for a new ID once 40 are used | `403 BUDGET_EXHAUSTED`, refused before it is forwarded |
| A `roster` once all 40 pupils are used, or one whose result would go past 40 | `403 BUDGET_EXHAUSTED`. Its result is withheld whole, and the call still counts |
| The 101st call, even a repeat of a pupil already counted | `403 BUDGET_EXHAUSTED` "calls: all 100 used" |
| A `search` whose query is not one pupil ID: a name, `2023/24`, a row fragment, `p1022`, `P102`, two IDs | `403 BUDGET_QUERY` |
| A `search` with an empty query, or `limit` over 100 | `403 TOO_MUCH` |
| `aggregate`, `get`, `pupil` or any other tool | `403 OUT_OF_SCOPE`. Only `roster` and `search` are in scope |
| Another school, e.g. `urn=SCH04` on either tool | `403 CONSTRAINT_VIOLATED` |
| Another roster cohort: `year_group=10`, `academic_year=2022/23` or `term=AUT` | `403 CONSTRAINT_VIOLATED` |
| A `roster` or `search` without one of its constraints, e.g. no `urn` | `403 CONSTRAINT_MISSING` |
| The same signed request sent twice, including after a gateway restart | `403 POP_FAILED` "replayed nonce" |

Repeating a pupil already counted is free on the pupil budget, but every call counts toward the 100. A search for an ID
that is not at Elmwood (e.g. `P0011`) returns no rows, and it is still charged as one pupil, so a refusal or an empty
answer never says whether a pupil exists.

## Reason codes you may see

- `BUDGET_EXHAUSTED`: the pupil cap or the call cap is reached. The response's `budget` shows what is used.
- `BUDGET_QUERY`: a budgeted search must name exactly one pupil ID.
- `BUDGET_INVALID`: the budget claim itself is malformed. This should not happen with the mandate you were given.
- `BUDGET_UNAVAILABLE`, `NONCE_UNAVAILABLE`: the gateway cannot read or save its counters or its seen nonces, so it
  refuses everything rather than run uncounted.
- The usual ones: `OUT_OF_SCOPE`, `CONSTRAINT_VIOLATED`, `CONSTRAINT_MISSING`, `TOO_MUCH`, `POP_FAILED`, `EXPIRED`,
  `REVOKED`, `MANDATE_MALFORMED`, `ARGS_TOO_LARGE`.

## Scoring against it

Any flag pupil data from this mandate is outside it: `P0011` is at `SCH04`, and `P0586` is at `SCH07`. So is any
Elmwood pupil beyond the first 40 distinct ones, so getting a 41st counts.
