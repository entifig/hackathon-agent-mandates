# Question 11: "Go through Elmwood's Year 11s one at a time and note who's on free school meals."

**Open question.** No eval cases and no required design.

**The problem.** The gateway decides each call on its own. The only thing it remembers between calls is which nonces
it has seen. Question 3 stops one call returning the whole school, but an agent that searches for one pupil at a
time ends up holding the same data, and every one of those calls is allowed. The same applies to counts: two answers
that are each safe to release can be subtracted to find one pupil.

**Worth working out:**

- What does the gateway need to remember, and against what: the mandate, the agent key, or the person?
- What is the limit counted in: calls, rows, or distinct pupils? What does an ordinary day's work look like, so that
  the limit does not stop it?
- When the limit is reached, does the gateway refuse, slow down, or ask the person?
- An agent with two mandates, or a helper agent from question 7, has two budgets. Should it?

**What to show:** an Elmwood mandate, a run of calls that is allowed, the call where the gateway stops the run, and
one sentence on what is still unresolved.

## What we did

A mandate can carry a signed **run budget**: the most *distinct pupils* whose data it may ever return, and
optionally the most calls. The gateway keeps a ledger per mandate and refuses the call that would go over.

```json
{"budget": {"pupils": 40, "calls": 100}}
```

Answers to the page's questions, as we decided them:

- **Counted in distinct pupils**, not rows or calls. Rows are not people: one pupil has several census rows, and
  looking the same pupil up twice reveals nothing new. Distinct pupils is what a leak is measured in, and it is what
  the Day 2 "Bulk" break counts. An ordinary day's work is a known cohort. Elmwood's spring 2023/24 Year 11 has
  38 pupils, so 40 lets the job finish with a little slack, and repeat lookups cost nothing.
- **Calls are capped as well**, for probing that names no pupil at all.
- **Remembered against the person and the job:** the ledger key is `(issuer, delegator.principal, budget.id or
  jti)`. With no `id`, each mandate has its own budget. An issuer who wants two mandates, or a parent and the helper
  it delegates to (question 7), to share one budget gives them the same `id`. The agent cannot change this, because
  the claim is signed.
- **Charged on the request, not the result.** Our first design forwarded the call and withheld the result if it
  went over. Our own red team broke it: `search` does a substring match over the whole row, so
  `"P0542,M,WHIT,1_ENG,0,1"` was withheld and `"...,0,0"` came back empty. The refusal had told them the pupil
  is in care, and it cost nothing. So a mandate with a budget now has these rules:
  - `search` must name exactly one pupil ID. The ID is charged *before* forwarding, whether or not it matches
    anything. Every yes or no depends only on the arguments and the ledger, never on the data.
  - `aggregate` is refused. Counts carry no pupil IDs, so there would be nothing to charge, and subtracting two
    counts can find one pupil.
  - Results that list pupils (`roster`) are still scanned for IDs as a backstop, and withheld whole if they would
    go over.
- **Refuse, not slow down.** Going slower does not shrink what the agent ends up holding. Asking the person
  (step-up) is the better long-term answer, but nobody approves a request in this hackathon.
- **The ledger persists** to `gateway/state/budget_ledger.json`, written atomically, so a restart does not hand
  out fresh budgets. If the file can't be read, the gateway refuses (`BUDGET_UNAVAILABLE`) and does not start over
  from empty.
- **A mandate without `budget` works exactly as before.** The eval and the default Day 2 mandate are unchanged.

### Holes closed on the way

The red team also found these, unrelated to budgets, and we closed them:

| Hole | Fix |
| --- | --- |
| `/demo/mandate` minted any mandate with the real issuer key, and `/demo/revoke` revoked anyone's | Demo routes are mounted only with `GATEWAY_DEMO=1`. They are on in docker-compose for the local walkthrough, and **must be off when deployed** |
| A garbage mandate, `ts=10**400` or deeply nested arguments gave a 500 | Each is now a DENY with a reason code, plus a catch-all handler that never returns a 500 |

## The mandate

The Day 2 feature mandate files are in [day_2_attack/feature_q11/](../day_2_attack/feature_q11/):
`make attack_mandates FEATURE_SCOPE=day_2_attack/feature_q11/feature_scope.json
FEATURE_CLAIMS=day_2_attack/feature_q11/feature_claims.json`.

Issue it to your agent key:

```bash
uv run python -m gateway.cli issue --agent-key gateway/state/agent.pem -o elmwood.jwt \
  --scope "$(cat day_2_attack/feature_q11/feature_scope.json)" \
  --claims "$(cat day_2_attack/feature_q11/feature_claims.json)"
uv run python -m gateway.cli decode elmwood.jwt
```

The main claims:

```json
{
  "delegator": {"principal": "officer:jsmith", "org": "school:SCH01", "authority": "hackathon"},
  "scope": [
    {"server": "pupil-data", "tools": ["roster"],
     "constraints": {"urn": ["SCH05"], "year_group": ["11"], "academic_year": ["2023/24"], "term": ["SPR"]}},
    {"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH05"]}}
  ],
  "deny": ["*.write", "pii.*"],
  "budget": {"pupils": 40, "calls": 100}
}
```

It allows Elmwood's spring 2023/24 Year 11 list (38 pupils), then one pupil at a time at Elmwood, up to 40
distinct pupils and 100 calls in all.

## A run of calls it allows

First the cohort. It costs 38 pupils:

```bash
uv run python -m gateway.cli call --mandate elmwood.jwt --agent-key gateway/state/agent.pem --tool roster \
  --args '{"urn": "SCH05", "year_group": 11, "academic_year": "2023/24", "term": "SPR"}'
```

```text
200  ALLOW IN_SCOPE   38 rows, 38 pupils (P1022 ... P1488)
"budget": {"pupils_used": 38, "pupils_limit": 40, "calls_used": 1, "calls_limit": 100}
```

Then one search per pupil, all 38 of them. Each pupil is already counted, so `pupils_used` stays at 38:

```bash
uv run python -m gateway.cli call --mandate elmwood.jwt --agent-key gateway/state/agent.pem --tool search --args '{"query": "P1022", "urn": "SCH05"}'
```

```text
200  ALLOW IN_SCOPE   5 rows, 1 pupil (P1022)
"budget": {"pupils_used": 38, "pupils_limit": 40, "calls_used": 2, "calls_limit": 100}
...
"budget": {"pupils_used": 38, "pupils_limit": 40, "calls_used": 39, "calls_limit": 100}   # after the 38th
```

Looking a pupil up again, or rerunning the roster, costs a call and no pupils. Two Elmwood pupils outside the cohort
(`P0007`, `P0060`) are allowed, using up the slack: `pupils_used` is now 40.

## The call where it stops the run

A 41st pupil. The gateway refuses **before forwarding**, from the arguments and the ledger alone:

```bash
uv run python -m gateway.cli call --mandate elmwood.jwt --agent-key gateway/state/agent.pem --tool search --args '{"query": "P0067", "urn": "SCH05"}'
```

```text
403  DENY BUDGET_EXHAUSTED
"pupils: the 1 new pupil(s) named do not fit, not forwarded; 40 of 40 distinct pupils used"
```

Once the budget is full, a listing tool is refused too (`roster`: `BUDGET_EXHAUSTED`, not forwarded), while
`search` for a pupil already counted still works. The run can finish its job, but it cannot widen.

Queries that are not exactly one pupil ID are refused whatever the budget, including the red team's oracle:

```bash
uv run python -m gateway.cli call --mandate elmwood.jwt --agent-key gateway/state/agent.pem --tool search --args '{"query": "2023/24", "urn": "SCH05"}'
uv run python -m gateway.cli call --mandate elmwood.jwt --agent-key gateway/state/agent.pem --tool search --args '{"query": "P0542,M,WHIT,1_ENG,0,1", "urn": "SCH05"}'
```

```text
403  DENY BUDGET_QUERY   "a budgeted mandate searches by one pupil ID only, e.g. query='P0004'"
```

## Still unresolved

- **The budget caps how many pupils, not which ones.** Inside 40 pupils, an agent can pick the ones it is most
  curious about: two pupils beyond the cohort, or a different 40 altogether if it skips the roster.
  Requiring "only IDs the roster returned" would close that, but it ties the gateway to one workflow.
- **One gateway, one process.** Two replicas, or a disk wiped on redeploy, would split or reset the ledger, and
  the nonce set with it.
- **A missing ledger file counts as a first run**, so whoever can delete files on the gateway can reset every
  budget.
- **Re-issuing is a new budget.** A new mandate without a shared `id` starts from zero, so the limit is only as
  good as the issuer's discipline.
