# Question 7: "Get a helper agent to draft Dunmore's absence letters. It only needs their Year 11 list."

**Open question.** No eval cases and no required design.

**The problem.** The agent wants to give a helper agent less access than it holds. Today the only way to share access
is to hand over its own mandate and key, and that hands over everything.

**Worth working out:**

- How does the gateway know a child mandate came from its parent?
- What counts as narrower: fewer tools, fewer allowed argument values, a shorter lifetime?
- What happens to the child when the parent is revoked?

**What to show:** a Dunmore mandate and a narrower one handed on from it, a helper request that is allowed, an attempt
to reach wider than the parent that is denied, and one sentence on what is still unresolved.

## What we did

The agent holding a Dunmore mandate hands a helper agent a **delegated child**: a smaller mandate that the agent
signs itself, with the key its own mandate names (`cnf`), without going back to the issuer. Make one with
`cli delegate` (see the README, "Handing a helper less access"). The code is in
[gateway/lib/delegation.py](../gateway/lib/delegation.py), with tests in
[gateway/tests/test_delegation.py](../gateway/tests/test_delegation.py).

Answers to the page's questions, as we decided them:

- **How the gateway knows a child came from its parent.** The child carries the whole parent mandate in a `parent`
  claim and is signed with the parent's `cnf` key, the same key the agent already proves it holds on every request.
  Its `iss` is that key's thumbprint as a URI (RFC 9278), and its own `cnf` is the helper's key. On every call the
  gateway verifies the parent in full (issuer, signature, dates, revocation), then the child's signature against
  the parent's key. Only the holder of the parent can make a child of it, and the helper cannot turn the child back
  into the parent: it has the parent token but not the parent's key (`POP_FAILED`).
- **What counts as narrower.** Each scope entry of the child must sit inside **one** parent entry: the same server,
  a subset of its tools, every parent constraint kept with a subset of its values. The child may add constraints
  of its own (`year_group`, `kind`). It must keep every parent deny rule, start no earlier and end no later than
  the parent, and have a budget no bigger. Anything else is `403 DELEGATION_WIDER`. As a backstop the request is
  checked against the child, then against the parent again.
- **What happens when the parent is revoked.** The child stops on the very next call, with `REVOKED` and
  `"parent mandate: <jti>"` in the detail, because the parent is re-verified on every call. The same goes for an
  expired parent, or one from an issuer that is no longer trusted.

Design decisions, and what we rejected:

- **One level only.** A child's parent must be an issuer-signed mandate; a child of a child is `DELEGATION_INVALID`.
  The format allows a chain, but every extra hop makes the narrower check and the audit trail harder to read, and
  "Dunmore's Year 11 letters" did not need one.
- **Who and why are inherited.** `delegator` and `purpose` come from the parent, and a child that sets them (or
  `status`, or any claim we do not know) is `DELEGATION_INVALID`. A helper's calls are logged under the person who
  granted the parent, so their own request log (question 16) shows them.
- **Budgets chain.** Every child call is charged to the parent's budget (question 11), and to the child's own if it
  has one, so an agent cannot get round its budget by handing out children. A child may not pick its budget `id`:
  the gateway gives it one, so it cannot borrow somebody else's ledger.
- **A child cannot read the request log.** `gateway.audit` answers "what was done in my name", and only the person
  should hold it, so a child granting server `gateway` is `DELEGATION_INVALID`.
- **Different `typ`, and `parent` reserved.** The child is `delegated-mandate+jwt`, so a gateway without this code
  refuses it (`WRONG_TOKEN_TYPE`) rather than reading it as a mandate. An issuer-signed mandate carrying `parent` is
  refused (`MANDATE_MALFORMED`), so the claim can only mean one thing.
- **Rejected: asking the issuer for every child.** That is safe, but it is the round trip the question wants to
  avoid, and the issuer does not know what the helper needs better than the agent does.
- **Rejected: a "may delegate" flag in the mandate.** An agent that holds a mandate and its key can always run the
  helper's calls itself, as a proxy. Forbidding children would not take any power away, it would only take away
  the narrowing and the log entry that says a helper did it. We would rather see it.
- **Rejected: sharing the agent's key with the helper.** That hands over everything, which is the problem.

A mandate with no delegation works exactly as before: the eval passes 32/32, and all the earlier tests pass.

## The mandate

Dunmore Community College is `SCH04`. The agent's mandate, as the issuer signed it (decoded with `cli decode`):

```json
{
  "iss": "https://issuer.hack.local",
  "jti": "urn:uuid:5c2cea5c-148b-4341-af45-bfb79026ee57",
  "nbf": 1795524016, "exp": 1795552816,
  "vct": "urn:hack:mandate:v1",
  "delegator": {"principal": "officer:jsmith", "org": "school:SCH04", "authority": "hackathon"},
  "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": "Nc1hCfmp8Epr_ZHqETl-p_uJFM-rXuz10twT9IGZkZc"}},
  "agent_id": "KvkVwHlf17PTVHWfnZ9dRhPlZt-rhT4qim1VPZeRibo",
  "purpose": "Dunmore absence letters",
  "scope": [
    {"server": "pupil-data", "tools": ["roster", "search", "pupil", "draft"], "constraints": {"urn": ["SCH04"]}}
  ],
  "deny": ["*.write", "pii.*"],
  "status": {"status_list": {"uri": "https://issuer.hack.local/status/1", "idx": 0}}
}
```

Every list, pupil and letter at Dunmore, for 8 hours.

## The child

The agent hands the helper the Year 11 list and absence letters, for one hour:

```bash
uv run python -m gateway.cli delegate --mandate dunmore.jwt --agent-key agent.pem --helper-key helper.jwk \
  --ttl 3600 -o helper.jwt --scope '[
    {"server": "pupil-data", "tools": ["roster"],
     "constraints": {"urn": ["SCH04"], "year_group": ["11"], "academic_year": ["2023/24"], "term": ["SPR"]}},
    {"server": "pupil-data", "tools": ["draft"], "constraints": {"urn": ["SCH04"], "kind": ["absence"]}}]'
```

Header `{"alg": "EdDSA", "typ": "delegated-mandate+jwt", "kid": "KvkVwHlf17PTVHWfnZ9dRhPlZt-rhT4qim1VPZeRibo"}`.
Claims:

```json
{
  "iss": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:KvkVwHlf17PTVHWfnZ9dRhPlZt-rhT4qim1VPZeRibo",
  "jti": "urn:uuid:dbdf70ba-0d03-4099-a287-c582cef0b316",
  "nbf": 1795524016, "exp": 1795527616,
  "vct": "urn:hack:mandate:delegated:v1",
  "parent": "eyJhbGciOiJFZERTQSIsImtpZCI6Imlzc3Vlci0y...",
  "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": "znrc0hwbb74XyyUQ10MUlQwRhmm7WG4fx0G0tl1ZlEA"}},
  "agent_id": "TTIDa133ZAHuQowq49DrRJxEcO_GPghRmz1kK0u96jE",
  "scope": [
    {"server": "pupil-data", "tools": ["roster"],
     "constraints": {"urn": ["SCH04"], "year_group": ["11"], "academic_year": ["2023/24"], "term": ["SPR"]}},
    {"server": "pupil-data", "tools": ["draft"], "constraints": {"urn": ["SCH04"], "kind": ["absence"]}}
  ],
  "deny": ["*.write", "pii.*"]
}
```

`iss` is the agent's key, the one in the parent's `cnf`; `cnf` is the helper's. `parent` is the whole Dunmore
mandate (shortened here; `cli decode` shows it decoded). There is no `delegator`, `purpose` or `status`: those come
from the parent.

## A helper request it allows

```bash
uv run python -m gateway.cli call --mandate helper.jwt --agent-key helper.pem --tool roster \
  --args '{"urn": "SCH04", "year_group": 11, "academic_year": "2023/24", "term": "SPR"}'
```

```text
200  ALLOW IN_SCOPE   agent_id TTIDa133ZAHuQowq49DrRJxEcO_GPghRmz1kK0u96jE (the helper)
41 rows: {"Psuedo ID": "P1017", "DisplayName": "Hana Walsh"}, {"Psuedo ID": "P1027", ...}, ...
```

Then a letter:

```text
draft {"urn": "SCH04", "pupil_ids": ["P1017"], "kind": "absence"}
202  STEP_UP SENSITIVE_TOOL   "*.draft"
```

This gateway holds every `*.draft` for a person to approve, and a child does not get round that. The request log
files both calls under the parent:

```text
$ uv run python -m gateway.cli audit --jti urn:uuid:5c2cea5c-148b-4341-af45-bfb79026ee57
#0 ALLOW IN_SCOPE officer:jsmith jti=urn:uuid:dbdf70ba-... parent=urn:uuid:5c2cea5c-... jkt=TTIDa133ZA pupil-data.roster {...,"year_group":11} -> 200 rows=41 pupils=P1017,P1027,...
#1 STEP_UP SENSITIVE_TOOL officer:jsmith jti=urn:uuid:dbdf70ba-... parent=urn:uuid:5c2cea5c-... jkt=TTIDa133ZA pupil-data.draft {"kind":"absence","pupil_ids":["P1017"],"urn":"SCH04"} -> 202
```

## Requests it denies

Reaching past the child, with the child as made:

| Request | Answer |
| --- | --- |
| `roster` with `year_group: 10` | `403 CONSTRAINT_VIOLATED` `year_group=10` |
| `search` for `P1017` at Dunmore (the parent may, the child may not) | `403 OUT_OF_SCOPE` |
| `draft` with `kind: "attendance_meeting"` | `403 CONSTRAINT_VIOLATED` |
| The parent mandate lifted out of the child, signed with the helper's key | `403 POP_FAILED` |

**Reaching wider than the parent.** The agent makes a child for Dunmore *and* Elmwood (`SCH05`). Its own tool
refuses:

```text
$ uv run python -m gateway.cli delegate ... --scope '[{"server": "pupil-data", "tools": ["roster"],
    "constraints": {"urn": ["SCH04", "SCH05"], "year_group": ["11"]}}]'
not delegated: DELEGATION_WIDER: scope[0] pupil-data.['roster'] is not inside any one parent scope entry
```

With `--no-check` it signs it anyway, and the helper asks for Elmwood's Year 11:

```text
403  DENY DELEGATION_WIDER
"scope[0] pupil-data.['roster'] is not inside any one parent scope entry"
```

The gateway refuses the child as a whole, whatever it is asked: a child that claims more than its parent is not one
we honour at all. And once the issuer revokes the Dunmore mandate, the helper's own valid child stops too:

```text
403  DENY REVOKED   "parent mandate: urn:uuid:5c2cea5c-148b-4341-af45-bfb79026ee57"
```

### Our red team

Each attack is a test in [gateway/tests/test_delegation.py](../gateway/tests/test_delegation.py):

| Attack | Answer |
| --- | --- |
| Wider tools, another server, wider values, a dropped constraint, no constraints | `DELEGATION_WIDER` |
| Mixing constraints from two parent entries (`urn` from one, `path` from the other) | `DELEGATION_WIDER` |
| A dropped deny rule, a longer `exp`, an earlier `nbf`, a bigger budget | `DELEGATION_WIDER` |
| A child signed by a stranger's key, or by the helper itself; an `iss` that is not the parent's key | `DELEGATION_INVALID` |
| A child dressed as an issuer-signed `mandate+jwt` | `SIG_INVALID` |
| An issuer-signed mandate with a `parent` claim | `MANDATE_MALFORMED` |
| A child of a revoked / expired / untrusted-issuer / tampered parent | `REVOKED` / `EXPIRED` / `ISSUER_NOT_ACCREDITED` / `SIG_INVALID` |
| A child of a child | `DELEGATION_INVALID` ("depth is limited to 1") |
| A helper with no budget under a budgeted parent, to get past the parent's 2 pupils | the 3rd pupil is `BUDGET_EXHAUSTED` ("parent mandate's budget"), and so is the parent's own next one |
| A child budget with its own `id`, to share another ledger | `DELEGATION_INVALID` |
| A child granting `gateway.audit` | `DELEGATION_INVALID` |
| `parent` as `"garbage"`, `5`, `null`, a list, an object, `"a.b.c"`, 5000 characters; a child that sets `purpose`, `delegator` or `status`; a bad `cnf`, `scope`, `exp` | `403`, never a 500 |
| The same signed request twice; a request with the child signed by the agent's key, not the helper's | `POP_FAILED` |
| The narrower check switched off (monkeypatched) | the parent's scope still refuses: `DELEGATION_WIDER` |

## Still unresolved

- **A child cannot be revoked on its own.** It has no status entry, so to stop one helper the issuer revokes the
  parent, and the agent and every other helper stop too. A short `--ttl` is the only other control. A
  gateway-side list of revoked child `jti`s, filed by the agent, would fix this.
- **"Only their Year 11 list" holds for the roster, not the letters.** `draft` takes a list of `pupil_ids`, and a
  constraint cannot say "only IDs the roster returned", so the helper may ask for a letter for any Dunmore pupil it
  can name. Here the step-up stops it, but the gateway cannot narrow it.
- **The helper sees names.** The roster returns display names as well as IDs, which the letters need. The child
  narrows *which* pupils, not *which fields*.
- **Only this gateway understands children.** Other teams' gateways refuse `delegated-mandate+jwt`, which is safe
  but means a child is useless there.
- **The child carries the whole parent.** Anyone who sees the child can read everything the agent may do. The
  parent cannot be used without the agent's key, but its scope is no secret.
