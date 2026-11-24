# Question 16: "I think someone may have taken my access. Can I see a log of the requests made with it?"

**Open question.** No eval cases and no required design.

**The problem.** The gateway decides every call and remembers none of them (`tools_call` in `gateway/main.py` marks
where a record would go). If an agent key leaks, the person who granted the mandate cannot see what was asked for
in their name, when, or from where. Question 14 asks what the agent saw. This one asks who was using the access.

**Worth working out:**

- What does a record need to show someone that a call was not theirs: the time, the agent key, the source address,
  the arguments?
- The person has no key of their own, only the mandates they granted. How do they prove the log is theirs to read,
  and how is someone else's activity kept out of what they see?
- Whoever stole the access can also ask for the log. What should they get?
- If a request was refused, does it belong in the log? A run of refusals may be the first sign of a stolen key.

**What to show:** a mandate whose key someone else has used, the log its person is shown, a request for another
person's log that is denied, and one sentence on what is still unresolved.

## What we did

The log is the same one as [question 14](14-what-did-it-see.md#what-we-did): every decision, refusals included,
written to `gateway/state/audit.jsonl` (or `GATEWAY_AUDIT_LOG`) before the response goes out. Each entry records
the time, the mandate (`jti`, issuer, `delegator.principal`, agent-key thumbprint `jkt`), the source address (with
any `X-Forwarded-For`), the server, tool and arguments, and the outcome. If the mandate does not verify, its claims
are still read and recorded, marked `"verified": false`. A forged mandate that names you therefore shows up in your
log as a warning, and does not simply vanish.

The person reads it through the gateway like any other tool: `server: "gateway", tool: "audit"`. The request shape
of `POST /tools/call` does not change. The gateway answers this call itself and never forwards it.

The output below is from a real run on a scratch state, with the gateway on `:28082`. The commands are written
against the repo defaults.

### A mandate whose key someone else has used

The default agent mandate (`officer:jsmith`, `search` at `SCH01`, agent key `VASXdF…`). After the agent's own calls
from question 14, someone else gets hold of it:

| What they hold | Request | Result |
| --- | --- | --- |
| a copy of the mandate, their own key | `search` P0011 at `SCH01` | `403 POP_FAILED` bad signature for jkt `VASXdF…` |
| the mandate and the agent's private key | `search` P0037 at `SCH01` | `200 IN_SCOPE`, sent P0037 |
| the same signed request, replayed | the same | `403 POP_FAILED` replayed nonce |
| the stolen key | `search` P0011 at `SCH04` | `403 CONSTRAINT_VIOLATED` urn='SCH04' |
| the stolen key | `get` the names file | `403 CONSTRAINT_VIOLATED` path='synthetic/synthetic_display_names.csv' |
| the stolen key | `gateway.audit` for `officer:jsmith` | `403 OUT_OF_SCOPE` gateway.audit |

The last row answers "whoever stole the access can ask for the log": an agent mandate has no `gateway` scope, so
the thief is refused, and that refusal goes into the log too.

### The mandate the person reads with

The person has no key of their own yet, so they make one and are issued a mandate that grants only `gateway.audit`,
pinned to their own principal:

```bash
uv run python -m gateway.cli keygen -o gateway/state/person.pem > gateway/state/person.jwk
uv run python -m gateway.cli issue --agent-key gateway/state/person.jwk -o gateway/state/my_log.jwt --ttl 3600 \
  --purpose 'Read the request log of mandates I granted' --deny '[]' \
  --scope '[{"server": "gateway", "tools": ["audit"], "constraints": {"principal": ["officer:jsmith"]}}]'
```

```json
{
  "delegator": {"principal": "officer:jsmith", "org": "school:SCH01", "authority": "hackathon"},
  "purpose": "Read the request log of mandates I granted",
  "agent_id": "Lf84B3fzCfI326qxLhrzMsc5KxCfCIgZTShsRbVG86s",
  "scope": [{"server": "gateway", "tools": ["audit"], "constraints": {"principal": ["officer:jsmith"]}}],
  "deny": []
}
```

`principal` is an ordinary constraint, so the existing scope check (`check_request` in `gateway_verify.py`) enforces
it: `arguments.principal` must be in the list. As a second line of defence, the audit handler also refuses a
`gateway.audit` grant that does not pin `principal` (`CONSTRAINT_MISSING`). An unpinned grant would otherwise let
the holder read anyone's log. The optional arguments are `jti` (one mandate), `since` (epoch or ISO time) and
`limit` (the last N entries, up to 100).

### The log the person is shown

```bash
uv run python -m gateway.cli call --mandate gateway/state/my_log.jwt --agent-key gateway/state/person.pem \
  --server gateway --tool audit --args '{"principal": "officer:jsmith"}'
```

```text
200
{
  "decision": {"decision": "ALLOW", "reason_code": "IN_SCOPE"},
  "result": {
    "principal": "officer:jsmith",
    "summary": [
      "11 requests made with mandates naming you, 24 Nov 11:51 UTC to 24 Nov 11:51 UTC: 4 allowed, 7 refused, 0 held for approval.",
      "Pupils whose data was sent: 3 (P0004, P0022, P0037).",
      "Agent keys used: agent key VASXdF… (11).",
      "Sent from: 127.0.0.1 (11).",
      "7 refused: outside the mandate (4); not signed by the mandate's agent key, or a replayed request: someone else may hold a copy (2); the mandate had been cancelled (1).",
      "Warning: 2 requests carried a mandate naming you but were not properly signed or the mandate was altered. Someone else may hold a copy of it."
    ],
    "lines": [
      "24 Nov 11:51 UTC: agent key VASXdF… from 127.0.0.1 searched pupil-data for 'P0004' at SCH01 and was sent 1 row about 1 pupil (P0004): allowed",
      "24 Nov 11:51 UTC: agent key VASXdF… from 127.0.0.1 searched pupil-data for 'SPR' at SCH01 and was sent 3 rows about 3 pupils (P0004, P0022, P0037): allowed",
      "24 Nov 11:51 UTC: agent key VASXdF… from 127.0.0.1 opened synthetic/synthetic_schools.csv and was sent 12 rows with no pupil IDs in it: allowed",
      "24 Nov 11:51 UTC: agent key VASXdF… from 127.0.0.1 searched pupil-data for 'SPR' at SCH02: refused (outside the mandate)",
      "24 Nov 11:51 UTC: agent key VASXdF… from 127.0.0.1 searched pupil-data for 'P0011' at SCH01: refused (not signed by the mandate's agent key, or a replayed request: someone else may hold a copy)",
      "24 Nov 11:51 UTC: agent key VASXdF… from 127.0.0.1 searched pupil-data for 'P0037' at SCH01 and was sent 1 row about 1 pupil (P0037): allowed",
      "24 Nov 11:51 UTC: agent key VASXdF… from 127.0.0.1 searched pupil-data for 'P0037' at SCH01: refused (not signed by the mandate's agent key, or a replayed request: someone else may hold a copy)",
      "24 Nov 11:51 UTC: agent key VASXdF… from 127.0.0.1 searched pupil-data for 'P0011' at SCH04: refused (outside the mandate)",
      "24 Nov 11:51 UTC: agent key VASXdF… from 127.0.0.1 opened synthetic/synthetic_display_names.csv: refused (outside the mandate)",
      "24 Nov 11:51 UTC: agent key VASXdF… from 127.0.0.1 read the request log for officer:jsmith: refused (outside the mandate)",
      "24 Nov 11:51 UTC: agent key VASXdF… from 127.0.0.1 searched pupil-data for 'P0004' at SCH01: refused (the mandate had been cancelled)"
    ],
    "entries": ["... the 11 full entries, as in question 14 ..."],
    "total": 11, "shown": 11,
    "chain": {"ok": true, "entries": 11,
              "head": "sha256:29dd2cbc088bf445014201e704d85ed5150e2f2343254898cd3ad4201b157b75"}
  }
}
```

The person never made a request for P0011, for `SCH04` or for the names file, and never tried to read the log
with the agent's mandate. The run of refusals, plus the warning about two badly signed requests, is what tells them
somebody else holds the mandate.

### A request for another person's log, denied

```bash
uv run python -m gateway.cli call --mandate gateway/state/my_log.jwt --agent-key gateway/state/person.pem \
  --server gateway --tool audit --args '{"principal": "officer:kpatel"}'
```

```text
403
{"decision": {"decision": "DENY", "reason_code": "CONSTRAINT_VIOLATED", "detail": "principal='officer:kpatel'", ...}}
```

The refusal is in the log under `officer:jsmith`, so the person sees their own key's attempt as well.

### Still unresolved

- **A stolen key in scope looks just like the agent.** The 200 for P0037 at `SCH01` has the same agent key, the
  same mandate and, on one machine, the same address as the agent's real calls. Only the refusals around it give the
  thief away. A careful thief who stays inside the mandate leaves nothing to tell them apart.
- **The address tells you little.** It is the TCP peer, so behind a proxy or load balancer every call has the same
  address, and `X-Forwarded-For` is recorded as sent but anyone can set it. In this run every call, the thief's
  included, came from `127.0.0.1`.
- **The `POP_FAILED` line names the mandate's key, not the thief's.** The gateway does not keep the key that made
  the bad signature, so the log shows that something is wrong but cannot show who did it.
- **Unverified entries are not trustworthy.** Anyone can send garbage carrying a mandate that names `officer:jsmith`,
  and it will appear (marked unverified) in their log. That is useful as a warning, but someone could also use it
  to flood the log or make the person suspicious.
- **No external anchor** (as in question 14): the person is shown `chain.head`, but nothing stops the operator from
  rewriting the file before the next read. The person would have to keep the head hashes themselves, or the gateway
  would have to publish them, for a later rewrite to show.
