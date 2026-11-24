# Question 14: "I gave it too much yesterday. Take it back, and tell me what it saw."

**Open question.** No eval cases and no required design.

**The problem.** Revoking a mandate stops the next call. It does nothing about what the agent has already been
sent, and the starter gateway keeps no record of its decisions (`tools_call` in `gateway/main.py` marks where one
would go). The administrator cannot find out what their agent took, so they cannot tell anyone whose data it was.

**Worth working out:**

- What goes in the record: the decision, the arguments, the rows returned, or a summary of them?
- A record of everything an agent saw is itself a copy of the sensitive data. Who may read it?
- Can whoever runs the gateway change or delete an entry afterwards? How would anyone find out?
- What can a person who is not technical read from it?

**What to show:** a mandate, the requests made with it before it was revoked, the record the administrator reads
afterwards, and one sentence on what is still unresolved.

## What we did

The gateway now writes every decision to an append-only, hash-chained log, `gateway/state/audit.jsonl` (or the
path in `GATEWAY_AUDIT_LOG`). That covers allowed, refused and held calls, and calls whose mandate did not verify.
The code is in `gateway/lib/audit.py`, and `gateway/main.py` gains a few hook lines marked `AUDIT(q14/q16)`. For a
call that was answered, the entry keeps a **summary** of what went out, not the rows themselves: the row count, the
column names, the sorted pupil IDs, the school codes and the HTTP status. Each entry is fsync'd before the response
leaves the gateway. If the log cannot be written, the call is refused with `403 AUDIT_UNAVAILABLE`, so nothing is
sent unrecorded, and `/healthcheck` returns 503 from startup onwards.

The output below is from a real run on a scratch state, with the gateway on `:28082`. The commands are written
against the repo defaults.

### The mandate

The default one from `make gateway_issue`, decoded as on [the worked example](02-worked-example.md): `search` at
`SCH01` and `get` on the two files with no pupil data, granted by `officer:jsmith`, status index 0.

### The requests made with it, then the revocation

```bash
call() { uv run python -m gateway.cli call --mandate gateway/state/mandate.jwt --agent-key gateway/state/agent.pem "$@"; }
call --tool search --args '{"query": "P0004", "urn": "SCH01", "limit": 1}'   # 200 ALLOW, P0004
call --tool search --args '{"query": "SPR", "urn": "SCH01", "limit": 3}'     # 200 ALLOW, P0004 P0022 P0037
call --tool get --args '{"path": "synthetic/synthetic_schools.csv"}'          # 200 ALLOW
call --tool search --args '{"query": "SPR", "urn": "SCH02"}'                  # 403 CONSTRAINT_VIOLATED urn='SCH02'
# ... question 16's stolen-key calls ...
uv run python -m gateway.cli revoke --idx 0                                    # "I gave it too much"
call --tool search --args '{"query": "P0004", "urn": "SCH01", "limit": 1}'   # 403 REVOKED
```

### The record the administrator reads afterwards

The operator searches by pupil, by mandate or by decision, and checks that nothing was edited:

```bash
uv run python -m gateway.cli audit --decision ALLOW --plain
```

```text
5 requests made with the matching mandates, 24 Nov 11:51 UTC to 24 Nov 11:51 UTC: 5 allowed, 0 refused, 0 held for approval.
Pupils whose data was sent: 3 (P0004, P0022, P0037).
Agent keys used: agent key VASXdF… (4), agent key Lf84B3… (1).
Sent from: 127.0.0.1 (5).
24 Nov 11:51 UTC: agent key VASXdF… from 127.0.0.1 searched pupil-data for 'P0004' at SCH01 and was sent 1 row about 1 pupil (P0004): allowed
24 Nov 11:51 UTC: agent key VASXdF… from 127.0.0.1 searched pupil-data for 'SPR' at SCH01 and was sent 3 rows about 3 pupils (P0004, P0022, P0037): allowed
24 Nov 11:51 UTC: agent key VASXdF… from 127.0.0.1 opened synthetic/synthetic_schools.csv and was sent 12 rows with no pupil IDs in it: allowed
24 Nov 11:51 UTC: agent key VASXdF… from 127.0.0.1 searched pupil-data for 'P0037' at SCH01 and was sent 1 row about 1 pupil (P0037): allowed
24 Nov 11:51 UTC: agent key Lf84B3… from 127.0.0.1 read the request log for officer:jsmith: allowed
```

That is the answer to "what did it see": three pupils, and these are the people to tell. (The `Lf84B3…` line is
the person reading their own log, from question 16.) `--pupil` goes the other way, from a pupil to every request
that named them, refusals included:

```bash
uv run python -m gateway.cli audit --pupil P0022
```

```text
#1 2026-11-24T11:51:37Z ALLOW IN_SCOPE officer:jsmith jti=urn:uuid:74b001ce-… idx=0 jkt=VASXdFScx5 from=127.0.0.1 pupil-data.search {"limit":3,"query":"SPR","urn":"SCH01"} -> 200 rows=3 pupils=P0004,P0022,P0037
```

The full entry stores the column names but no values from the rows:

```json
{
  "seq": 1, "at": "2026-11-24T11:51:37Z",
  "decision": {"decision": "ALLOW", "reason_code": "IN_SCOPE", "agent_id": "VASXdFScx5SYgmO_DPJGi-wO09GMcpn2KeLkDvuzqlY",
               "mandate_hash": "sha256:875c6f9f…", "request_hash": "sha256:8423c34a…", ...},
  "mandate": {"verified": true, "jti": "urn:uuid:74b001ce-3db6-4353-be81-f9193c6a0a4e", "iss": "https://issuer.hack.local",
              "principal": "officer:jsmith", "org": "school:SCH01", "jkt": "VASXdFScx5SYgmO_DPJGi-wO09GMcpn2KeLkDvuzqlY",
              "status_idx": 0, "purpose": "Pupil-data lookups for school SCH01", "exp": 1795528296},
  "client": {"addr": "127.0.0.1"},
  "server": "pupil-data", "tool": "search", "arguments": {"limit": 3, "query": "SPR", "urn": "SCH01"},
  "status": 200,
  "released": {"rows": 3, "pupils": ["P0004", "P0022", "P0037"], "schools": ["SCH01"],
               "columns": ["AcademicYear", "AgeAtStartOfAcademicYear", "CensusTerm", "EnrolStatus", "Ethnicity",
                           "FSMeligible", "Gender", "InCareAtCurrentSchool", "Language", "Psuedo ID", "URN"]},
  "prev": "sha256:0419d728…", "hash": "sha256:ac889c26…"
}
```

### Can the operator change it afterwards?

Not without it showing, as long as someone kept an earlier head hash. Each entry carries the hash of the one
before it (`prev`), and its own `hash` covers its whole content. In this test we removed one pupil from what entry
1 says was sent, and deleted entry 3:

```bash
uv run python -m gateway.cli audit --verify                           # chain OK: 13 entries, head sha256:f057fa6e…
uv run python -m gateway.cli audit --file tampered.jsonl --verify     # chain BROKEN at line 1: hash does not match
                                                                      # the entry's content (the entry was edited); exit 1
```

### Still unresolved

- **Nothing outside the gateway anchors the chain.** Whoever runs the gateway can rewrite the whole file and
  recompute every hash, or cut entries off the end, and `--verify` still says OK. Publishing the head hash somewhere
  the operator cannot rewrite would close this, for example to the person on every read (the audit read already
  returns `chain.head`), or to another team's gateway, or to a transparency log.
- **Revocation does not recall anything.** The log says exactly which pupils' data left the gateway. It cannot
  bring that data back or show what the agent did with it afterwards.
- **The log is itself level-2 data.** It holds pupil IDs, school codes, search terms and who asked, so it needs the
  same protection as the data. We kept row values out, but `arguments` hold whatever the agent typed. A search for a
  pupil's name would be stored as typed.
- **It only finds what has an ID.** A summary with no pupil ID in it, such as an aggregate count of one or a row
  matched only by name, is logged as a row count, and `--pupil` will not find it.
- **It only sees traffic through the gateway.** Calls that go straight to `:8080` leave no entry.
