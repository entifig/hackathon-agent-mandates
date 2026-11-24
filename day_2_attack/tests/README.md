# How the defensive eval relates to Day 2 scoring

Run `.venv/bin/python -m pytest day_2_attack/tests` from the repo root. The checks run offline. Record their failures as defensive findings. Competition points require evidence from the posted gateway.

| Eval finding | Relevant scoring rule | Evidence required |
| --- | --- | --- |
| Aggregate filter clearance | The updated gateway labels filter columns. This regression check now passes. | A future data claim still needs a response establishing an out-of-scope fact about the flag pupil. |
| Unclassified JSON file labelled public | Conditional data flag. Fixed: a file with no label is the top level, and only the manifest is public. | A feature mandate would have to permit the file read, and the result would have to establish a qualifying fact outside the mandate's clearance. The fixture contains no flag. |
| Demo administration routes mounted | Forged mandate, 30 points once per target. Fixed: mounted only with `GATEWAY_DEMO=1`. | Evidence that the gateway accepted an unauthorized mandate. Route registration alone earns zero. |
| JWT parser exception escapes the verifier | Crash, 5 points once per target. Fixed: `MANDATE_MALFORMED`, a 403. | A single request that causes the posted gateway to return HTTP 500 or stop answering. The offline exception alone earns zero. |

For each target, count the highest qualifying data flag separately for the default and feature mandates. Add each proven gateway break once. A feature flag must fall outside the posted feature scope and its accompanying note.

On defense, a level-2-or-higher flag costs the 30-point clean sheet for the default mandate or the 20-point feature-held bonus for the feature mandate used. Both bonuses require questions 0–5 to pass on the deployed gateway at the end. The feature bonus also requires a mandate posted by the end of Day 2 morning that allows at least one real request for its intended job. [Official scoring rules](../ATTACK_SCORING.md)

## Gateway-break coverage

The separate suite now includes real signed requests through the HTTP handler, temporary issuer and agent keys, and a fixture MCP server. Each authentication test first proves an authorized request succeeds, then checks that the rejected request never reaches the upstream server.

| Scored break | Points | Current coverage |
| --- | --- | --- |
| Keys | 50 | Three discovery responses checked for the fixture issuer's PEM and raw private key component. Other response paths remain untested for key disclosure. |
| Forged mandate | 30 | Edited claims and an untrusted issuer are rejected. The public demo routes that issued a SCH04 mandate and signed a call returning a fixture flag row now answer 404 unless `GATEWAY_DEMO=1`; the test checks each is refused and nothing reaches the upstream server. |
| Dead mandate | 15 | Expired and revoked mandates are rejected through the HTTP handler. |
| No key | 15 | Empty signature, invalid signature, another signing key, replay, stale and future timestamps, and changed signed arguments are rejected. A replay after gateway state reload is rejected too: accepted nonces are kept in the state directory. Cross-replica behavior remains untested, and one file does not cover it. |
| Bulk | 10 | Existing gateway tests reject oversized individual requests. Extraction of more than 100 distinct out-of-scope pupils across multiple requests remains untested. |
| Unseen | 10 | Requires a successful data flag and the defending team's five-minute record lookup. No automated coverage. |
| Crash | 5 | Malformed mandate requests are a 403 in the isolated HTTP test, and the parser exception check passes. The gateway's own tests add a payload with no `iss`, an oversized `ts`, a lone surrogate in the arguments and malformed `aggregate` arguments. |

Rechecked on `fix/review-clearance-holes` after merging main at cbb7741: every check in this directory passes. `test_public_demo_routes_cannot_mint_or_use_an_out_of_scope_mandate` was the finding test for the demo routes and now asserts the refusal. Deployment evidence is still required for competition claims.

Earlier state, rechecked after merging main at 21dda34. The aggregate filter test now passes. Eight defensive checks still fail, including public demo issuance with a fixture flag row, three malformed mandates returning HTTP 500, replay after state reload, demo route exposure, a parser exception, and unknown JSON classification. The existing gateway suite passes and includes the questions 0–5 pack against an in-process upstream. Deployment evidence is still required for competition claims.
