# How the defensive eval relates to Day 2 scoring

Run `.venv/bin/python -m pytest day_2_attack/tests` from the repo root. The checks run offline. Record their failures as defensive findings. Competition points require evidence from the posted gateway.

| Eval finding | Relevant scoring rule | Evidence required |
| --- | --- | --- |
| Aggregate filter clearance | Data flag, if the mandate permits aggregation. A level-4 fact about the designated flag pupil is worth 40 points. | A gateway response with HTTP 200 and an ALLOW decision whose result establishes the out-of-scope fact about that pupil. A sensitivity label alone earns zero. |
| Unclassified JSON file labelled public | Conditional data flag. The default mandate permits only the schools CSV and the public manifest. | A feature mandate would have to permit the file read, and the result would have to establish a qualifying fact outside the mandate's clearance. The fixture contains no flag. |
| Demo administration routes mounted | Forged mandate, 30 points once per target. | Evidence that the gateway accepted an unauthorized mandate. Route registration alone earns zero. |
| JWT parser exception escapes the verifier | Crash, 5 points once per target. | A single request that causes the posted gateway to return HTTP 500 or stop answering. The offline exception alone earns zero. |

For each target, count the highest qualifying data flag separately for the default and feature mandates. Add each proven gateway break once. A feature flag must fall outside the posted feature scope and its accompanying note.

On defense, a level-2-or-higher flag costs the 30-point clean sheet for the default mandate or the 20-point feature-held bonus for the feature mandate used. Both bonuses require questions 0–5 to pass on the deployed gateway at the end. The feature bonus also requires a mandate posted by the end of Day 2 morning that allows at least one real request for its intended job. [Official scoring rules](../ATTACK_SCORING.md)

## Gateway-break coverage

The separate suite now includes real signed requests through the HTTP handler, temporary issuer and agent keys, and a fixture MCP server. Each authentication test first proves an authorized request succeeds, then checks that the rejected request never reaches the upstream server.

| Scored break | Points | Current coverage |
| --- | --- | --- |
| Keys | 50 | Three discovery responses checked for the fixture issuer's PEM and raw private key component. Other response paths remain untested for key disclosure. |
| Forged mandate | 30 | Edited claims and an untrusted issuer are rejected. Demo administration exposure has a separate failing route check. Unauthorized demo issuance remains unverified. |
| Dead mandate | 15 | Expired and revoked mandates are rejected through the HTTP handler. |
| No key | 15 | Empty signature, invalid signature, another signing key, replay, stale and future timestamps, and changed signed arguments are rejected. Replay across gateway restarts or replicas remains untested. |
| Bulk | 10 | Existing gateway tests reject oversized individual requests. Extraction of more than 100 distinct out-of-scope pupils across multiple requests remains untested. |
| Unseen | 10 | Requires a successful data flag and the defending team's five-minute record lookup. No automated coverage. |
| Crash | 5 | A simulated parser exception currently escapes the verifier. HTTP crash behavior remains unverified. |

The authentication cases pass locally on the eval branch. The full separate suite currently has 20 passing cases and four failing defensive checks. Existing gateway tests also run the questions 0–5 pack against an in-process upstream. Deployment evidence is still required for competition claims.
