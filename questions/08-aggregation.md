# Question 8: "How many pupils in care does each school have, split by ethnic group?"

**Open question.** No eval cases and no required design.

**The problem.** The answer is only counts, but a count of one in-care pupil of one ethnic group at one school
identifies that child. Whether an answer is safe depends on the result, not on the table it came from. The gateway
only looks at the request.

**Worth working out:**

- Do you check before the call (refuse risky `group_by` combinations), after it (suppress small counts), or both?
- Who sets the smallest count that is safe to release, and where does that setting live?
- Can two answers that are each safe be subtracted to recover a small count?

**What to show:** a counts mandate, a count that is released, a count that is refused or suppressed, and one sentence
on what is still unresolved.

## What we did

Every `aggregate` call, under any mandate, now goes through a small-count check in the gateway
([gateway/lib/disclosure.py](../gateway/lib/disclosure.py)). It runs **both before and after the call**:

- **Before the call**, the gateway refuses a request whose shape is a way to single someone out:
  - more than 2 `group_by` columns;
  - an identifying column (`Psuedo ID`, `DisplayName`, `DeprivationScore`, or anything named like an ID, name, date
    of birth, postcode, address, email or phone number) in `group_by`, `measure` or `where`;
  - a `where` that is anything other than absent or exactly one census snapshot (`AcademicYear` + `CensusTerm`).
    Subgroups are asked for with `group_by`, so they pass through the checks below. A `where` would just be a free
    way to subtract.
  - Wrongly typed `group_by`, `where`, `measure` or `table`, or any extra argument, is a 403 `AGGREGATE_MALFORMED`
    and is never forwarded. It is not a 500.
- **After the call**, it checks the answer itself:
  - **Counted in distinct pupils, not rows.** The MCP `aggregate` counts census rows, and one child has up to 11.
    Ashfield's 15 in-care rows are 3 children, so a row threshold would have released them. The gateway quietly
    asks upstream for `group_by + ["Psuedo ID"]`, so it can see how many different pupils stand behind every
    number, then adds the result back up to the groups that were asked for. Pupil IDs never leave the gateway.
  - **Primary suppression:** a group with fewer than *k* pupils is left out of the answer entirely. A count is
    shown only if at least *k* pupils have the measure **and** at least *k* do not. That second rule covers both
    "total minus count" and the zero next to a small number.
  - **Secondary suppression:** within each row and each column of the answer (each slice along one `group_by`
    column), either nothing is hidden or at least two cells are, so the margin can't give one back. Totals are done
    first and depend only on totals, so two different measures can't be played against each other. Ties are broken
    by column name, not by request order, so `["URN","Ethnicity"]` and `["Ethnicity","URN"]` hide the same cells.
  - **Rounding:** every released total and count is rounded to the nearest 5.
  - Hidden numbers come back as `"suppressed"`. The response carries a `disclosure` note, the decision detail says
    how many numbers were suppressed, and so does the hash-chained audit entry.
  - An upstream result in the wrong shape gives 403 `AGGREGATE_UNCHECKABLE`. Nothing goes out unchecked.

**Who sets k.** The gateway has a floor: **10 pupils, rounding to 5**, applied to every aggregate call whether the
mandate mentions it or not. A mandate may carry `disclosure: {"min_count": N, "round_to": M}` to be **stricter**.
A value below the floor is raised to the floor, so an issuer can't hand an agent a looser policy than the
gateway's. A malformed claim denies every call with `DISCLOSURE_INVALID`, the same way a malformed `budget` does.
The floor lives in the gateway because the gateway's operator answers for releases. The claim lives in the mandate
because some purposes (a published report, say) call for a higher threshold.

**Gateway-wide, and the eval still passes.** The only eval case that reaches `aggregate` is the question 2 counts
mandate's FSM-by-school query. It gives `200 ALLOW` as before, now with rounded and suppressed numbers, and the eval
only checks status and decision. The in-care measure case is still refused by the scope (`CONSTRAINT_VIOLATED`)
before this check runs. The Day 2 default mandate has no `aggregate`. A question 11 budgeted mandate is still
refused `BUDGET_QUERY` before any of this runs.

### Decisions and alternatives we rejected

| Rejected | Why |
| --- | --- |
| Threshold on the row counts `aggregate` returns | Rows aren't children. 15 rows at Ashfield are 3 children in care |
| Suppress small groups but still list them | With `group_by: ["URN", "InCareAtCurrentSchool"]`, the bare existence of a `(SCH07, "1")` row says Greystone has a child in care. Small groups are left out, so a missing group says nothing |
| Pre-check only: a list of forbidden `group_by` combinations | Whether an answer is safe depends on the data. School × ethnicity is fine for FSM and not for care |
| Post-check only | It can't tell a filter on one pupil's ID from a legitimate snapshot. Refusing before the call also never touches the data |
| A free `where` | `where URN=SCH07` next to `group_by URN` is two routes to the same cell, and two answers that can be subtracted. Only the snapshot is allowed, because there is no other way to ask for "this term" |
| Random noise (differential privacy) | Asking the same thing twice and averaging defeats noise unless it is cached per query, which is state across replicas. Fixed rounding gives the same answer every time, and that is what UK official statistics practice does: suppress small cells, round to 5 |
| A cross-call query ledger to catch differencing | It needs shared state across gateway replicas, and question 11's budget already refuses `aggregate` for any mandate that wants call-level limits. We rely on the narrow `where`, consistent suppression and rounding instead (see below) |
| Letting a mandate lower k | One leaked counts mandate with `min_count: 1` would undo the whole thing |

### Red team

[gateway/tests/test_aggregation.py](../gateway/tests/test_aggregation.py) has one test or more for each attack, run
against the real synthetic data through the real MCP tool. Each one is checked against the truth computed straight
from the CSV.

| Attack | Result |
| --- | --- |
| `group_by` URN + Ethnicity + InCare, and look for 1s | 403 `AGGREGATE_DISCLOSIVE` (3 columns), never forwarded. With 2 columns (URN + InCare) no `"1"` group is listed |
| Total minus count | A count is hidden unless ≥ k pupils lack the measure too. Every FSM=1 group of `["URN","FSMeligible"]` has its count hidden |
| Rows vs pupils | Ashfield in-care: 15 rows, 3 children: hidden |
| Greystone's one child in care (the Day 2 flag) | Hidden in every grouping and snapshot we tried |
| Differencing with a `where` filter (`URN`, `Gender`, half a snapshot, snapshot + URN) | 403 `AGGREGATE_DISCLOSIVE` |
| Differencing without a filter: all censuses minus the other 10 snapshots | 13 cases leave exactly one snapshot cell unknown. Because of rounding, the estimate was wrong every time we checked (e.g. 0 against a true 6, 15 against 5, 50 against 36). This blurs the attack but doesn't prove it impossible. The test pins Ironbridge FSM summer 2021/22 |
| Differencing two `group_by` sets (`URN` vs `URN`+`Ethnicity`) | Each row and column of the finer table hides 0 or ≥ 2 cells, checked over 7 groupings × 2 measures × 3 filters |
| `measure` on an identifying column (`Psuedo ID`, `DisplayName`, `DeprivationScore`, `date_of_birth`, `Postcode`, `pupil_id`) | 403 `AGGREGATE_DISCLOSIVE` |
| `where` pinning one pupil (`{"Psuedo ID": "P0586"}`) | 403 `AGGREGATE_DISCLOSIVE` |
| `group_by` as a string, ints, nested lists, a dict, `None` or duplicates; `where` as a string, a list, non-string values or `{"$ne": ...}`; an extra argument | 403 `AGGREGATE_MALFORMED`, not a 500 |
| An upstream answer without pupil IDs, or a negative total | 403 `AGGREGATE_UNCHECKABLE` |
| Every pair of census columns, all censuses, in-care | No listed group has < 10 pupils, and no released count has < 10 on either side |

## The mandate

A counts-only mandate for the officer's question. The scope keeps it to the census and the two measures. The
`disclosure` claim is optional: without it you get the gateway floor anyway.

```bash
uv run python -m gateway.cli issue --agent-key gateway/state/agent.pem -o counts.jwt \
  --scope '[{"server":"pupil-data","tools":["aggregate"],"constraints":{"table":["personal_data_school_census"],"measure":["InCareAtCurrentSchool","FSMeligible"]}}]' \
  --claims '{"disclosure":{"min_count":10,"round_to":5}}' \
  --purpose "In-care counts by school and ethnic group" --org la:hackathon
uv run python -m gateway.cli decode counts.jwt
```

The main claims:

```json
{
  "delegator": {"principal": "officer:jsmith", "org": "la:hackathon", "authority": "hackathon"},
  "purpose": "In-care counts by school and ethnic group",
  "scope": [
    {"server": "pupil-data", "tools": ["aggregate"],
     "constraints": {"table": ["personal_data_school_census"],
                     "measure": ["InCareAtCurrentSchool", "FSMeligible"]}}
  ],
  "deny": ["*.write", "pii.*"],
  "disclosure": {"min_count": 10, "round_to": 5}
}
```

## The question, answered (suppressed)

```bash
uv run python -m gateway.cli call --mandate counts.jwt --agent-key gateway/state/agent.pem --tool aggregate \
  --args '{"table":"personal_data_school_census","group_by":["URN","Ethnicity"],"measure":"InCareAtCurrentSchool","where":{"AcademicYear":"2023/24","CensusTerm":"SPR"}}'
```

Real output (run in process against the synthetic data):

```text
200 ALLOW IN_SCOPE 'min 10 pupils, rounded to 5, 13 numbers suppressed'
   {"URN": "SCH01", "Ethnicity": "WHIT", "total": 35, "count": "suppressed"}
   {"URN": "SCH02", "Ethnicity": "WHIT", "total": 30, "count": "suppressed"}
   {"URN": "SCH03", "Ethnicity": "WHIT", "total": 25, "count": "suppressed"}
   {"URN": "SCH04", "Ethnicity": "WHIT", "total": 35, "count": "suppressed"}
   {"URN": "SCH05", "Ethnicity": "WHIT", "total": 25, "count": "suppressed"}
   {"URN": "SCH06", "Ethnicity": "ASIA", "total": 10, "count": "suppressed"}
   {"URN": "SCH06", "Ethnicity": "WHIT", "total": 35, "count": "suppressed"}
   {"URN": "SCH07", "Ethnicity": "WHIT", "total": 25, "count": "suppressed"}
   ... SCH08 to SCH12 WHIT, totals 30 to 35, every count suppressed
   disclosure: {"min_count": 10, "round_to": 5, "suppressed": 13}
```

This is the honest answer. In spring 2023/24 there are **7 children in care across all 12 schools** (3 at
Ashfield, all White; 1 Mixed and 1 Black at SCH04; 1 at SCH10; 1 at SCH11). No school × ethnic group cell, and no
school, has 10, so every count is hidden. Groups under 10 pupils are left out entirely (that is why only one
non-White group appears). Asked over the whole borough by ethnic group, across all censuses, one number survives:
`{"Ethnicity": "WHIT", "total": 5440, "count": 55}`. Over all censuses these are census records, not children
(see "Still unresolved").

The audit entry:

```text
agent key 30qvUz… called pupil-data.aggregate and was sent 13 rows with no pupil IDs in it, 13 numbers suppressed as too small to release: allowed
```

## A count that is released

The same mandate, free school meals by school in the same snapshot (rounded to 5; within one snapshot one row is
one pupil):

```text
200 ALLOW IN_SCOPE 'min 10 pupils, rounded to 5, 7 numbers suppressed'
   {"URN": "SCH01", "total": 45, "count": "suppressed"}
   {"URN": "SCH02", "total": 40, "count": "suppressed"}
   {"URN": "SCH03", "total": 35, "count": 15}
   {"URN": "SCH04", "total": 40, "count": 15}
   {"URN": "SCH05", "total": 40, "count": 10}
   {"URN": "SCH06", "total": 45, "count": 10}
   {"URN": "SCH07", "total": 35, "count": "suppressed"}
   ... SCH09 40/10, SCH08 SCH10 SCH11 SCH12 suppressed
```

The same request under `"disclosure": {"min_count": 15}` releases only SCH03 (11 numbers suppressed). Under
`{"min_count": 3}` the answer is exactly the k = 10 one (`min 10 pupils`): the claim can't go below the floor.
`{"min_count": 0}` is `403 DISCLOSURE_INVALID`.

## Requests it refuses

```text
>> group_by ["URN","Ethnicity","InCareAtCurrentSchool"]
403 DENY AGGREGATE_DISCLOSIVE 'at most 2 group_by columns, got 3'
>> where {"Psuedo ID": "P0586"}
403 DENY AGGREGATE_DISCLOSIVE "identifying column(s) ['Psuedo ID'] cannot be grouped, counted or filtered on"
>> where {"AcademicYear": "2023/24", "CensusTerm": "SPR", "URN": "SCH07"}
403 DENY AGGREGATE_DISCLOSIVE "where may only pick one census snapshot (['AcademicYear', 'CensusTerm']), got ['AcademicYear', 'CensusTerm', 'URN']; ask for subgroups with group_by"
>> where "AcademicYear=2023/24"
403 DENY AGGREGATE_MALFORMED 'where must be an object of column name to string value'
>> any aggregate under a question 11 budgeted mandate
403 DENY BUDGET_QUERY 'aggregate is not available to a budgeted mandate (its cost cannot be counted in pupils)'
```

## Still unresolved

- **Differencing over time is blurred, not prevented.** "All censuses" minus the 10 other snapshots leaves one
  hidden snapshot cell as a difference of rounded numbers. Each one can be up to 2 off, so 11 of them can be off by
  more than the whole hidden range (0 to 9). Our scan never recovered a true value, but that is evidence, not a
  proof. A per-mandate query ledger, or refusing the all-censuses view, would close it.
- **Secondary suppression covers one answer and its margins.** Two different tables that share cells, for example
  school × ethnicity and school × gender, are only protected by rounding.
- **All-censuses numbers count census records, not children.** We kept the tool's meaning so the eval and other
  teams' tools see the same numbers, but "5440" next to "55" is easy to misread as children. The thresholds always
  use distinct children.
- **The identifying column list is a list.** A new quasi-identifier column with an innocent name would get only
  the k-threshold protection.
- **Suppression only matters for a counts-only mandate.** A mandate that also allows `roster` or `search` already
  gives the rows, and `:8080` gives everything to anyone who skips the gateway.
