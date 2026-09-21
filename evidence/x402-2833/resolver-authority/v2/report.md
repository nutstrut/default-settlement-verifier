# x402 #2833 — Resolver-authority conformance vector V2

Local fixture, deterministic verifier, and readiness report only. No production
or scanner code, graph/state entry, canonical governance, public thread,
comment, issue, PR, commit, or push was modified.

## Hydration and traceability

- Starting CWD: `C:\Users\green\.codex\worktrees\8f6b\morpheus`
- Worktree/branch: new local worktree, detached `HEAD`
- Starting `HEAD`: `a7cd4d189c3863d1491df9cc8785f493b190fdb0`
- Starting `origin/main`: `a7cd4d189c3863d1491df9cc8785f493b190fdb0`
- Ahead/behind: `0 / 0`
- Starting working tree: clean
- Fresh fetch: `git fetch origin main`
- V1 traceability commit: `aeec88d92085f6ac36f0c10dc18e8640214232e2`

V1 remains unchanged at its original three-case fixture and verifier. V2 is
versioned separately rather than silently overwriting V1.

## V2 schema and evaluator changes

The fixture preserves separate `evidence_valid`, `lifecycle_bound`,
`resolution_valid`, `resolver_authorized`, `authority_prior`,
`transition_allowed`, `classification`, and `reason` dimensions. Exact
authority remains the tuple `(resolver_id, check_set_id,
permitted_successor_state)`; no independent allow-list intersection is used.

True null authority is represented literally as `"authority_commitment": null`.
The evaluator returns `NO_PRECOMMITTED_AUTHORITY` before computing a commitment
digest, sequence ordering, tuple membership, or conflict rule. The separate
`case-empty-authority-set` retains a prior authority object whose
`authorized_resolutions` is empty and returns `NO_AUTHORIZED_RESOLUTIONS`.

The authority commitment now contains `commitment_sequence`. Evidence contains
`observed_sequence`. Prior authority is mechanically true only when:

`authority.commitment_sequence < evidence.observed_sequence`

Equal and later positions are rejected as `AUTHORITY_NOT_PRIOR`. This fixture
demonstrates ordering given supplied ordering inputs; it does not authenticate
those inputs, prove historical timing, or prove anti-backdating in production.

The commitment digest remains SHA-256 over sorted-key compact JSON of the full
authority configuration, including policy version, exact tuples, sequence, and
conflict rule. The digest commits bytes only; it does not prove authority
validity, trusted time, historical existence, or operator standing.

Conflict selection is a generic precommitted object:

```json
{"type":"priority_order","order":["resolution-C","resolution-A","resolution-B"]}
```

The evaluator resolves any N authorized candidates by resolution identity. It
does not hardcode resolver names or choose after observing evidence. A missing,
invalid, or non-unique rule produces no transition and
`BLOCKED_INDETERMINATE`.

## Explicit named behavior matrix

| Named behavior | Independent assertion | Expected result |
|---|---|---|
| `NULL_AUTHORITY_BLOCKED` | `test_NULL_AUTHORITY_BLOCKED` | Literal `authority_commitment: null`, valid evidence/resolution, blocked with `NO_PRECOMMITTED_AUTHORITY` |
| `EMPTY_AUTHORITY_SET_BLOCKED` | `test_EMPTY_AUTHORITY_SET_BLOCKED` | Prior authority object with empty set, blocked with `NO_AUTHORIZED_RESOLUTIONS` |
| `AUTHORIZED_A_ALLOWED` | `test_AUTHORIZED_A_ALLOWED` | Exact prior A tuple transitions |
| `UNAUTHORIZED_B_BLOCKED` | `test_UNAUTHORIZED_B_BLOCKED` | Valid B without committed tuple is blocked with `RESOLVER_NOT_PREAUTHORIZED` |
| `LATE_AUTHORITY_BLOCKED` | `test_LATE_AUTHORITY_BLOCKED` | Sequence 11 after observed 10 is blocked with `AUTHORITY_NOT_PRIOR` |
| `MULTIPLE_AUTHORIZED_PRIORITY_RESOLVES` | `test_MULTIPLE_AUTHORIZED_PRIORITY_RESOLVES` | Precommitted B>A selects B deterministically |
| `MULTIPLE_AUTHORIZED_NO_RULE_BLOCKED_INDETERMINATE` | `test_MULTIPLE_AUTHORIZED_NO_RULE_BLOCKED_INDETERMINATE` | Conflicting A/B stop with `BLOCKED_INDETERMINATE` / `CONFLICT_RULE_MISSING` |
| `RESOLVER_SUBSTITUTION_BLOCKED` | `test_RESOLVER_SUBSTITUTION_BLOCKED` | Resolver identity substitution loses exact-tuple authority |
| `CHECK_SET_SUBSTITUTION_BLOCKED` | `test_CHECK_SET_SUBSTITUTION_BLOCKED` | Check-set substitution loses exact-tuple authority |
| `SUCCESSOR_SUBSTITUTION_BLOCKED` | `test_SUCCESSOR_SUBSTITUTION_BLOCKED` | Successor substitution loses exact-tuple authority |
| `THREE_CANDIDATE_PRIORITY_ORDER_RESOLVES` | `test_THREE_CANDIDATE_PRIORITY_ORDER_RESOLVES` | C>A>B selects C; A/B are non-selected |
| `EQUAL_SEQUENCE_AUTHORITY_NOT_PRIOR` | `test_EQUAL_SEQUENCE_AUTHORITY_NOT_PRIOR` | Equal position is not prior and is blocked |

## Reason-code model

The verifier exercises these distinct outcomes:

- `NO_PRECOMMITTED_AUTHORITY` — authority set is empty; empty is not unconstrained.
- `NO_AUTHORIZED_RESOLUTIONS` — authority commitment exists but authorizes no resolutions.
- `AUTHORITY_NOT_PRIOR` — supplied commitment sequence is equal to or later than evidence.
- `RESOLVER_NOT_PREAUTHORIZED` — exact resolver/check-set/successor tuple is absent.
- `CONFLICT_RULE_MISSING` — multiple prior-authorized conflicting candidates have no rule.
- `PRECOMMITTED_CONFLICT_RULE` — the committed priority rule selected the winner.
- `PRECOMMITTED_CONFLICT_RULE_NON_SELECTED` — authorized candidate was not selected.

`BLOCKED_INDETERMINATE` is used as a classification for unresolved conflicts,
not as a replacement for all blocked reasons.

## Charter-fit check

| Proposed clause | Classification | Narrow basis |
|---|---|---|
| Evidence capture grants no decision authority. | `SUPPORTED_BY_VECTOR` | Valid evidence and valid resolutions remain unable to transition without exact prior authority. |
| Authority not committed prior to evaluation is not authority. | `SUPPORTED_BY_VECTOR` | Sequence comparison rejects equal/later commitment positions. |
| Where multiple committed resolutions conflict and no precommitted conflict rule selects among them, the transition does not occur. | `SUPPORTED_BY_VECTOR` | A/B conflict without a rule is `BLOCKED_INDETERMINATE` with no operative state. |

This is a fixture-level result only and is not normative adoption or charter
acceptance.

## Validation

Commands run:

```text
python reports/fixtures/x402-2833-resolver-authority-verify-20260919.py
python reports/fixtures/x402-2833-resolver-authority-verify-v2-20260921.py
python -c "import json; json.load(open('reports/fixtures/x402-2833-resolver-authority-vector-v2-20260921.json'))"
git diff --check
```

Expected/observed validation summary:

- V1: unchanged verifier passes, 4 tests.
- V2: 12 named behavior tests pass.
- Named behavior count: 12.
- Blocked reasons exercised: `NO_PRECOMMITTED_AUTHORITY`,
  `AUTHORITY_NOT_PRIOR`, `RESOLVER_NOT_PREAUTHORIZED`,
  `CONFLICT_RULE_MISSING`, plus `PRECOMMITTED_CONFLICT_RULE_NON_SELECTED`.
- 3-candidate case: covered and passes.
- True null authority and empty authority set are distinct cases and reason codes.

## Strongest safe claim

THIS VECTOR DEMONSTRATES THAT VALID EVIDENCE AND VALID RESOLUTIONS DO NOT
CREATE DECISION AUTHORITY.

A TRANSITION MAY PROCEED ONLY WHEN AN EXACT RESOLVER/CHECK-SET/SUCCESSOR
RELATIONSHIP IS COVERED BY AUTHORITY THAT PRECEDES THE EVIDENCE-EVALUATION
POINT UNDER THE SUPPLIED ORDERING MODEL.

WHERE MULTIPLE PRIOR-AUTHORIZED RESOLUTIONS CONFLICT, ONLY A PRECOMMITTED
DETERMINISTIC CONFLICT RULE MAY SELECT THE OPERATIVE RESULT.

WITHOUT PRIOR AUTHORITY OR WITHOUT A RULE THAT RESOLVES THE CONFLICT, THE
TRANSITION STOPS.

The ordering limitation is explicit: the vector enforces relative ordering over
supplied trusted ordering inputs. It does not prove authenticity of real-world
timestamps, heights, or sequences, historical timing, anti-backdating, x402
adoption, or charter acceptance.

## NSPG13 four-hardening result

1. Null authority: covered, including literal missing authority commitment.
2. Priority/timing: covered mechanically, including equal and late cases.
3. Generalized conflict selection: covered with generic priority order and three candidates.
4. Distinct blocked outcome codes: covered without collapsing blocked reasons.

Every advertised behavior is independently named and mapped to an assertion,
including distinct true-null and empty-set authority cases.
The V2 result is `READY_TO_RETURN_TO_NSPG13` as a local review artifact only.

Files changed:

- `reports/fixtures/x402-2833-resolver-authority-vector-v2-20260921.json`
- `reports/fixtures/x402-2833-resolver-authority-verify-v2-20260921.py`
- `reports/readiness/x402-2833-resolver-authority-conformance-vector-v2-20260921.md`

External actions: NONE
Public actions: NONE
Commits: NONE
Pushes: NONE

X402 #2833 RESOLVER-AUTHORITY VECTOR V2 COMPLETE —
READY_TO_RETURN_TO_NSPG13
