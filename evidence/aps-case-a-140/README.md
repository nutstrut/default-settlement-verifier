# APS Case A (ancestor revocation) — independent verification bundle

Public evidence for [Agent-Authority-Conformance/aps-conformance-suite#140](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/issues/140).

Files:

- `verify_case_a.py` — the verifier, exactly as used for the recorded run (see "Source integrity").
- `observed-output.txt` — raw stdout of `verify_case_a.py` against the pinned vector. Nothing hand-written.

## Scope

This is an **independent implementation of the pinned APS Case A vector**.

It is **not** a blinded evaluation.

It is **not**:

- general APS conformance
- OpenShell verification
- middleware verification
- adoption
- a dependency
- production behavior

## Producer pin

| Item | Value |
|---|---|
| Repo | `aeoess/aps-openshell-reference-middleware` |
| Commit | `2508f6a76a0cd86673a51441b9eb79f9197b12e5` |
| Vector | `vector/case-a-neutral-vector.CANDIDATE.json` |
| Vector SHA-256 | `4918125741234d749e4ab23cb6ec98c12f6b86b951147eca984b04a76bb53d31` (4876 bytes) |
| Profile / evaluation instant | `aps:authority-delegation:v1` / `2026-06-01T00:00:00.000Z` |

Fixed-commit URL:
`https://raw.githubusercontent.com/aeoess/aps-openshell-reference-middleware/2508f6a76a0cd86673a51441b9eb79f9197b12e5/vector/case-a-neutral-vector.CANDIDATE.json`

## Spec pin

`draft-pidlisnyi-aps-04` (28 Sep 2026), `https://www.ietf.org/archive/id/draft-pidlisnyi-aps-04.txt`,
720,711 bytes, SHA-256 `6912754a92ae82790568ca2169b9b74ab0a24e6aef485b3f0366eb7d1f2a1eb3`.

Normative sections actually used:

| Section | Used for |
|---|---|
| 3.4 / 3.5 | historical key selection (checked: no key-validity boundary in the vector, so ambiguity paths are not triggered) |
| 4.1 | record shape, closed schema, `delegation_id` and signature construction, key resolution, root acceptance as verifier policy |
| 4.2 | component orders for the seven facets (scope, spend, depth, time, reputation, values, reversibility); profile match |
| 4.3 | phase-major processing; first failing phase and lowest index decide the result; result vocabulary |
| 4.5 | revocation: a revoked delegation invalidates any chain containing it, no descendant record needed |
| 4.6 | issuance-time enforcement (informative) |
| 6 / 6.2 | the four facet profile identifiers; a changed profile is `unsupported` |
| 8.2.1 (L1) | ancestor revocation reaches dependents |
| 13.5 | per-vector pass/fail meaning |

## Implementation boundary

- No producer `verify.mjs`.
- No APS SDK.
- No producer verifier logic (`verify.mjs`, `generate.mjs`, `src/`, `harness/` were not used as logic).
- Generic Python standard library (json, hashlib, re, datetime, copy).
- Python `cryptography` only, for Ed25519.
- Local JCS (RFC 8785) implementation. It is a subset (strings, integers, booleans, null; no floats) sufficient for this vector, not a general RFC 8785 conformance claim.

## Dependencies

- Python 3 with `cryptography` (import: `cryptography.hazmat.primitives.asymmetric.ed25519`, `cryptography.exceptions`).
- **The Python and `cryptography` versions of the original 2026-10-01 run were not recorded.** No version is claimed for it.
- Reproduction for this publication (not the original run) was done on Python 3.10.12 with `cryptography` 50.0.0 (Linux), and produced the same results; `observed-output.txt` is from that run. No minimum version has been tested.

## Command

The script takes the vector path as its only argument (no flags). Exit code 0 means both cases agree with the vector.

```bash
git clone https://github.com/nutstrut/default-settlement-verifier.git
mkdir -p vec
curl -fL -o vec/case-a-neutral-vector.CANDIDATE.json \
  https://raw.githubusercontent.com/aeoess/aps-openshell-reference-middleware/2508f6a76a0cd86673a51441b9eb79f9197b12e5/vector/case-a-neutral-vector.CANDIDATE.json
sha256sum vec/case-a-neutral-vector.CANDIDATE.json   # must be 4918125741234d749e4ab23cb6ec98c12f6b86b951147eca984b04a76bb53d31
python3 -m pip install cryptography
python3 default-settlement-verifier/evidence/aps-case-a-140/verify_case_a.py vec/case-a-neutral-vector.CANDIDATE.json
```

Output is deterministic and should be identical to `observed-output.txt`
(the "resigned" controls use throwaway keys generated per run, but their results do not depend on key values).

## Observed result

| case | observed | vector expectation | agreement |
|---|---|---|---|
| `ancestor-active` | **VALID** (`valid: true`, no failure codes) | same | AGREES |
| `ancestor-revoked` | **INVALID**, `REVOKED`, revocation index **0** | same | AGREES |

In both cases both `delegation_id`s recompute, both Ed25519 signatures verify, root trust, parent link, issuer continuity, child issuance time, all seven attenuation facets and the half-open time windows pass. In the revoked case the child passes every check on its own and the chain fails because member 0 is revoked (§4.5, §8.2.1).
Frozen observed-results hash (printed by the script before `expected` is read): `f5e27d0590f125bde42b5adde10e9fb1dc00ee7123e054602c72032148dc94aa`.

## Negative controls

These are produced by the same script (`negative_controls`, `resigned_controls`). The script prints only the result label and index, not the phase name; the **phase** column below is the phase of `verify_chain` that emits that label (see the phase-major structure in the source and the `failed_phase` field for the two vector cases in `observed-output.txt`).

**All rejection labels below are verifier-local.** draft-04 §4.3 defines no failure-code vocabulary ("a failure reason the verifier reports"). What the draft defines is the phase-major order, the result states (`valid` / `invalid` / `indeterminate` / `unsupported`), and the lowest-index rule. `REVOKED` happens to be the vector's own label, so agreement on it is a naming match, not a spec match.

### Controls on the vector's own records (vector file untouched; mutation applied in memory, not re-signed)

| Mutation / input | Phase | Observed label (verifier-local) |
|---|---|---|
| flip one byte of child signature | signature (3) | `SIGNATURE_INVALID`, idx 1 |
| change child `nonce` | delegation-id (2) | `DELEGATION_ID_MISMATCH`, idx 1 |
| change child `parent_delegation_id` (not re-sealed) | delegation-id (2) | `DELEGATION_ID_MISMATCH`, idx 1 (phase 2 fires before linkage; see re-sealed control below) |
| evaluate at 2026-12-15 (after child `not_after`) | temporal (10) | `NOT_CURRENTLY_VALID`, idx 1 |
| evaluate at 2026-01-15 (before child `not_before`) | temporal (10) | `NOT_CURRENTLY_VALID`, idx 1 |
| evaluate exactly at child `not_after` 2026-12-01T00:00:00.000Z (half-open window) | temporal (10) | `NOT_CURRENTLY_VALID`, idx 1 |
| revoke child only | revocation (11) | `REVOKED`, idx 1 |
| revoke both | revocation (11) | `REVOKED`, idx 0 (lowest index) |
| root issuer not in trust pins | trust (5) | `ROOT_NOT_TRUSTED`, idx 0 |
| parent's key replaced by root's key | signature (3) | `SIGNATURE_INVALID`, idx 1 |

### Phase-isolating controls (re-sealed with locally generated throwaway keys, not the vector's keys)

| Mutation / input | Phase | Observed label (verifier-local) |
|---|---|---|
| unmutated re-sealed chain (baseline) | — | valid |
| `parent_delegation_id` = `sha256:000…0` | linkage (6) | `BROKEN_PARENT_LINK`, idx 1 |
| child issuer ≠ parent subject | continuity (7) | `ISSUER_DISCONTINUITY`, idx 1 |
| child scope widened to `net:*` | attenuation (9) | `ATTENUATION_VIOLATION`, idx 1 |
| child depth not decremented (4) | attenuation (9) | `ATTENUATION_VIOLATION`, idx 1 |
| child cumulative spend 100001 | attenuation (9) | `ATTENUATION_VIOLATION`, idx 1 |
| child reputation ceiling 91 | attenuation (9) | `ATTENUATION_VIOLATION`, idx 1 |
| child reversibility `irreversible` | attenuation (9) | `ATTENUATION_VIOLATION`, idx 1 |
| child `not_after` beyond parent's | attenuation (9) | `ATTENUATION_VIOLATION`, idx 1 |

Bounded: a small set, not a mutation campaign; not every sub-condition inside each facet is separately controlled.

## Blindness disclosure

The implementer had already seen the expected results before coding.
The verifier code does not consume `expected` until after its observed results are frozen (it strips every `expected` member before evaluating, hashes the observed results, and only then reads `expected` for comparison).

Therefore:

- INDEPENDENT IMPLEMENTATION = YES
- BLINDED EVALUATION = NO

## Limitations

1. Revocation state is taken as supplied and treated as established and fresh; the stale/unavailable → `indeterminate` path (§4.3) is not exercised by this vector.
2. Failure-code strings are verifier-local (see above).
3. Key pins have no validity windows and there is no rotation, so §3.4 historical key-selection rules are not exercised.
4. Closed-schema checking (inner facet key sets) is the implementer's reading of §4.1 and §4.2.
5. Spend accounting across a subtree (§4.4) and runtime reputation scoring are outside this vector.
6. Single implementation, single run environment.

## Source integrity

`verify_case_a.py` is byte-for-byte identical (SHA-256 `ebaa2533ca1ef6dc50feb614fca6e9c700bc7ebba71a66bf42138f0d4947fb95`) to the reproducer used for the run, with no path-handling or logic edits. Its header comment and a couple of in-code comments refer to the implementer's own report, which is not part of this bundle; nothing in the script depends on it.

## Claim ceiling

An independently implemented verifier, using the pinned APS draft, pinned test keys, pinned vector and fixed evaluation instant, reached the same per-case authority-chain result as the vector for the two named cases.

Not established:

- general APS conformance
- OpenShell correctness
- middleware correctness
- execution occurrence
- production behavior
- real-world authority
- adoption
- external dependency
