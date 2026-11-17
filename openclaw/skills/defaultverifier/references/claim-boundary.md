# Claim boundary reference

Doctrine: APPROVAL != ADMISSION != EXECUTION != EFFECT. Receipt validity != external
event truth. Historical validity != current admissibility. Reference != attestation.
Signing != epistemic upgrade.

## Output fields (from `--json`)

| Field | Meaning |
|---|---|
| `receipt_valid` | Structure, trusted key, receipt_id and Ed25519 signature all passed. Not the verdict. |
| `issuer_verdict` | `{verdict, reason_code}` as signed. Null when invalid. |
| `signed_properties` | Five properties, each pass / fail / unknown. |
| `boundary` | established / contradicted / not_established / not_implied lists. |
| `unsigned_fields_present` | Field names outside the signature. Never evidence. |
| `issuer` | kid, key_status, key_currency (current / historical / unstated), trust_snapshot (fetched_on, sha256). |
| `rejection` | Stable code and detail when invalid. |

## Question -> property

| Question about | Read | If `unknown` |
|---|---|---|
| execution / "did it happen" | `runtime_execution_established` | Not established. Do not infer from PASS. |
| payment finality | `payment_finality_established` | Not established. |
| legal finality | `legal_finality_established` | Not established. |
| declared condition met | `declared_condition_satisfied` / verdict | INDETERMINATE = not established. |
| agent safety / endorsement | none | Never implied. |
| identity ownership | none (counterparty is a binding, not ownership proof) | Never implied. |
| still admissible now | none | Never implied. |

## Rejections

Trust class (`UNKNOWN_KEY`, `KEY_NOT_ACTIVE`, `KEY_USE_NOT_AUTHORIZED`,
`PROFILE_NOT_AUTHORIZED`): "could not establish trust with the currently bundled registry".
The snapshot is pinned (see `trust/*.provenance.json`) and refreshed only by an explicit,
reviewed act, never by this Skill.
Integrity class (`RECEIPT_ID_MISMATCH`, `SIGNATURE_INVALID`): altered or not signed by the claimed key.
Scope class (`NOT_A_V02_RECEIPT`, `UNSUPPORTED_*`): not a v0.2-candidate receipt.
Everything else: malformed input.
None of these is an issuer FAIL verdict.
