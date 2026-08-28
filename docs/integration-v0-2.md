# SettlementWitness SAR v0.2 - Integration Notes

**Status:** Current. Receipts are issued under the `settlement-witness-verified-v0.2`
profile with verdicts `PASS` / `FAIL` / `INDETERMINATE`. The request shape is
`{"checks": [...]}`, not the legacy `{"spec":{"goal":"..."}}` shape.

## Overview

SAR v0.2 introduces wallet binding via the `counterparty` field.

Beginning with verifier key `sar-prod-ed25519-03`, the wallet address is included inside the signed receipt payload.

This allows verifiers to cryptographically prove that a specific wallet participated in the attested settlement.

## Key Properties

- Included inside the signed receipt payload for receipts issued from `sar-prod-ed25519-03` onward
- Included in canonicalization
- Covered by the Ed25519 signature
- Fully backward compatible with earlier receipts

## Purpose

Enables downstream systems to verify and index wallet <-> settlement relationships.

## Signed vs Unsigned

### Signed (deterministic)
- the `settlement-witness-verified-v0.2` receipt payload
- `counterparty` (for receipts issued from `sar-prod-ed25519-03` onward)

### Unsigned (contextual)
- `_ext`

## Compatibility

All earlier receipts remain valid without modification; retired signer keys
remain usable to verify the historical receipts they signed. A receipt's
`verifier_kid` is historical evidence and is never rewritten.

Receipts issued under `sar-prod-ed25519-01` and `sar-prod-ed25519-02` do not include the wallet in signature scope.

Receipts issued from `sar-prod-ed25519-03` onward include `counterparty` inside the signed payload.

Current signer lifecycle (which `kid` is active vs. retired) is published at
`https://defaultverifier.com/.well-known/sar-keys.json`.

## Example

{
  "task_id": "example",
  "verdict": "PASS",
  "reason_code": "CONDITION_SATISFIED",
  "receipt": {
    "profile": "settlement-witness-verified-v0.2",
    "task_id_hash": "sha256:...",
    "verdict": "PASS",
    "reason_code": "CONDITION_SATISFIED",
    "ts": "2026-01-01T00:00:00Z",
    "verifier_kid": "sar-prod-ed25519-03",
    "counterparty": "0xABC...",
    "receipt_id": "sha256:...",
    "sig": "base64url:..."
  }
}