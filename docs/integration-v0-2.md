# SettlementWitness SAR v0.2 - Integration Notes

## Overview

SAR v0.2 introduces wallet binding via the `counterparty` field.

Beginning with verifier key `sar-prod-ed25519-03`, the wallet address is included inside the signed receipt payload.

This allows verifiers to cryptographically prove that a specific wallet participated in the attested settlement.

## Key Properties

- Included inside `receipt_v0_1` for receipts issued under `sar-prod-ed25519-03`
- Included in canonicalization
- Covered by the Ed25519 signature
- Fully backward compatible with earlier receipts

## Purpose

Enables downstream systems to verify and index wallet <-> settlement relationships.

## Signed vs Unsigned

### Signed (deterministic)
- `receipt_v0_1`
- `counterparty` (for `sar-prod-ed25519-03` and later)

### Unsigned (contextual)
- `_ext`

## Compatibility

All SAR v0.1 and earlier receipts remain valid without modification.

Receipts issued under `sar-prod-ed25519-01` and `sar-prod-ed25519-02` do not include the wallet in signature scope.

Receipts issued under `sar-prod-ed25519-03` and later include `counterparty` inside the signed payload.

## Example

{
  "receipt_v0_1": {
    "task_id_hash": "sha256:...",
    "verdict": "PASS",
    "confidence": 1.0,
    "reason_code": "SPEC_MATCH",
    "ts": "2026-01-01T00:00:00Z",
    "verifier_kid": "sar-prod-ed25519-03",
    "counterparty": "0xABC...",
    "receipt_id": "sha256:...",
    "sig": "base64url:..."
  }
}