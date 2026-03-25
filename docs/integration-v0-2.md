# SettlementWitness SAR v0.2 — Integration Notes

## Overview

SAR v0.2 introduces an optional top-level field:

"counterparty": "0x..."

## Key Properties

- Top-level field
- NOT part of `receipt_v0_1`
- NOT included in canonicalization
- NOT signed
- Fully backward compatible

## Purpose

Enables downstream systems to index agent ↔ counterparty relationships.

## Signed vs Unsigned

### Signed (deterministic)
- `receipt_v0_1`

### Unsigned (contextual)
- `counterparty`
- `_ext`

## Compatibility

All SAR v0.1 clients remain valid without modification.

## Example

{
  "receipt_v0_1": {...},
  "counterparty": "0xABC..."
}
