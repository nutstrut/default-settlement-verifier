# Signature verification (SettlementWitness)

This document describes the receipt format and the intended verification model for SettlementWitness outputs.

SettlementWitness provides attestations only. It does not execute payments, hold custody, enforce settlements, or trigger on-chain actions.

---

## Receipt model

A SettlementWitness receipt contains (at minimum):

- `task_id`
- `verdict` (`PASS` / `FAIL`)
- `confidence`
- `signature` (verifier signature over a deterministic payload)
- `receipt_id` (stable identifier derived from the same payload)

Some deployments may include additional metadata such as timestamps or fee-related fields.

---

## Deterministic signing note

Signatures are produced over a deterministic, canonicalized payload derived from:

- `task_id`
- `spec`
- `output`

Non-deterministic fields (for example, timestamps) are excluded from the signed payload.

---

## Replay stability guarantee

Identical inputs MUST yield identical outputs:

- same `verdict`
- same `receipt_id`
- same `signature`

This makes receipts safe to cache, forward, and audit.

---

## Verification tooling roadmap

Public key verification tooling will be published.

Current receipts are cryptographically stable attestations intended for downstream logging, gating, and audit trails.

---

## Support & Provenance

SettlementWitness is operated as part of the Default Settlement Verifier infrastructure.

If this documentation or verification infrastructure is useful, you can support ongoing work via GitHub Sponsors:  
https://github.com/sponsors/nutstrut

The verifier remains neutral, deterministic, and free to use.
