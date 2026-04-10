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

## Signed payload structure

Current SAR receipts include a canonical payload called `receipt_v0_1`.

Fields inside this structure are covered by the Ed25519 signature and
can be independently verified using the verifier public key.

Typical signed fields include:

- `task_id_hash`
- `verdict`
- `confidence`
- `reason_code`
- `ts`
- `verifier_kid`
- `counterparty` (present for receipts issued under `sar-prod-ed25519-03` and later)

The `counterparty` field binds the wallet address to the receipt inside
the signature scope.

---

## Deterministic signing note

Signatures are produced over the canonicalized `receipt_v0_1` payload.

Signature generation follows this process:

1. Build the deterministic receipt core fields
2. Canonicalize the payload using RFC 8785 JSON Canonicalization Scheme (JCS)
3. Compute a SHA256 digest of the canonical payload
4. Sign the digest using the verifier Ed25519 private key

This ensures receipts are deterministic, replay-stable, and independently verifiable using the public keys published at:

https://defaultverifier.com/.well-known/jwks.json

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
