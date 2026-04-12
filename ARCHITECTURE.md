# SAR Protocol — Architecture

Version: v0.2

Note: This implementation follows SAR verification semantics with an extended signed payload when `counterparty` is present.

Status: Live

---

## The System in One Sentence

SAR is a verification layer for autonomous agent execution.

It produces signed, deterministic receipts proving whether an agent action satisfied its specification.

---

## Core Model

Agent action → Verify → Sign → Receipt → Execute

Verification must be:

- Deterministic
- Canonicalized (RFC 8785 JCS)
- Cryptographically signed (Ed25519)
- Independently verifiable
- Portable

---

## Signed Receipt Model

The Ed25519 signature is computed over a canonicalized payload (receipt_v0_1).

### Required fields (always present)

- task_id_hash
- verdict
- confidence
- reason_code
- ts
- verifier_kid

### Optional fields (included when present)

- counterparty

When counterparty is present, it is included in:

- the canonicalized payload
- the SHA256 digest
- the Ed25519 signature
- the receipt_id derivation

Legacy receipts (without counterparty) remain valid.

---

## Receipt ID

receipt_id is derived as:

SHA256(JCS(canonical_signed_payload))

This means:

- identical inputs → identical receipt_id
- receipt_id always matches the signed payload
- receipt_id is independently recomputable

---

## Key Infrastructure

Public keys are available via:

Primary (implementation):
https://defaultverifier.com/.well-known/jwks.json

SAR protocol reference:
https://defaultverifier.com/.well-known/sar-keys.json

Keys are referenced via verifier_kid and support rotation.

---

## Verification Flow

To verify a receipt:

1. Reconstruct the signed payload
2. Canonicalize using RFC 8785 (JCS)
3. Compute SHA256 digest
4. Verify receipt_id matches digest
5. Resolve verifier_kid → public key
6. Verify Ed25519 signature

No server interaction is required after key resolution.

---

## Separation of Concerns

SAR verifies:

- whether an output satisfies a specification

SAR does NOT:

- execute payments
- enforce outcomes
- provide identity
- resolve disputes

Other systems compose on top of SAR receipts.

---

## Final Model

SAR provides a portable, deterministic, cryptographic truth layer for agent execution.

If it matters — verify it.
