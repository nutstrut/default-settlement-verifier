# SAR Protocol — Architecture

**Version:** v0.2  
**Status:** Live  

**Note:** This implementation follows SAR verification semantics with an extended signed payload when `counterparty` is present.

---

## The System in One Sentence

SAR is a verification layer for autonomous agent execution.

It produces signed, deterministic receipts proving whether an agent action satisfied its specification.

---

## Core Model

Agent action → Verify → Sign → Receipt → Execute

Verification must be:

- Deterministic  
- Canonicalized (RFC 8785 — JCS)  
- Cryptographically signed (Ed25519)  
- Independently verifiable  
- Portable  

---

## Signed Receipt Model

The Ed25519 signature is computed over a canonicalized payload called `receipt_v0_1`.

---

## Signed Scope (Critical)

The signed payload is exactly the `receipt_v0_1` object.

All fields inside `receipt_v0_1` are included in:

- Canonicalization (JCS)  
- SHA256 hashing  
- Signature verification  
- `receipt_id` derivation  

Fields outside `receipt_v0_1` are not part of the signed scope and do not affect receipt validity.

---

## Canonical Signed Payload (`receipt_v0_1`)

All field-level mappings in this implementation refer to paths under `receipt_v0_1`.

Example:

```json
{
  "task_id_hash": "sha256:...",
  "verdict": "PASS",
  "confidence": 1.0,
  "reason_code": "SPEC_MATCH",
  "ts": "2026-04-15T17:21:16.517881Z",
  "verifier_kid": "sar-prod-ed25519-03",
  "counterparty": "0x123..."
}
```

---

## Field Paths

The following fields exist at:

- `receipt_v0_1.task_id_hash`  
- `receipt_v0_1.verdict`  
- `receipt_v0_1.confidence`  
- `receipt_v0_1.reason_code`  
- `receipt_v0_1.ts`  
- `receipt_v0_1.verifier_kid`  
- `receipt_v0_1.counterparty` (optional)  

---

## Required Fields (Always Present)

- `receipt_v0_1.task_id_hash`  
- `receipt_v0_1.verdict`  
- `receipt_v0_1.confidence`  
- `receipt_v0_1.reason_code`  
- `receipt_v0_1.ts`  
- `receipt_v0_1.verifier_kid`  

---

## Optional Fields

- `receipt_v0_1.counterparty`  

---

## Counterparty Behavior

When `counterparty` is present, it is included in:

- The canonicalized payload  
- The SHA256 digest  
- The Ed25519 signature  
- The `receipt_id` derivation  

Legacy receipts (without `counterparty`) remain valid.

---

## Protocol Distinction

This behavior differs from earlier SAR protocol drafts (e.g. sarprotocol.org), where:

- `counterparty` existed outside the signed core  
- It did not affect `receipt_id` derivation  

This implementation reflects the **SettlementWitness / DefaultVerifier model**.

---

## Receipt ID

`receipt_id` is derived as:

```
SHA256(JCS(receipt_v0_1))
```

This means:

- Identical payload → identical `receipt_id`  
- `receipt_id` always matches the signed payload  
- `receipt_id` is independently recomputable  

---

## Key Infrastructure

Public keys are available via:

- https://defaultverifier.com/.well-known/jwks.json  
- https://defaultverifier.com/.well-known/sar-keys.json  

Keys are referenced via:

- `receipt_v0_1.verifier_kid`  

---

## Verification Flow

To verify a receipt:

1. Extract `receipt_v0_1`  
2. Canonicalize using RFC 8785 (JCS)  
3. Compute SHA256 digest  
4. Confirm digest matches receipt_v0_1.receipt_id  
5. Resolve `verifier_kid` to a public key  
6. Verify Ed25519 signature  

No server interaction is required after key resolution.

---

## Separation of Concerns

SAR verifies:

- Whether an output satisfies a specification  

SAR does NOT:

- Execute payments  
- Enforce outcomes  
- Provide identity  
- Resolve disputes  

---

## Final Model

SAR provides a portable, deterministic, cryptographic truth layer for agent execution.

**If it matters — verify it.**
