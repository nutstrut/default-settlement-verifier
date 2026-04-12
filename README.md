# DefaultVerifier — SAR Verification Infrastructure

SAR (Settlement Attestation Receipt) is a verification protocol that produces cryptographically signed receipts proving whether an AI agent completed a task according to its specification.

DefaultVerifier is a live SAR verifier implementation with a public receipt registry, metrics API, and explorer.

**If it matters—Verify it.**

## Architecture

Understand the SAR stack and verification model:

👉 [SAR Architecture](./ARCHITECTURE.md)

---

## Example Response

{
  "witness": "SettlementWitness",
  "witness_version": "v0",
  "task_id": "example",
  "verifier_endpoint": "https://defaultverifier.com/verify",
  "witness_timestamp": "2026-01-01T00:00:00Z",
  "receipt_id": "...",
  "receipt_v0_1": {
    "task_id_hash": "sha256:...",
    "verdict": "PASS",
    "confidence": 1.0,
    "reason_code": "SPEC_MATCH",
    "ts": "...",
    "verifier_kid": "...",
    "counterparty": "0xABC...",
    "receipt_id": "sha256:...",
    "sig": "base64url:..."
  },

  "_ext": {
    "agent_id": "0x123:demo"
  }
}

---

## Notes

- `receipt_v0_1` is the signed canonical receipt payload used by this implementation
- when `counterparty` is present, it is included in signature scope and in `receipt_id` derivation
- legacy receipts (`sar-prod-ed25519-01` and `sar-prod-ed25519-02`) remain valid and do not include `counterparty` in signature scope
- this behavior is implemented and publicly verifiable via the live receipt and key endpoints

---


**SAR Compatibility:** This implementation follows SAR verification semantics, with an extended signed payload when `counterparty` is present.


## Examples

Node.js verification example:
examples/node-verify/


## API Endpoints

### Create Receipt

POST /settlement-witness

Submits a task verification request and returns a signed SAR receipt.

---

### Retrieve Receipt

GET /settlement-witness/receipt/{receipt_id}

Note: Use the `receipt_id` inside `receipt_v0_1` (sha256:...) for retrieval.


Returns a previously issued receipt.

---

### Wallet Receipt Explorer

GET /settlement-witness/receipts?wallet={address}

Returns recent receipts associated with a wallet address.

The public explorer is available at:

https://defaultverifier.com/explorer

This interface allows browsing recent receipts and wallet-indexed delivery history.

---

### Public Verification Keys

https://defaultverifier.com/.well-known/jwks.json

Alternative (SAR protocol reference):
https://defaultverifier.com/.well-known/sar-keys.json


Used to verify Ed25519 signatures for receipts.

---

### Key Registry

https://defaultverifier.com/.well-known/sar-keys.json

Registry of verifier public keys referenced by `verifier_kid`.