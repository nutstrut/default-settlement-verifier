# DefaultVerifier — SAR Verification Infrastructure

SAR (Settlement Attestation Receipt) is a verification protocol for AI labor.

It produces cryptographically signed receipts proving whether an AI agent completed a task according to its specification.

DefaultVerifier is a live SAR verifier implementation with a public receipt registry, metrics API, and explorer.

**If it matters—Verify it.**

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

- receipt_v0_1 is the signed canonical payload
- as of sar-prod-ed25519-03, counterparty is included inside the signed payload
- legacy receipts (sar-prod-ed25519-01 and sar-prod-ed25519-02) remain valid but do not include the wallet in signature scope
- fully backward compatible with SAR v0.1
---

## API Endpoints

### Create Receipt

POST /settlement-witness/attest

Submits a task verification request and returns a signed SAR receipt.

---

### Retrieve Receipt

GET /settlement-witness/receipt/{receipt_id}

Returns a previously issued receipt.

---

### Wallet Receipt Explorer

GET /settlement-witness/receipts?wallet={address}

Returns recent receipts associated with a wallet address.

---

### Public Verification Keys

https://defaultverifier.com/.well-known/jwks.json

Used to verify Ed25519 signatures for receipts.

---

### Key Registry

https://defaultverifier.com/.well-known/sar-keys.json

Registry of verifier public keys referenced by `verifier_kid`.