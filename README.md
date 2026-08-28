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
  "receipt": {
    "profile": "settlement-witness-verified-v0.2",
    "task_id_hash": "sha256:...",
    "verdict": "PASS",
    "reason_code": "CONDITION_SATISFIED",
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

- the receipt payload is issued under the `settlement-witness-verified-v0.2` profile; verdicts are `PASS`, `FAIL`, or `INDETERMINATE`
- when `counterparty` is present, it is included in signature scope and in `receipt_id` derivation
- retired signer keys remain valid for verifying receipts they historically signed; `verifier_kid` in a receipt is historical evidence and is never rewritten
- current signer lifecycle (which `kid` is active vs. retired) is published at `https://defaultverifier.com/.well-known/sar-keys.json` — treat that endpoint, not this README, as the source of truth for which key is currently active
- this behavior is implemented and publicly verifiable via the live receipt and key endpoints

---


**SAR Compatibility:** This implementation follows SAR verification semantics, with an extended signed payload when `counterparty` is present.




## Demo

Run a full end-to-end verification in ~2 minutes:
DEMO.md


## Quick Start

### 1. Create a receipt

curl -X POST https://defaultverifier.com/settlement-witness \
  -H 'content-type: application/json' \
  -d '{
    "task_id":"quickstart-001",
    "spec":{"checks":[{"kind":"field_equals","inputs":{"output_path":"$.result"},"expected":"hello"}]},
    "output":{"result":"hello"},
    "counterparty":"0x1234567890abcdef1234567890abcdef12345678"
  }'

### 2. Fetch the receipt

curl https://defaultverifier.com/settlement-witness/receipt/<receipt_id>

Note: use the `receipt_id` from the returned receipt

### 3. Verify locally (Node)

cd examples/node-verify
node verify.js receipt.json jwks.json

## Examples

Node.js verification example:
examples/node-verify/

Python verification example:
examples/verify_receipt_python.py

Usage:
python3 examples/verify_receipt_python.py <receipt_id>

## API Endpoints

### Create Receipt

POST /settlement-witness

Submits a task verification request and returns a signed SAR receipt.

---

### Retrieve Receipt

GET /settlement-witness/receipt/{receipt_id}

Note: Use the `receipt_id` from the returned receipt (sha256:...) for retrieval.


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