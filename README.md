# Default Settlement Verifier (SettlementWitness)

Verifiable settlement layer for autonomous agents.

Deterministic. Stateless. x402-compatible.

Supports:
attestation → payment → settlement → offline verification

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
    "receipt_id": "sha256:...",
    "sig": "base64url:..."
  },

  "counterparty": "0xABC...",

  "_ext": {
    "agent_id": "0x123:demo"
  }
}

---

## Notes

- receipt_v0_1 is the signed, canonical payload
- counterparty is optional and NOT signed
- Fully backward compatible with SAR v0.1
