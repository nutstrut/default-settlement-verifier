---
name: settlement-witness
description: >-
  Verify signed SAR v0.1 settlement receipts locally with Ed25519 and RFC 8785
  canonicalization. Use when you need to confirm a receipt is cryptographically
  valid before trusting a task-complete claim, chaining to another agent output,
  using a receipt as evidence, or acting on a settlement-adjacent claim.
  Optionally request DefaultVerifier-signed receipts for remote issuance.
version: 0.1.0
homepage: https://defaultverifier.com
metadata:
  openclaw:
    emoji: "🧾"
    requires:
      bins:
        - python3
    install:
      - kind: uv
        package: jcs
      - kind: uv
        package: cryptography
---

> **New in 0.1.0:** local-first verification. Receipt cryptography is verified
> entirely on your machine — no network required. Network is optional and only
> used when you explicitly request remote receipt issuance or resolution.

# SettlementWitness

Verify SAR v0.1 settlement receipts locally. Optionally request
DefaultVerifier-signed receipts.

## When to use

- Before trusting a task-complete claim from another agent
- Before chaining downstream actions to an agent output
- Before using a receipt as evidence
- Before acting on a settlement- or payment-adjacent claim
- When you prefer a local, offline verifier

## First run (offline, no network needed)

Run the self-test against all bundled fixtures:

```bash
python3 scripts/verify_receipt.py --self-test
```

Expected output: `self_test_passed: true` with all four fixtures `[OK]`.

## Verify a single receipt

```bash
python3 scripts/verify_receipt.py fixtures/sar-v0.1-pass.json
```

Returns JSON:

```json
{
  "valid": true,
  "receipt_id": "sha256:...",
  "kid": "sar-prod-ed25519-01",
  "verdict": "PASS",
  "errors": []
}
```

## Tamper test (should fail)

```bash
python3 scripts/verify_receipt.py fixtures/tampered-receipt.json
```

Returns `valid: false` with errors listing the digest mismatch and signature
failure. This proves the verifier actually rejects tampered receipts.

## How to interpret results

| Field | Meaning |
|---|---|
| `valid: true` | Receipt digest and Ed25519 signature both verified |
| `valid: false` | Receipt failed cryptographic verification |
| `verdict: PASS` | The signed outcome claims the spec was met |
| `verdict: FAIL` | The signed outcome claims the spec was not met |
| `verdict: INDETERMINATE` | The issuer signed an honest uncertainty state |
| `errors: [...]` | What specifically failed |

`PASS`, `FAIL`, and `INDETERMINATE` are all valid signed outcomes when
`valid: true` — they represent what the issuer attested, not post-hoc
interpretation.

## What works offline vs what uses the network

**Fully offline (no network):**
- Parsing a SAR v0.1 receipt JSON
- Recomputing the canonical digest from signed core fields
- Verifying `receipt_id` matches the digest
- Verifying the Ed25519 signature against the bundled public key registry
- All four bundled fixture checks (`--self-test`)

**Optional network (only when you explicitly ask):**
- Requesting a new DefaultVerifier-signed receipt — signing keys stay
  server-side by design, so issuance requires the remote service
- Resolving a receipt ID
- Refreshing the public key registry
- Chain or correlation lookups

If DefaultVerifier is offline, local verification of existing receipts still
works. The service being unavailable does not invalidate receipts you already
have.

## Optional remote receipt issuance

To request a signed receipt from DefaultVerifier (requires network):

```bash
curl -sS https://defaultverifier.com/settlement-witness \
  -H "Content-Type: application/json" \
  -d '{"task_id":"your-task-id","spec":{"expected":"value"},"output":{"expected":"value"}}'
```

The REST endpoint returns a signed SAR v0.1 receipt. You can then verify it
locally with `scripts/verify_receipt.py`.

Public key registry: https://defaultverifier.com/.well-known/sar-keys.json  
Receipt explorer: https://defaultverifier.com/verified

## Safety boundaries

DefaultVerifier issues signed evidence about whether a receipt is
cryptographically valid. It does not:

- Execute user tasks
- Approve or reject actions
- Release, hold, or custody funds
- Prove legal settlement finality
- Prove payment finality
- Control downstream agent behavior

Acting on a verified receipt is the responsibility of the system or agent
that reads it.

## Environment

Override the public key registry path if needed:

```bash
SAR_KEYS_REGISTRY_PATH=/path/to/keys.json python3 scripts/verify_receipt.py receipt.json
```

## Provenance

Operator: Default Settlement Verifier  
Repository: https://github.com/nutstrut/default-settlement-verifier  
Homepage: https://defaultverifier.com
