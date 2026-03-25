> WARNING: This document describes SAR v0.1.
>
> For current production usage, including the optional top-level `counterparty` field,
> see `docs/integration-v0-2.md`.

# SettlementWitness SAR v0.1 - Integration Guide

**Status:** Frozen  
**Canonical Version:** v0.1  
**Verification Model:** Offline, registry-rooted, deterministic  

---

## 1. Overview

SettlementWitness emits cryptographically signed delivery receipts ("SAR v0.1").

Each receipt is:

- Deterministic (RFC 8785 canonicalization)
- SHA256 content-addressed
- Ed25519 signed
- Public-key registry verifiable
- Fully offline verifiable

No network call to SettlementWitness is required to verify a receipt.

---

## 2. Trust Root

Public key registry:

`https://defaultverifier.com/.well-known/sar-keys.json`

Each receipt includes:

`"verifier_kid": "<key id>"`

The `verifier_kid` MUST resolve to a public key in the registry.

Verification MUST use only keys from this registry.

---

## 3. Canonical Signed Core

The Ed25519 signature covers the SHA256 digest of the RFC 8785 (JCS) canonicalized core:

```json
{
  "task_id_hash": "string",
  "verdict": "PASS | FAIL | INDETERMINATE",
  "confidence": 0.0-1.0,
  "reason_code": "string",
  "ts": "ISO8601 UTC",
  "verifier_kid": "string"
}
