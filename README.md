# Default Settlement Verifier

Deterministic, neutral verification for agent-to-agent and programmatic settlements.

Landing page: https://defaultverifier.com

---

## Overview

The Default Settlement Verifier is a stateless verification service that evaluates whether a claimed settlement outcome satisfies predefined conditions under deterministic rules.

It answers one question only:

> “Given this claim and these conditions, does it verify?”

It produces **signed, replayable truth**, not coordination, custody, or enforcement.

---

## What It Does

The verifier accepts a structured verification request describing a settlement claim and evaluates it against deterministic rules. It returns:

- A binary verdict (`PASS` / `FAIL`)
- A confidence score
- A cryptographic signature
- Optional fee metadata (fee-aware; currently not enforced)

The verifier:

- Does **not** hold funds
- Does **not** initiate payments
- Does **not** maintain session state
- Does **not** rely on identity, reputation, or trust assumptions

---

## Core Properties

- **Deterministic** — Identical inputs always produce identical signed results
- **Stateless** — Every call is independent
- **Neutral** — No buyer/seller bias, no incentives, no governance layer
- **Composable** — Plugs into agent frameworks, payment rails, and settlement protocols
- **Auditable** — Signed responses allow downstream verification and logging

---

## Intended Use Cases

- Agent-to-agent payments requiring post-condition verification
- x402-style pay-after-execution flows
- Automated escrow or conditional release systems
- Buyer protection primitives without custody
- Programmatic settlement validation in AI workflows

---

## Canonical Verification Endpoint (POST)

POST https://defaultverifier.com/verify

**Important:**  
This endpoint accepts POST requests only.  
Browsers will show “Cannot GET /verify”. This is expected behavior.

Example request:

    {
      "task_id": "example-001",
      "spec": { "expected_output": "hash_or_descriptor" },
      "output": { "expected_output": "hash_or_descriptor" }
    }

---

## SettlementWitness (v0)

SettlementWitness is a thin, stateless wrapper that calls the Default Settlement Verifier and returns a replay-stable receipt for agent workflows.

It adds:
- no state
- no judgment
- no retries
- no facilitation logic

### Canonical Endpoints

- POST https://defaultverifier.com/settlement-witness
- GET  https://defaultverifier.com/manifest

Notes:
- POST `/settlement-witness` is POST-only.
- GET `/settlement-witness` returns 405 by design.

---

### Example (PASS)

    curl -s -X POST https://defaultverifier.com/settlement-witness \
      -H "Content-Type: application/json" \
      -d '{
        "task_id": "example-002",
        "spec": { "expected": "foo" },
        "output": { "expected": "foo" }
      }'

Minimal response shape (trimmed):

    {
      "witness": "SettlementWitness",
      "witness_version": "v0",
      "task_id": "example-002",
      "verifier_response": {
        "verdict": "PASS",
        "reason_code": "MATCH",
        "signature": "..."
      },
      "witness_timestamp": "...",
      "receipt_id": "..."
    }

---

## MCP (Canonical)

SettlementWitness is available via MCP for agent-native workflows.

- **MCP Server:** https://defaultverifier.com/mcp
- **Health:** https://defaultverifier.com/mcp-healthz
- **Tool:** `settlement_witness`
- **Arguments (required):**
  - `task_id` (string)
  - `spec` (object)
  - `output` (object)
- **Returns:** receipt JSON (verbatim)

**Determinism guarantee:**
Identical inputs produce the same `receipt_id` and verifier signature.
Timestamps may differ.

---

## Security & Settlement Gating

Default Settlement Verifier can serve as a lightweight mitigation layer in autonomous workflows:

- **Proof-of-Delivery** — Deterministic PASS/FAIL verdicts verify outputs match task specifications before settlement.
- **Settlement Gating** — Payments or downstream actions can be conditioned on verifiable completion.
- **Dispute Reduction** — Signed receipts provide replayable evidence for post-task settlement decisions.

The verifier does not enforce outcomes or custody funds; it produces neutral, signed verification receipts.

---

## Determinism & Signatures (Replay Stability)

- `timestamp` and `witness_timestamp` may change on each call (observability).
- For identical inputs (`task_id`, `spec`, `output`), the verifier signature is stable.
- `receipt_id` is derived from the verifier signature and is stable for identical inputs.

---

## Endpoint Behavior (Expected)

- POST `/verify` → works (GET not supported)
- POST `/settlement-witness` → works (GET returns 405)
- GET `/manifest` → works

---

## OpenClaw Compatibility

SettlementWitness is compatible with OpenClaw via a drop-in skill definition included in this repository:

    openclaw/skills/settlement-witness/SKILL.md

The skill calls the public HTTPS endpoint:

POST https://defaultverifier.com/settlement-witness

No local services are required.

## Agent Wrappers & Skills

SettlementWitness is a stateless witness wrapper that issues replay-stable
verification receipts for post-task settlement workflows.

It is compatible with:
- Heurist Mesh (submission pending)
- MCP invocation patterns
- OpenClaw skills (drop-in wrapper included)

---

## Deployment Notes (Factual)

- Verifier and SettlementWitness are served via HTTPS behind NGINX on `defaultverifier.com`
- SettlementWitness runs persistently and is proxied via NGINX (no raw port exposure)
- Cloudflare cache bypass is enabled for API routes (`/verify`, `/settlement-witness`, `/manifest`)

---

## Non-Goals

The Default Settlement Verifier explicitly does **not**:

- Act as an oracle of subjective truth
- Resolve disputes
- Store or escrow funds
- Enforce payment
- Provide reputation or identity services

Those layers belong upstream or downstream.

---

## Roadmap (Non-Commitment)

- Expanded claim schemas
- Optional replay-safe receipts
- Public verification key endpoint
- Optional metrics endpoint

No timelines are guaranteed.

---

## License

MIT License

---

## Contact

Project discussions and updates:

https://x.com/defaultsettle

---

## Operator & Provenance

SettlementWitness is operated as part of the Default Settlement Verifier infrastructure.

Operator: Default Settlement Verifier  
Repository: https://github.com/nutstrut/default-settlement-verifier  
Homepage: https://defaultverifier.com  

SettlementWitness is a stateless deterministic attestation service.
It does not hold funds, execute payments, enforce settlements, or trigger on-chain actions.

Receipt verification: see `docs/signature-verification.md` (added in this repo).

---

## Support

If Default Settlement Verifier or SettlementWitness saved you time, reduced risk, or helped you ship faster, you can support ongoing infrastructure work.

Support via GitHub Sponsors:  
https://github.com/sponsors/nutstrut

Infrastructure is operated independently and remains free to use.
