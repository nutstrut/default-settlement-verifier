# SAR Protocol — Architecture

**Version:** v0.2  
**Status:** Live  
**Last updated:** March 2026

---

## The System in One Sentence

SAR is a verification layer for autonomous agent execution.

It produces signed, deterministic receipts that determine whether an agent action is allowed to execute.

**No receipt = no execution.**

---

## Why This Exists

Agents are no longer just generating outputs — they are executing actions, making decisions, and moving money.

Execution without verification is uncontrolled.

SAR exists to ensure every action can be verified before it is allowed to matter.

---

## System Stack

The system is a stack, not a collection of tools.

- **APPLICATION LAYER**  
  Skills · Integrations · Workflow Wrappers

- **HOSTED SERVICE**  
  SettlementWitness

- **REFERENCE IMPLEMENTATION**  
  Default Verifier

- **PROTOCOL**  
  SAR (Settlement Attestation Receipt)

---

## Layer Definitions

### SAR — The Protocol

SAR defines the canonical model for deterministic, signed verification receipts.

It specifies:

- The verification model (`spec → output → deterministic comparison`)
- The canonical payload structure
- The receipt format and field requirements
- The signature requirements (`Ed25519` over JCS-canonicalized payload)
- The key registry model (`kid`-indexed, rotation-safe)

SAR is the source of truth. All implementations must conform to it.

**Spec:** https://defaultverifier.com/spec/sar-v0.1  
**Current version:** SAR v0.2

---

### Default Verifier — The Reference Implementation

Default Verifier is the reference implementation of the SAR protocol.

It implements:

- JCS canonicalization (RFC 8785)
- Deterministic spec/output comparison
- Ed25519 signature generation and validation
- Receipt derivation (SHA256 of canonical signed core)
- Public key registry integration

Any system claiming SAR compatibility should validate against Default Verifier behavior.

**Endpoint:** https://defaultverifier.com/verify  
**Key registry:** https://defaultverifier.com/.well-known/sar-keys.json  
**GitHub:** https://github.com/nutstrut/default-settlement-verifier

---

### SettlementWitness — The Hosted Service

SettlementWitness is the default hosted deployment of the Default Verifier.

It provides:

- Remote verification endpoint
- Signed SAR receipt generation
- TrustScore integration (reputation per `agent_id`)
- x402-native payment endpoints (Base + Solana)
- MCP server for agent-native workflows

SettlementWitness is the recommended integration point for most use cases.

**Endpoint:** https://defaultverifier.com/settlement-witness  
**MCP:** https://defaultverifier.com/mcp

---

### Application Layer — Skills and Integrations

Skills and integrations are workflow-specific applications of the SAR protocol.

They are adoption surfaces — **not the system itself**.

Current applications:

- **Verified Task** — Universal execution gating for agent workflows
- **Self Improving Agent v2** — Verification-gated agent evolution
- **Verified Humanizer** — SAR-attested content transformation
- **Skill Vetter v2** — SAR-verified skill safety analysis
- **Refer** — Verified referral engine
- **SettlementWitness Skill** — Direct SAR integration

---

## The Core Primitive

All layers reduce to one operation:

`Agent action → Verify → Sign → Receipt → Execute`

Verification must be:

- **Deterministic** — identical inputs always produce identical outputs
- **Canonicalized** — JCS (RFC 8785) before signing
- **Cryptographically signed** — Ed25519
- **Independently verifiable** — no callbacks required
- **Portable** — valid forever, anywhere

**The receipt is not just proof — it is the gating mechanism for execution.**  
**The receipt is the product.**

---

## Canonical Signed Core

The Ed25519 signature covers exactly these fields:

- `task_id_hash`
- `verdict`
- `confidence`
- `reason_code`
- `timestamp`
- `verifier_kid`

Fields outside this core are metadata and are **not** part of receipt verification.

---

## Key Infrastructure

### Public Key Registry

https://defaultverifier.com/.well-known/sar-keys.json

All signing keys are published here and referenced via `verifier_kid`.

Key rotation is additive. No receipt is ever invalidated.

---

### Offline Verification

Receipts can be verified without calling SettlementWitness:

1. Fetch key registry
2. Match `verifier_kid`
3. Reconstruct signed core
4. Verify signature

Receipts remain valid forever.

---

## Agent Identity

**Format:** `wallet_address:agent_name`

- Prevents collisions
- Supports multiple agents per operator
- Enables per-agent reputation

---

## Multi-Envelope Model

SAR supports multiple domain-specific uses:

- Settlement verification
- Capability attestation
- Pre-transaction validation
- Reputation systems

All share deterministic verification and signed receipts.

---

## Ecosystem Stack

- **Pre-transaction condition-based access** (Insumer)
- **x402** (payment)
- **SettlementWitness** (verification)
- **TrustScore** (reputation)
- **MoltBridge** (trust graph)
- **ERC-8004** (portable registry)

SAR receipts are the evidence layer for all downstream systems.

---

## TrustScore

TrustScore is the off-chain reputation system based on receipt history per `agent_id`.

Tiers:

- **Building Trust** — starting tier
- **Bronze** — initial verification history
- **Silver** — consistent verified performance
- **Gold** — high reliability

TrustScore evolves based on verified outcomes — not claims.

---

## What SAR Is Not

- Not a payment processor
- Not a fund custodian
- Not an enforcement layer
- Not a dispute resolver
- Not a subjective quality judge

SAR verifies that output matches spec, deterministically.

It does not decide what should happen — it enables other systems to act on verified truth.

---

## Integration Points

- **API:** https://defaultverifier.com/settlement-witness
- **SDK:** https://www.npmjs.com/package/sar-sdk
- **MCP:** https://defaultverifier.com/mcp
- **Spec:** https://defaultverifier.com/spec/sar-v0.1

---

## Current Ecosystem

- **InsumerAPI** — pre-transaction condition-based access
- **xMandate / sar-sdk** — SDK
- **Pylon** — reputation scoring
- **MoltBridge** — trust graph
- **x402** — payment rail

---

## Final Model

SAR verifies what autonomous systems do, learn, and decide — before it matters.

---

## Resources

- https://defaultverifier.com
- https://sarprotocol.org
- https://github.com/nutstrut/default-settlement-verifier

---

## Final Note

**SAR is infrastructure. Build on it.**
