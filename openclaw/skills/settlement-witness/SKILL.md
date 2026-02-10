Skill Version: 0.0.4

# SettlementWitness

Deterministic verification gate for agent execution and x402 settlement.

SettlementWitness provides **replay-stable proof-of-delivery receipts** that allow agents, tools, and orchestrators to **safely gate downstream execution** based on whether a claimed outcome actually satisfies predefined conditions.

It does not coordinate, enforce, or hold funds.
It answers one question only:

> “Given this claim and these conditions — does it verify?”


---

## What This Skill Does

SettlementWitness evaluates a claimed result against a deterministic specification and returns a signed verification receipt.

The receipt is:
- Deterministic (same inputs → => same receipt_id + signature)
- Replayable
- Neutral
- Safe to cache, forward, and audit

This allows agent systems to **halt, continue, or settle** based on objective verification rather than trust or heuristics.

---

## Canonical Endpoints

**MCP Adapter (install this):**  
https://defaultverifier.com/mcp

**REST Witness Endpoint:**  
https://defaultverifier.com/settlement-witness

**Public MCP Health:**  
https://defaultverifier.com/mcp-healthz

---

## Tool

### `settlement_witness`

Verifies that an output satisfies a deterministic specification and returns a signed receipt.

**Inputs**
- `task_id` — stable identifier for the task
- `spec` – deterministic conditions expected to be satisfied
- `output` – claimed result to be verified

**Outputs**
- `verdict` — `PASS` or `FAIL`
- `confidence` — numeric confidence score
- `receipt_id` – deterministic receipt identifier
- `signature` – cryptographic proof
- `timestamp` – verification time

---

## Gating Semantics (Important)

This skill is designed to be used as a **verification gate**.

- **PASS** – downstream execution may proceed
- **FAIL** – execution SHOULD halt or roll back

SettlementWitness does not retry, repair, or reinterpret results.
A FAIL is an explicit signal that conditions were **not satisfied**.


---

## Common Use Cases

### x402 Payment Gating
Verify that a task completed correctly **before** releasing or settling payment.

### Post-Task Verification
Confirm that an agent actually produced what it claimed before chaining further actions.

### Proof-of-Delivery Receipts
Generate deterministic receipts that can be replayed, audited, or shared across systems.

### Malicious or Broken Skill Mitigation
Prevent downstream agents from acting on incorrect, partial, or fabricated outputs.

### Agent Orchestration Safety
Use objective verification instead of trust when coordinating multi-agent workflows.

---

## Determinism Guarantee

SettlementWitness is fully deterministic.

Given the same:
- `task_id`
- `spec`
- `output`

It will always return:
- the same `receipt_id`
- the same `signature`
- the same verdict


This makes receipts safe for caching, replay, and dispute resolution.


---

## What This Is Not

- Not a malware scanner
- Not an LLM judge
- Not a coordinator or enforcer
- Not a payment processor

It is neutral verification infrastructure.

---

## Identity vs Delivery Proof

SettlementWitness provides **delivery proof**, not identity.

It complements ERC-8004 and identity systems by answering:
> “Did this outcome satisfy the rules?”

— not:
> “Who is this agent?”


---

## When to Use SettlementWitness

Use this skill when **truth must be established before action**, settlement, or escalation.

If correctness matters, verify first.

---

## Provenance

Operator: Default Settlement Verifier  
Repository: https://github.com/nutstrut/default-settlement-verifier  
Homepage: https://defaultverifier.com  

This skill invokes a public deterministic verification oracle.
It performs no settlement, custody, enforcement, or execution.
