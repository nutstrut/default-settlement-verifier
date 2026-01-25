Default Settlement Verifier


Deterministic, neutral verification for agent-to-agent and programmatic settlements.



The Default Settlement Verifier is a stateless verification service that evaluates whether a claimed settlement outcome satisfies predefined conditions and returns a signed, deterministic verdict (PASS or FAIL).



It is designed to act as a trust-minimized verification primitive in automated payment, escrow, and agent-based workflows (e.g. x402-style flows), without custody, mediation, or subjective judgment.

What It Does


The verifier accepts a structured verification request describing a settlement claim and evaluates it against deterministic rules.



It returns:

A binary verdict (PASS / FAIL)

A confidence score

A cryptographic signature

Optional fee metadata (fee-aware, currently zero-enforced)



The verifier:

Does not hold funds

Does not initiate payments

Does not maintain session state

Does not rely on identity, reputation, or trust assumptions



It simply answers one question:



“Given this claim and these conditions, does it verify?”
Core Properties
Deterministic

Identical inputs always produce identical outputs.

Stateless

No memory of prior requests; every call is independent.

Neutral

No buyer/seller bias, no incentives, no governance layer.

Composable

Designed to plug into agent frameworks, payment rails, and settlement protocols.

Auditable

Signed responses allow downstream verification and logging.

Intended Use Cases
Agent-to-agent payments requiring post-condition verification

x402-style pay-after-execution flows

Automated escrow or conditional release systems

Buyer protection primitives without custody

Programmatic settlement validation in AI workflows

Canonical Verification Endpoint


POST

https://defaultverifier.com/verify

Content-Type

application/json

Example Request
{
"task_id": "example-001",
"claim": {
"type": "delivery_verification",
"parameters": {
"expected_output": "hash_or_descriptor",
"observed_output": "hash_or_descriptor"
}
}
}

Example Response
{
"verdict": "PASS",
"confidence": 1.0,
"signature": "0xabc123...",
"fee_due": "0.001",
"fee_enforced": false
}

Note:

The verifier is fee-aware but currently operates with zero enforcement. Fee fields are returned for forward compatibility.

Status
✅ Live

✅ 24/7 available

✅ Production infrastructure

⚠️ API surface intentionally minimal (v1)



There is no separate “test” or “sandbox” environment.

The live endpoint is the canonical interface.

Non-Goals


The Default Settlement Verifier explicitly does not attempt to:

Act as an oracle of subjective truth

Resolve disputes

Store or escrow funds

Enforce payment

Provide reputation or identity services



Those layers belong upstream or downstream.

Roadmap (Non-Commitment)
Expanded claim schemas

Optional replay-safe receipts

Public verification key endpoint

Optional metrics endpoint



No timelines are guaranteed.

License


MIT License

Contact


Project discussions and updates are shared via:

Twitter: @defaultsettle