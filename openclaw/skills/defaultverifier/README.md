# DefaultVerifier

Verifies an **existing** Default Settlement receipt on your own machine and tells you
exactly what it does and does not establish. Homepage: https://defaultverifier.com

## What it does

- Checks that a `0.2-candidate` receipt is **cryptographically valid**: structure, issuer key,
  `receipt_id` and Ed25519 signature, against a trust snapshot bundled with the Skill.
- Reports the issuer's verdict (**PASS / FAIL / INDETERMINATE**) as signed.
- Maps each signed property to **established** (signed `pass`), **contradicted** (signed `fail`)
  or **not established** (signed `unknown`), and names any unsigned fields without treating them as evidence.

## What it does not do

- It does not issue, create or demo receipts. Issuance belongs to the `settlement-witness` Skill / SettlementWitness.
- It does not use the network, credentials, payments or hosted endpoints, and never fetches keys.
- It does not certify agents or endorse them, and it does not guarantee settlement.
- A receipt is evidence of what an issuer signed. It does not by itself prove that execution happened,
  that payment was final, or that anything is true in the outside world, unless the signed property says so.

## Requirements

`python3` and the `cryptography` package. No network access is needed or used.

## Usage

```bash
python3 scripts/verify_receipt_v02.py RECEIPT.json --question "What does this receipt prove?"
```

Add `--json` for machine-readable output. Exit code 0 = receipt valid (any verdict), 1 = invalid or
untrusted, 2 = unreadable, non-regular, oversized (over 2 MiB) or unparseable.

### First run

```bash
python3 scripts/verify_receipt_v02.py examples/receipt-indeterminate.json
```

`examples/receipt-indeterminate.json` is a real receipt, signed by the production issuer on 2026-09-08
for a request with `request_id: profile-check`. Expect: **valid receipt, verdict INDETERMINATE**. Only
`evidence_digest_binding` is established; the declared condition, runtime execution, payment finality and
legal finality are *not established*; the unsigned `payment` field is listed but is not evidence. It shows
that a valid receipt can still establish very little.

## Validity, verdict and properties are different things

| Question | Answer comes from |
|---|---|
| Is the receipt authentic and intact? | receipt validity (`receipt_valid`) |
| What did the issuer conclude? | verdict: PASS, FAIL or INDETERMINATE |
| What exactly is signed? | five properties: established / contradicted / not established |

A valid FAIL or INDETERMINATE receipt is still a valid receipt. An invalid receipt has no verdict and is
not a FAIL. "Not established" is not the same as false. See `references/claim-boundary.md`.

## Trust snapshot

- The issuer key registry is **bundled** at `trust/sar-keys-v02-snapshot.json`
  (fetched **2026-11-17** from https://defaultverifier.com/.well-known/sar-keys.json; sha256 is in
  `trust/sar-keys-v02-snapshot.provenance.json`).
- There is no silent or automatic refresh and the Skill never touches the network.
- If a receipt names a key the snapshot does not contain, the result is "could not establish trust with the
  currently bundled registry". That can simply mean the snapshot predates the receipt. It does **not** mean
  the receipt is forged.
- Updating trust material requires a new release of this Skill.

## Legacy v0.1 receipts

This verifier supports `0.2-candidate` receipts. A v0.1 receipt (or any other format) is reported as
`NOT_A_V02_RECEIPT`. For legacy SAR v0.1 receipts, use the `settlement-witness` Skill. DefaultVerifier
handles current v0.2-candidate receipt verification.

## Provenance

The verification core `scripts/verify_v02.py` is a byte copy of the `defaultsettle-cli` verifier at commit
`5d5f4f4549443de36ce94672ef4a269d33c226d0` (sha256 `f86663a9c3159b3ef9b343ffc07e5952f2ab7f0533bddf529a78b0c3ec6bfbec`).
`scripts/verify_receipt_v02.py` only reads the file and renders the report.

Version: Skill 0.1.0 (see `CHANGELOG.md`); it is independent of the receipt version it supports.
