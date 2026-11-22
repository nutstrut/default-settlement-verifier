# Changelog

## 0.1.0 — initial public candidate

First version of the DefaultVerifier Skill.

- Offline verification of `0.2-candidate` Default Settlement receipts.
- Bundled, pinned trust snapshot (fetched 2026-11-17, preserved byte-for-byte); no network access, no credentials.
- Claim-boundary reporting: receipt validity, issuer verdict and signed properties
  (established / contradicted / not established) reported separately.
- v0.1 receipts are reported as `NOT_A_V02_RECEIPT` and routed to the `settlement-witness` Skill.
- One example receipt (`examples/receipt-indeterminate.json`).
