# CHANGELOG

## 0.1.1

- Bundled the full current SAR public key registry (`sar-prod-ed25519-01`,
  `sar-prod-ed25519-02`, `sar-prod-ed25519-03`) in `keys/sar-keys.json`
- Added a current kid-03 production-signer fixture
  (`fixtures/sar-v0.1-current-kid03.json`) as an offline test vector
- Extended `scripts/verify_receipt.py --self-test` to cover the kid-03 fixture
- Ensures local verification works for current DefaultVerifier SAR receipts
  (signed by `sar-prod-ed25519-03`) as well as bundled historical fixtures
- Clarified in SECURITY.md that local verification requires the receipt's
  `verifier_kid` to be present in the pinned local registry

## 0.1.0

- Added local-first SAR v0.1 receipt verification via `scripts/verify_receipt.py`
- Added offline verifier requiring no network and no DefaultVerifier availability
- Added signed PASS, FAIL, and INDETERMINATE fixture receipts as test vectors
- Added tampered fixture expected to fail cryptographic verification
- Added bundled public key registry (`keys/sar-keys.json`)
- Added EGRESS.md with explicit offline/optional-network split and domain declaration
- Added SECURITY.md with trust model, non-claims, and key pinning policy
- Added spec/canonicalization.md with SAR v0.1 digest and signature rules
- Rewrote SKILL.md with proper ClawHub frontmatter (`name`, `description`, `version`, `metadata.openclaw`)
- Clarified that network is optional and only used for: remote signed receipt emission, receipt ID resolution, public key refresh, chain/correlation lookup
- Removed positioning language that implied DefaultVerifier executes tasks, approves actions, or controls funds

Earlier versions (0.0.4, 0.0.5) focused on remote DefaultVerifier receipt
issuance via the REST endpoint and MCP adapter. v0.1.0 makes local receipt
verification the default first path; remote issuance remains available but is
explicitly optional.
