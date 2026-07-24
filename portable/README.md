# Portable SAR (six-field) inbound verifier — canonical source

This directory is the **single canonical source** for Default Settlement's
inbound Portable SAR v0.1 verification logic — the six-field, original/
portable signed-core profile also implemented independently by
`xmandate-ai/sar-sdk` and documented at `sarprotocol.org`.

This is deliberately **separate** from, and does not modify, Default
Settlement's existing wallet-bound SAR verification logic
(`_sar_core_without_sig` / `_sar_verify_receipt_v0_1` in `settlement-witness`
and its skill/MCP/CLI mirrors). The two profiles have different signed
cores and different guarantees; see
`reports/strategy/sar-portable-verification-remediation-20260723.md` for
the full design and evidence trail.

## Files

- `portable_sar_verify.py` — canonical Python implementation.
- `portable_sar_verify.js` — canonical browser/Node-compatible JS implementation
  (Web Crypto API only, no bundler required).
- `fixtures/portable-sar-fixtures.json` — synthetic, deterministic conformance
  fixture corpus (throwaway keys, no production data).
- `fixtures/portable-sar-fixture-keys.json` — the fixture corpus's key registry.
- `generate_fixtures.mjs` — regenerates the fixture corpus (non-deterministic
  key generation; regenerating produces a *different* valid corpus, not a
  byte-identical one — the committed fixtures are the pinned, canonical set).
- `test_conformance.py`, `test_conformance.mjs` — cross-language conformance
  tests against the same fixture corpus. Both must pass with identical
  per-fixture outcomes.

## Versioning and consumption

Every consuming surface (settlement-witness, defaultsettle-cli, the
SettlementWitness skill, defaultverifier-mcp, sar-explorer-prod) bundles a
**pinned copy** of the relevant file(s) here, annotated with the exact
commit hash of this repository they were copied from. There is no runtime
import across repositories — each surface's copy is self-contained. When
this canonical source changes, each consumer's pinned copy must be updated
and re-pinned deliberately; silent drift is caught by comparing each
consumer's recorded source hash against this repo's current HEAD (see the
drift-check note in each consumer's bundled file header).

## Design invariants (see full report for rationale and executed evidence)

- Six-field signed core only: `task_id_hash, verdict, confidence,
  reason_code, ts, verifier_kid`.
- `counterparty` and `_ext`, if present, are always reported as unsigned
  metadata — never an attested wallet/counterparty binding.
- Profile candidacy (`receipt_version` + `sig_alg` declared and recognized)
  is necessary but never sufficient by itself — a `key_policy(kid)` must
  additionally authorize that specific key for the portable profile before
  any digest/signature check runs.
- An explicit caller-requested profile can narrow but never override a
  key/profile authorization mismatch.
- No trial-and-error canonicalization — the six-field core is reconstructed
  exactly once; there is no fallback to a different field set.
- Distinct, non-conflated outcomes: malformed envelope, unsupported/
  unrecognized profile, unknown key, profile not authorized, receipt_id
  mismatch, invalid signature.
