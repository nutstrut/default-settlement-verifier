# SAR primitive interoperability vectors (self-contained capsule)

> **Claim ceiling: `PRIMITIVE_COMPATIBILITY_ONLY`.**
> This corpus tests shared cryptographic/canonicalization primitives only.
> It does **not** establish: AIR↔SAR composition, semantic equivalence, native cross-format
> verification, interchangeable formats, AIR adoption, SAR adoption of AIR, deployment or
> production interoperability, or dependency.

SAR-side input for a shared primitive harness (RFC 8785 canonicalization, SHA-256, Ed25519 over
explicit preimages, negative mutations). Runs offline from this directory alone. No AIR code, no AIR
adapter, no AIR runtime dependency; no SAR core, `receipt_id`, verifier, runtime or spec change.

**Derived artifact.** This capsule is re-pinned from a private canonical source
(`nutstrut/morpheus@7374947a08510a7857d3ba5fd8c1b9387f3ed44d`). It is not byte-identical to it as a
whole; see [PROVENANCE.md](PROVENANCE.md). The public commit containing this directory is the pin to cite.

## Run

```bash
cd evidence/sar-primitive-vectors-20261006
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt            # exact pins: jcs 0.2.1, cryptography 50.0.0, rfc8785 0.1.4, pytest 9.1.0
python3 run_vectors.py                     # corpus
python3 -m pytest tests -q                 # negative controls + 2^53 checks (21 tests)
sha256sum -c SHA256SUMS                    # integrity
```

Expected: `cases_run=27 failures=0 overall=ALL_DECLARED_EXPECTATIONS_MATCHED`, exit 0.
That string means only that every declared expectation matched; there is no aggregate
"primitives compatible" verdict. Add `--out FILE` to write the per-case result JSON
(retained copy: `results/primitive_results.json`).

## Files

| File | Purpose |
|---|---|
| `vectors.json` | 27 cases with pinned expectations |
| `run_vectors.py` | Offline runner; nonzero exit on any mismatch, unknown key, or case-count drift |
| `sar_crypto_common.py`, `sar_portable_reader.py` | SAR-side stack under test (capsule-local copies) |
| `fixtures/` | xMandate SAR v0.1 fixture (byte-identical to source) |
| `tests/test_vectors.py` | Nine corruption controls (each must exit nonzero) and direct ±2^53 checks |
| `results/primitive_results.json` | Retained per-case/per-primitive output |
| `requirements.txt`, `SHA256SUMS`, `PROVENANCE.md` | Pins, integrity, provenance |

## Result model

Each case reports parse, canonicalization (status + exact bytes), SHA-256, signature, and mutation
outcomes separately. SAR's stack (`json.loads` → `jcs` 0.2.1 → SHA-256 → `cryptography` Ed25519) and the
independent `rfc8785` 0.1.4 implementation are executed and recorded **separately**; their
disagreement is an observation, never folded into one failure. SAR v0.1 signs the **32-byte SHA-256
digest** of the JCS-canonical six-field core, not the raw canonical bytes (`ED-2-MUT-CONVENTION`).

## Edge-case findings (recorded, not endorsed)

- **±2^53 family (NUM-1…5):**
  - `jcs` 0.2.1 emits +2^53 and −2^53 exactly; +(2^53+1) and −(2^53+1) are canonicalized to the ±2^53 bytes (silently lossy).
  - `rfc8785` 0.1.4 accepts 2^53−1 and raises `IntegerDomainError` for ±2^53 and ±(2^53+1).
- **Duplicate keys (DUP-1):** `{"a":1,"a":2}` is accepted by the SAR Python parse path; last value wins → `{"a":2}`. Not endorsed.
- **Lone surrogates (SURR-1/2):** parser accepts; canonicalization rejects at UTF-8 encoding (`UnicodeEncodeError`) in SAR's stack; `rfc8785` also rejects (error class recorded per case). SURR-3 is a valid-pair control.
- **UTF-16 key ordering (UTF16-1):** `a` < U+1F600 < U+E000.

## Known profile difference

SAR v0.1 `confidence` is numeric. AIR's profile is expected to reject non-integer JSON numbers.
**AIR EXPECTED REJECT is a PROFILE DIFFERENCE, NOT a primitive failure.** The runner records SAR
primitive behavior (`canonicalization`) and AIR profile admissibility (`air_profile_admissibility`,
a declared expectation only, never evaluated here) as separate fields. INT-2 is integer-only for
illustration and is not a conformant SAR v0.1 artifact.

## Test keys

**TEST KEYS ONLY.** Seeds are `SHA-256(label)` (labels in `vectors.json`) or the fixture's deterministic
local seed. No production key material, credentials or private URLs are present.
