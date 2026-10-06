# Provenance

This capsule is a **derived, re-pinned public distribution** of a private canonical corpus.
It is **not** byte-identical to the private source as a whole. The public commit that contains
this directory is the distribution pin external readers should use; the private hashes below are
provenance only.

## Private source

- Repository: `nutstrut/morpheus` (private)
- Commit: `7374947a08510a7857d3ba5fd8c1b9387f3ed44d`
- Source path: `fixtures/sar-primitive-vectors-20261006/` (plus the tool and fixture files below)

Original private SHA-256 values:

| Private file | SHA-256 |
|---|---|
| `fixtures/sar-primitive-vectors-20261006/README.md` | `998c1486aa680e7a36a4c524a63ca76ac2c2afd9eae6cf8ac77853df2de03119` |
| `fixtures/sar-primitive-vectors-20261006/vectors.json` | `b7f1989c09d471ee0ced4fe27e62306ce6652dd83fa8cda04f2244567843a88f` |
| `fixtures/sar-primitive-vectors-20261006/run_vectors.py` | `22bd1aada0687ba67c98a678068c6ccbe9f51e5721266dc9318fb233aeb65e79` |
| `fixtures/sar-primitive-vectors-20261006/results/primitive_results.json` | `959d550225e6ef789457f216cba910dc37b6b5f2bf828192e14b6ddb389e3b20` |
| `reports/ecosystem/xmandate/fixtures/xmandate-generated-sar-receipt-20260605T215954Z.json` | `538b6d7bfd3ff215c3156c3085c47b636ac2c4a473617799f4f96cab682f3236` |
| `tools/sar_crypto_common.py` | `4aa8701d1d43e2e538a12e15c6eab81d634c747c43368103f1bb3239fcd6433c` |
| `tools/sar_portable_reader.py` | `de323f19ea6771e43a390d853e73bbf5ce04067c6b10b51eac815ec851da61e5` |
| `tests/test_sar_primitive_vectors.py` | `04856513ab5b0d10e20eacebd396478353b5735e8d2b25b4987a68a8f30752e3` |

## Byte-identical to the private source

| Public file | SHA-256 |
|---|---|
| `fixtures/xmandate-generated-sar-receipt-20260605T215954Z.json` | `538b6d7bfd3ff215c3156c3085c47b636ac2c4a473617799f4f96cab682f3236` |
| `sar_crypto_common.py` | `4aa8701d1d43e2e538a12e15c6eab81d634c747c43368103f1bb3239fcd6433c` |

## Modified for public dependency closure (new hashes)

The private runner assumed a Morpheus repo layout (`REPO = HERE.parents[1]`, imports of
`tools.*`, a fixture referenced in place under `reports/`). A public reader has none of that, so:

| Public file | New SHA-256 | Change |
|---|---|---|
| `sar_portable_reader.py` | `9ac002ad472af9b703723bf4fe47319585f4f65fd7e7d5d270f7a15b9d628586` | One line: `from tools.sar_crypto_common import (` → `from sar_crypto_common import (`. No logic change. |
| `run_vectors.py` | `ce2311f25f7723611b2991dd3e5659164b703f5a4135c248bd67e03987cfcdc2` | Capsule-local imports/paths (no `REPO`, no `tools.*`); added an executed `rfc8785` observation per input case and a `rfc8785` expectation key. |
| `vectors.json` | `9692dfc5bd59cbbf6b8cad8f6a309786b3a07194a718c2952dd7506344db155f` | Fixture path now capsule-local; added `rfc8785` expected outcomes for all 16 input cases and the independent-implementation note. All pre-existing expectations unchanged. |
| `results/primitive_results.json` | `a36883a3ff6129e2f4e9875b9423f94279ced3224f9222f3a20aeaf4af23aefe` | Regenerated; now includes rfc8785 outcomes. Differs from the private result by that addition only. |
| `tests/test_vectors.py` | `f853b7a9c464baa1f21a507ba5765672e93e2c11a6d87ec9012ac0c3b62294ef` | Ported from `tests/test_sar_primitive_vectors.py`; same 8 corruptions plus a 9th (rfc8785 expectation flipped) and direct ±2^53 checks on both libraries. |
| `README.md` | see `SHA256SUMS` | Rewritten for the public capsule. |
| `requirements.txt` | `afe3d98b35abb4202faa13f2ce79a5bf201b33bf08c47a1ec82d2f7ec533b28d` | New: exact pins. |

Semantics, test expectations, case set (27 cases) and the claim ceiling are preserved. The SAR
signed core, `receipt_id` derivation and verifier acceptance rules are unchanged.

## Test keys only

All keys are deterministic, labelled-seed TEST keys (seed = SHA-256 of a label in `vectors.json`,
or the fixture's own "deterministic local fixture seed"). No production signing key, private key
material, API key, credential, private URL or absolute local path is included.

## Validated dependency set (Python 3.10.12, clean venv)

```
cffi==2.1.1
cryptography==50.0.0
exceptiongroup==1.3.1
iniconfig==2.3.0
jcs==0.2.1
packaging==26.3
pluggy==1.6.0
pycparser==3.0
Pygments==2.21.0
pytest==9.1.0
rfc8785==0.1.4
tomli==2.4.1
typing_extensions==4.16.0
```

Integrity of the files in this directory: `sha256sum -c SHA256SUMS`.
