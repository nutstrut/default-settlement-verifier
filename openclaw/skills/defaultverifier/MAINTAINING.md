# defaultverifier Skill: maintainer notes (repository-only, not part of the public bundle)

Helps an agent verify an **existing** Default Settlement receipt offline and state what
it does and does not establish. Verification only.

- **Does:** verify `0.2-candidate` receipts (profiles `settlement-witness-verified-v0.2`
  and `-counterparty-bound`) against a pinned bundled trust snapshot; map signed
  properties to established / contradicted / not established; report unsigned fields by name.
- **Does not:** issue or demo receipts, call hosted endpoints, enroll, pay, fetch keys,
  use the network or credentials, certify agents, or prove execution / payment / legal finality.
- **Versions:** v0.2-candidate only. v0.1 and portable receipts are rejected as
  `NOT_A_V02_RECEIPT`; the sibling `settlement-witness` Skill covers v0.1.
- **One verifier:** `scripts/verify_v02.py` is a byte copy of defaultsettle-cli's core
  (hashes in `UPSTREAM.json`). `scripts/verify_receipt_v02.py` is only I/O and report rendering.
- **Requires:** python3 and `cryptography`.

Input safety: the receipt path must open to a regular file (fstat on the open descriptor;
at most 2 MiB + 1 bytes are ever read). Symlinks are followed only if they resolve to a regular
file. FIFOs, devices, sockets and directories are refused without being read. Output safety:
receipt-controlled strings pass field-specific policies (known reason-code vocabulary, narrow
field-name shape, strict id shapes) in both the report and `--json`.

Test (offline; includes the 187-vector parity suite):

```bash
python3 -m pytest openclaw/skills/defaultverifier/tests -q
```

### Release gate (run before merge or release; fails, never skips)

```bash
python3 openclaw/skills/defaultverifier/tests/check_upstream_parity.py --cli-repo /path/to/defaultsettle-cli
```

`--cli-repo` is a local checkout that you supply (no cloning, no fetching; the checkout is only read).
It fails unless: the pinned commit exists; the vendored verifier, trust snapshot, provenance and
vectors are byte-identical to the upstream blobs at that commit and match `UPSTREAM.json` hashes;
the upstream HEAD has not drifted from the pinned version; and the canonical CLI `verify-v02` output
equals the helper's verifier result on the bundled-snapshot vectors. A missing path is a failure.

### Refreshing the vendored verifier

1. In defaultsettle-cli, review and land the verifier change; note the new commit SHA.
2. Copy `defaultsettle/verify_v02.py`, `defaultsettle/sar-keys-v02-snapshot.json`,
   `defaultsettle/sar-keys-v02-snapshot.provenance.json` and `tests/fixtures/v02/vectors.json`
   byte-for-byte to `scripts/`, `trust/` and `tests/fixtures/vectors.json`. Never edit them in place.
3. Update `source_commit` and each `sha256` in `UPSTREAM.json`
   (`sha256sum` each vendored file; the provenance file's own `sha256` must match the snapshot).
4. Update `DEPTH_TEXT_PATH_DIVERGENCES` in the tests if vector counts or depth vectors changed.
5. Run the tests, then the release gate above against the new commit. Merge only on PASS.

Depth-vector accounting: core-object parity runs every vector through the library path; file-text
parity runs every vector through the path the Skill uses. They may differ only for the exact vectors in
`DEPTH_TEXT_PATH_DIVERGENCES` (raw-text depth validation necessarily precedes object canonicalization);
each is asserted to diverge, and every other vector must match exactly.

### Local edit to the vendored provenance file

`trust/sar-keys-v02-snapshot.provenance.json` differs from upstream in exactly one field: upstream
names the snapshot `sar-keys-snapshot.json`; the shipped file is `sar-keys-v02-snapshot.json`.
`UPSTREAM.json` declares this under `local_edits` and the release gate verifies the file is
identical to upstream except that field (plus both hashes). The snapshot bytes are unchanged.
When refreshing, re-apply the one-field edit and update `sha256` / `upstream_sha256`.

### Public bundle (publication gate; nothing here publishes)

`PUBLIC_BUNDLE.json` defines exactly which files ship. Tests, vectors, the parity gate, this
file, `UPSTREAM.json` and `PUBLIC_BUNDLE.json` are repository-only.

```bash
python3 openclaw/skills/defaultverifier/tests/check_public_bundle.py --build /tmp/dv-bundle   # scratch copy from the manifest
python3 openclaw/skills/defaultverifier/tests/check_public_bundle.py /tmp/dv-bundle           # validate a directory or .zip
```

The check is offline and fails on tests, vectors, unexpected files, missing runtime files, caches
or `.pyc`, repository-only files, and internal paths/wording in shipped text.

### Example receipt provenance

`examples/receipt-indeterminate.json` is the receipt of vector `valid-real-06-indeterminate`
(a real production receipt signed by `sar-prod-ed25519-06`, `request_id: profile-check`, issued
2026-09-08), copied unchanged from `tests/fixtures/vectors.json` (which is byte-identical to the
upstream defaultsettle-cli vectors). No receipt was issued for this Skill. Its `payment` object is
an unsigned field of the original receipt and is public.
