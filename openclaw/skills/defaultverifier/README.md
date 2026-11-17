# defaultverifier Skill (internal, unpublished)

Helps an agent verify an **existing** Default Settlement receipt offline and state what
it does and does not establish. Verification only.

- **Does:** verify `0.2-candidate` receipts (profiles `settlement-witness-verified-v0.2`
  and `-counterparty-bound`) against a pinned bundled trust snapshot; map signed
  properties to established / contradicted / not established; report unsigned fields by name.
- **Does not:** issue or demo receipts, call hosted endpoints, enroll, pay, fetch keys,
  use the network or credentials, certify agents, or prove execution / payment / legal finality.
- **Versions:** v0.2-candidate only. v0.1 and portable receipts are rejected as
  `NOT_A_V02_RECEIPT`; the sibling `settlement-witness` Skill (untouched) covers v0.1.
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
