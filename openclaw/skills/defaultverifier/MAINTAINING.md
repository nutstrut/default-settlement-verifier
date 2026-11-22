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

Clarification: `byte_identical_to` in the provenance file refers to the SNAPSHOT being byte-identical to
`settlement-witness/sar-keys.json@cae818c`, not to the provenance JSON itself. The provenance JSON has
exactly one declared local edit (the snapshot filename); the release gate enforces that this is the only
allowed provenance divergence, and tests confirm `local_edits` is accepted only for the provenance file
and only for the `snapshot_file` field.

### Trust snapshot is shipped as-is (maintainer decision)

`trust/sar-keys-v02-snapshot.json` is hash-pinned canonical trust material and is preserved byte-for-byte.
Some metadata fields inside it (for example approval references, OPMA ids, internal report paths) are
canonical registry metadata. They are not runtime instructions, secrets or credentials, and scrubbing them
would break byte identity and reproducibility. Never edit the snapshot; the bundle checker does not
secret-scan it differently from other shipped files, and refreshes produce a new snapshot with new provenance.
When refreshing, re-apply the one-field edit and update `sha256` / `upstream_sha256`.

### Public bundle (publication gate; nothing here publishes)

`PUBLIC_BUNDLE.json` defines exactly which files ship. Tests, vectors, the parity gate, this
file, `UPSTREAM.json` and `PUBLIC_BUNDLE.json` are repository-only.

```bash
python3 openclaw/skills/defaultverifier/tests/check_public_bundle.py --build /tmp/dv-bundle   # scratch copy from the manifest
python3 openclaw/skills/defaultverifier/tests/check_public_bundle.py /tmp/dv-bundle           # validate a directory or .zip
```

`PUBLIC_BUNDLE.json` pins each shipped file's path, SHA-256 and size. After a deliberate edit to a shipped
file, refresh with `check_public_bundle.py --write-hashes` and review the diff.

The check is offline, never extracts a ZIP, and fails on: duplicate or case/Unicode-colliding entry names;
symlinks and any non-regular file (directories are inspected with `lstat`; ZIP symlink entries are detected
from Unix mode bits); absolute, traversal, `.`/`..`, backslash or drive-letter paths; tests, vectors, unexpected
files, missing files, caches or `.pyc`, repository-only files; any shipped byte that differs from the manifest
SHA-256; secret-like strings (PEM keys, `sk-`, GitHub, AWS, Slack tokens, bearer tokens, `KEY=`/`SECRET=`/`TOKEN=`
assignments); and internal paths/endpoints (`/home/`, `/Users/`, localhost, loopback, RFC1918 addresses,
worktree and working-branch names). Public URLs such as `https://defaultverifier.com` are allowed. Targeted
patterns are used instead of entropy heuristics, so receipt ids, hashes and signatures are not flagged.
Limitation: a ZIP entry whose Unix mode bits are absent cannot be identified as a symlink; such an entry
would still be hash-checked against the manifest and could not pass as a required file unless its bytes match.

### Example receipt provenance

`examples/receipt-indeterminate.json` is the receipt of vector `valid-real-06-indeterminate`
(a real production receipt signed by `sar-prod-ed25519-06`, `request_id: profile-check`, issued
2026-09-08), copied unchanged from `tests/fixtures/vectors.json` (which is byte-identical to the
upstream defaultsettle-cli vectors). No receipt was issued for this Skill. Its `payment` object is
an unsigned field of the original receipt and is public.
