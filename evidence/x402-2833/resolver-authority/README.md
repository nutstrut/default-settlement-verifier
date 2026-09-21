# x402 #2833 resolver-authority evidence

This directory publishes the exact V1 and V2 resolver-authority fixtures,
deterministic local verifiers, and conformance reports used to inspect the
resolver-authority behavior discussed in x402-foundation/x402#2833.

## V1 and V2

V1 is the original three-case vector. V2 is the current hardened vector: it
adds literal null-authority handling, explicit sequence ordering, exact
resolver/check-set/successor binding, generic priority resolution, and named
negative behaviors. V2 supersedes V1 for current review; V1 remains published
for traceability and compatibility.

Both fixtures are synthetic. The verifiers are deterministic and local; they
do not establish real-world authority, trusted time, historical existence,
operator standing, external adoption, or protocol conformance.

Supported claims are limited to the byte-published fixture behavior described
by each report: valid evidence and lifecycle inputs do not create authority,
exact prior-authorized tuples can allow a transition, and missing, late,
ambiguous, or substituted authority is blocked according to the vector.

These artifacts do not claim x402 adoption, x402 Foundation adoption, charter
adoption, production deployment, or endorsement by x402 contributors.

## Run locally

From this directory:

```text
python v1/verify.py
python v2/verify.py
```

Expected summaries:

```text
resolver_authority_vector=ok tests=4
resolver_authority_vector_v2=ok named_behaviors=12
```

## Canonical provenance

The published V1 bytes are copied from the Morpheus `origin/main` canonical
artifacts at commit
`aeec88d92085f6ac36f0c10dc18e8640214232e2`:

- `reports/fixtures/x402-2833-resolver-authority-vector-20260919.json`
- `reports/fixtures/x402-2833-resolver-authority-verify-20260919.py`
- `reports/readiness/x402-2833-resolver-authority-conformance-vector-20260919.md`

The published V2 bytes are copied from Morpheus `origin/main` canonical
artifacts at commit
`de405e876e9a52986c1e4e2fdae5d93d7c30a8da`:

- `reports/fixtures/x402-2833-resolver-authority-vector-v2-20260921.json`
- `reports/fixtures/x402-2833-resolver-authority-verify-v2-20260921.py`
- `reports/readiness/x402-2833-resolver-authority-conformance-vector-v2-20260921.md`

`SHA256SUMS` records the hashes of the six canonical copies. It is a
distribution index, not a new canonical artifact.

Public distribution makes the bytes externally inspectable; it does not by
itself establish external reproduction, adoption, or normative authority.
