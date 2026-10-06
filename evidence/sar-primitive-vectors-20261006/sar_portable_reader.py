"""Portable SAR v0.1 reader -- the portable-contract boundary.

Mirrors the public read-path API of the published `sar-envelope` package
(PyPI `sar-envelope` 0.1.1 / npm `sar-envelope` 0.1.0; confirmed by direct
wheel inspection in
`reports/readiness/sar-production-dependency-resolution-20260903.md` Part 6)
so behavior here matches what an independent, non-Default-Settlement
verifier already does. This module must never import, reference, or branch
on anything Default-Settlement-specific (`receipt_profile`,
`settlement-witness-verified-v0.2`, `verification_basis`, `properties`,
`counterparty`, etc.). An external portable-SAR implementation should be
able to verify a `sar.v0.1` artifact using logic equivalent to this file
with zero knowledge of Default Settlement's infrastructure or evaluation
records -- that is the whole point of keeping this file separate from
`sar_ds_reader.py`.
"""
from __future__ import annotations

from typing import Any, Mapping

from sar_crypto_common import (
    KeyEntry,
    UnknownKeyError,
    canonicalize,
    decode_sig,
    resolve_key,
    sha256_digest,
    verify_digest_signature,
)

# The frozen, six-field portable SAR v0.1 signed core. Never extend this
# tuple -- an artifact carrying any other field in its core is, by
# definition, not portable-SAR-conformant (see `CoreFieldError` below,
# matching the published package's own hard-rejection behavior).
CORE_FIELDS = (
    "task_id_hash",
    "verdict",
    "confidence",
    "reason_code",
    "ts",
    "verifier_kid",
)

# Envelope-level fields required alongside the core for an artifact to even
# be a portable-SAR *candidate* (necessary, not sufficient -- profile
# authorization is a separate check, done by the caller via the key
# registry's `profiles` field).
REQUIRED_CANDIDACY_FIELDS = ("receipt_version", "sig_alg")
REQUIRED_RECEIPT_VERSION = "0.1"
REQUIRED_SIG_ALG = "Ed25519"

# Fields commonly seen alongside the signed core in a full artifact object --
# envelope metadata or explicitly unsigned. This is NOT an allowlist: per the
# published `sar-envelope` 0.1.1 contract (`extract_core()`'s own docstring:
# "Ignores any other field present on `receipt`"), ANY top-level field not in
# `CORE_FIELDS` is tolerated, not just these named examples. Kept only to
# label a genuinely-unrecognized extra field in a diagnostic warning.
KNOWN_UNSIGNED_ENVELOPE_FIELDS = frozenset(
    {"receipt_id", "sig", "receipt_version", "sig_alg", "_ext", "_perf", "counterparty"}
)


class CoreFieldError(ValueError):
    """Raised when a mapping does not contain exactly the six core fields."""


def is_candidate(artifact: Mapping[str, Any]) -> bool:
    """True if `artifact` declares portable-SAR v0.1 candidacy.

    Candidacy requires `receipt_version == "0.1"` and `sig_alg == "Ed25519"`
    at the top level -- this is a necessary, unsigned declaration, not proof
    of a valid or authorized signature.
    """
    return (
        artifact.get("receipt_version") == REQUIRED_RECEIPT_VERSION
        and artifact.get("sig_alg") == REQUIRED_SIG_ALG
    )


def extract_core(artifact: Mapping[str, Any]) -> dict:
    """Extract exactly the six signed-core fields.

    Raises `CoreFieldError` if any is missing. Ignores any other top-level
    key, matching the published `sar-envelope` 0.1.1 contract -- callers that
    want to know whether *extra* fields are present (informational only, see
    `extra_top_level_fields`) must check that separately.
    """
    missing = [f for f in CORE_FIELDS if f not in artifact]
    if missing:
        raise CoreFieldError(f"artifact is missing required core field(s): {missing}")
    return {k: artifact[k] for k in CORE_FIELDS}


def extra_top_level_fields(artifact: Mapping[str, Any]) -> frozenset:
    """Fields present on `artifact` beyond the six-field signed core.

    Diagnostic only. Per the published `sar-envelope` 0.1.1 contract,
    `extract_core()` ignores any field not in `CORE_FIELDS` -- their presence
    never disqualifies an artifact from portable-SAR conformance, since they
    play no part in `core_digest()`/`verify_signature()` either way (both
    operate on exactly `CORE_FIELDS`, extracted fresh from the artifact).
    A caller may still want to flag a field it doesn't recognize as
    informational; `KNOWN_UNSIGNED_ENVELOPE_FIELDS` lists the common,
    expected ones (not exhaustive -- see its own docstring).
    """
    return frozenset(artifact.keys()) - frozenset(CORE_FIELDS)


def core_digest(core: Mapping[str, Any]) -> bytes:
    """sha256(JCS(core)) as raw 32 bytes. `core` must be exactly the six fields."""
    extra = set(core.keys()) - set(CORE_FIELDS)
    if extra:
        raise CoreFieldError(f"core contains non-core field(s): {sorted(extra)}")
    missing = [f for f in CORE_FIELDS if f not in core]
    if missing:
        raise CoreFieldError(f"core is missing required field(s): {missing}")
    return sha256_digest(canonicalize(core))


def receipt_id(core: Mapping[str, Any]) -> str:
    return "sha256:" + core_digest(core).hex()


def verify_signature(artifact: Mapping[str, Any], key_registry: Mapping[str, KeyEntry]):
    """Verify a portable SAR v0.1 artifact's signature against a key registry.

    Returns one of the strings: "VALID", "INVALID_SIGNATURE",
    "INVALID_RECEIPT_ID_MISMATCH", "UNKNOWN_KEY", "MISSING_SIG_FIELD".
    Never returns "VALID" without an actual Ed25519 verification. Does not
    check profile authorization (`profiles` on the KeyEntry) -- that is a
    distinct concept the caller (the classifier) must check separately, so
    "signature valid under an unauthorized key" and "signature invalid" stay
    two different findings rather than collapsing into one.
    """
    core = extract_core(artifact)
    digest = core_digest(core)
    kid = core["verifier_kid"]
    try:
        entry = resolve_key(key_registry, kid)
    except UnknownKeyError:
        return "UNKNOWN_KEY"
    sig_field = artifact.get("sig")
    if not sig_field:
        return "MISSING_SIG_FIELD"
    if artifact.get("receipt_id") and artifact["receipt_id"] != "sha256:" + digest.hex():
        return "INVALID_RECEIPT_ID_MISMATCH"
    sig_bytes = decode_sig(sig_field)
    if verify_digest_signature(entry.pubkey, digest, sig_bytes):
        return "VALID"
    return "INVALID_SIGNATURE"
