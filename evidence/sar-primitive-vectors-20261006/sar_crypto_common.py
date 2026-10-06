"""Generic, profile-agnostic crypto/canonicalization plumbing for SAR readers.

This module knows nothing about any SAR profile's field list, semantics, or
identity (portable `sar.v0.1`, `settlement-witness-verified-v0.2`, `sar-402`,
or anything else). It exists so `sar_portable_reader.py` (the portable-contract
boundary) and `sar_ds_reader.py` (Default Settlement-specific profiles) can
share JCS canonicalization, digesting, and Ed25519 verification without either
one importing the other or duplicating this plumbing. Sharing this file does
NOT let DS-specific semantics leak into the portable reader: nothing here
references a field name, profile id, or receipt shape.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Mapping

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SUPPORTED_KTY = "OKP"
SUPPORTED_CRV = "Ed25519"


class UnknownKeyError(KeyError):
    """`kid` not present in a parsed key registry."""


class UnsupportedAlgorithmError(ValueError):
    """Registry entry's kty/crv is not a recognized Ed25519 binding."""


@dataclass(frozen=True)
class KeyEntry:
    kid: str
    pubkey: bytes  # raw 32-byte Ed25519 public key
    alg: str  # always "Ed25519" for entries this module accepts
    profiles: tuple  # profile ids this kid is registry-authorized for, () if unspecified
    status: str  # registry lifecycle status string, "" if unspecified
    raw: Mapping[str, Any]  # original registry entry, for inspection


def _b64url_decode(value: str) -> bytes:
    pad = (4 - (len(value) % 4)) % 4
    return base64.urlsafe_b64decode(value + ("=" * pad))


def canonicalize(value: Any) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme encoding, as UTF-8 bytes."""
    return jcs.canonicalize(value)


def sha256_digest(canonical_bytes: bytes) -> bytes:
    return hashlib.sha256(canonical_bytes).digest()


def parse_key_registry(document: Mapping[str, Any]) -> Dict[str, KeyEntry]:
    """Parse a `.well-known/sar-keys.json`-shaped JWK-set document.

    Only `kty == "OKP"` / `crv == "Ed25519"` entries are accepted; any other
    kty/crv on a named `kid` raises rather than being silently skipped, so a
    caller cannot mistake "unsupported algorithm" for "key does not exist".
    Carries forward optional `profiles` (list of authorized profile ids) and
    `status` fields when present, since profile-authorization is a fact
    every reader needs kept separate from raw cryptographic validity.
    """
    keys = document.get("keys")
    if not isinstance(keys, list):
        raise ValueError("registry document must contain a 'keys' list")

    result: Dict[str, KeyEntry] = {}
    for entry in keys:
        kid = entry.get("kid")
        if not kid:
            continue
        kty = entry.get("kty")
        crv = entry.get("crv")
        if kty != SUPPORTED_KTY or crv != SUPPORTED_CRV:
            raise UnsupportedAlgorithmError(
                f"key {kid!r} declares kty={kty!r} crv={crv!r}; only "
                f"kty={SUPPORTED_KTY!r} crv={SUPPORTED_CRV!r} is supported"
            )
        x = entry.get("x")
        if not x:
            raise ValueError(f"key {kid!r} is missing required 'x' (public key) field")
        result[kid] = KeyEntry(
            kid=kid,
            pubkey=_b64url_decode(x),
            alg="Ed25519",
            profiles=tuple(entry.get("profiles", []) or []),
            status=entry.get("status", "") or "",
            raw=entry,
        )
    return result


def resolve_key(registry: Mapping[str, KeyEntry], kid: str) -> KeyEntry:
    try:
        return registry[kid]
    except KeyError as exc:
        raise UnknownKeyError(f"unknown key id: {kid!r}") from exc


def verify_digest_signature(pubkey_bytes: bytes, digest: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature over a raw digest (not canonical bytes).

    Every SAR profile encountered so far signs the sha256 digest of its JCS
    core, not the canonical bytes themselves -- this helper reflects that
    shared convention without asserting anything about which profile it is.
    Returns False on an invalid signature rather than raising, so callers can
    fold it into a classification result without a try/except at every call
    site; malformed key/signature bytes still raise (they are caller bugs,
    not "signature did not verify").
    """
    pubkey = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
    try:
        pubkey.verify(signature, digest)
        return True
    except InvalidSignature:
        return False


def decode_sig(sig_field: str) -> bytes:
    """Decode a `"base64url:<...>"`-prefixed signature field to raw bytes."""
    if sig_field.startswith("base64url:"):
        sig_field = sig_field[len("base64url:"):]
    return _b64url_decode(sig_field)
