"""Canonical Python conformance test for portable_sar_verify.py against the
shared synthetic fixture corpus (the SAME JSON files the JS test consumes —
cross-language parity is the point). Run with: python3 test_conformance.py
"""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from portable_sar_verify import (  # noqa: E402
    KeyPolicyEntry,
    PORTABLE_PROFILE_ID,
    STATUS_VERIFIED,
    STATUS_UNKNOWN_KEY,
    STATUS_PROFILE_NOT_AUTHORIZED,
    STATUS_RECEIPT_ID_MISMATCH,
    STATUS_INVALID_SIGNATURE,
    STATUS_NOT_CANDIDATE,
    verify_portable_sar_receipt,
)

HERE = os.path.dirname(__file__)
fixtures = json.load(open(os.path.join(HERE, "fixtures", "portable-sar-fixtures.json")))
key_registry = json.load(open(os.path.join(HERE, "fixtures", "portable-sar-fixture-keys.json")))


def b64url_to_bytes(s: str) -> bytes:
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))


def key_policy(kid):
    entry = key_registry.get(kid)
    if entry is None:
        return None
    return KeyPolicyEntry(
        pubkey=b64url_to_bytes(entry["pubkey_b64url"]),
        profiles=frozenset(entry["profiles"]),
        source=entry["source"],
    )


EXPECTED = {
    "01_valid_portable": STATUS_VERIFIED,
    "02_unsigned_counterparty": STATUS_VERIFIED,
    "03_with_ext": STATUS_VERIFIED,
    "04_tampered_signed_field": STATUS_RECEIPT_ID_MISMATCH,
    "05_substituted_unsigned_metadata": STATUS_VERIFIED,
    "05b_stripped_unsigned_metadata": STATUS_VERIFIED,
    "06_unknown_key": STATUS_UNKNOWN_KEY,
    "07_spoofed_key": STATUS_INVALID_SIGNATURE,
    "08_invalid_signature": STATUS_INVALID_SIGNATURE,
    "09_malformed_version": STATUS_NOT_CANDIDATE,
    "09b_malformed_alg": STATUS_NOT_CANDIDATE,
    "11_walletbound_presented_as_portable": STATUS_NOT_CANDIDATE,
    "12_metadata_grafted_walletbound": STATUS_PROFILE_NOT_AUTHORIZED,
    "13_portable_presented_as_walletbound_boundary_case": STATUS_VERIFIED,
    "14_ambiguous_envelope": STATUS_VERIFIED,
}

passed = 0
failed = 0

for name, expected_status in EXPECTED.items():
    receipt = fixtures[name]
    result = verify_portable_sar_receipt(receipt, key_policy)
    ok = result.status == expected_status
    passed += ok
    failed += not ok
    print(f"{'ok  ' if ok else 'FAIL'}  {name:<45} expected={expected_status} got={result.status}" + ("" if ok else f"  reason={result.reason}"))

for name, expected_status in EXPECTED.items():
    if expected_status != STATUS_VERIFIED:
        continue
    result = verify_portable_sar_receipt(fixtures[name], key_policy)
    ok = result.wallet_binding_attested is False
    passed += ok
    failed += not ok
    print(f"{'ok  ' if ok else 'FAIL'}  {name:<45} wallet_binding_attested must be False, got={result.wallet_binding_attested}")

r = verify_portable_sar_receipt(fixtures["12_metadata_grafted_walletbound"], key_policy, requested_profile=PORTABLE_PROFILE_ID)
ok = r.status == STATUS_PROFILE_NOT_AUTHORIZED
passed += ok
failed += not ok
print(f"{'ok  ' if ok else 'FAIL'}  explicit_request_cannot_override_authorization got={r.status}")

print(f"\n{passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)
