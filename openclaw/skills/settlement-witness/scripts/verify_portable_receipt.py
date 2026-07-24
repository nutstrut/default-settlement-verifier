#!/usr/bin/env python3
"""
Verify a Portable SAR v0.1 (six-field, original/portable profile) receipt
against a caller-supplied trusted-key policy.

This is a SEPARATE verification path from `verify_receipt.py` in this same
directory, which verifies Default Settlement's wallet-bound receipts.
`verify_receipt.py` is untouched by this file. See
default-settlement-verifier/portable/README.md for the canonical source
this script bundles a pinned copy of.

Usage:
  verify_portable_receipt.py <receipt.json> --keys <key-policy.json>

<key-policy.json> shape:
  {
    "<kid>": {"pubkey_b64url": "...", "profiles": ["portable-sar-v0.1"], "source": "..."}
  }

This script trusts ONLY the keys explicitly listed in the supplied
key-policy file. There is no default/bundled trust store for the portable
profile — unlike the wallet-bound path, which pins Default Settlement's own
production registry, the portable path is inherently multi-issuer and must
be told what to trust.
"""
import argparse
import base64
import json
import sys
from pathlib import Path

# --- BEGIN bundled pinned copy of default-settlement-verifier/portable/portable_sar_verify.py ---
# Pinned source: default-settlement-verifier, same-repo canonical path
# portable/portable_sar_verify.py. Imported directly (no cross-repo
# coupling — this IS the canonical repo) rather than duplicated, since the
# skill lives in the same repository as the canonical source.
_THIS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _THIS_DIR.parents[3]  # openclaw/skills/settlement-witness/scripts -> repo root
sys.path.insert(0, str(_REPO_ROOT / "portable"))
from portable_sar_verify import (  # noqa: E402
    KeyPolicyEntry,
    verify_portable_sar_receipt,
)
# --- END bundled pinned copy ---


def load_key_policy(path: str):
    data = json.loads(Path(path).read_text())

    def policy(kid):
        entry = data.get(kid)
        if entry is None:
            return None
        pad = (-len(entry["pubkey_b64url"])) % 4
        pubkey = base64.urlsafe_b64decode(entry["pubkey_b64url"] + ("=" * pad))
        return KeyPolicyEntry(pubkey=pubkey, profiles=frozenset(entry["profiles"]), source=entry["source"])

    return policy


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("receipt", help="Path to a Portable SAR receipt JSON file")
    parser.add_argument("--keys", required=True, help="Path to a key-policy JSON file")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON only")
    args = parser.parse_args()

    receipt = json.loads(Path(args.receipt).read_text())
    key_policy = load_key_policy(args.keys)
    result = verify_portable_sar_receipt(receipt, key_policy)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(f"status: {result.status}")
        if result.profile:
            print(f"profile: {result.profile}")
        if result.signed_fields:
            print(f"signed_fields: {', '.join(result.signed_fields)}")
        if result.unsigned_claims:
            print(f"unsigned_claims (NOT cryptographically attested): {json.dumps(result.unsigned_claims)}")
        print(f"wallet_binding_attested: {result.wallet_binding_attested}")
        if result.reason:
            print(f"reason: {result.reason}")

    return 0 if result.is_verified() else 1


if __name__ == "__main__":
    sys.exit(main())
