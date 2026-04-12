#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import sys
import urllib.request

try:
    import jcs
except ImportError:
    print("Missing dependency: jcs")
    print("Install with: pip3 install jcs pynacl")
    sys.exit(1)

try:
    from nacl.signing import VerifyKey
except ImportError:
    print("Missing dependency: pynacl")
    print("Install with: pip3 install jcs pynacl")
    sys.exit(1)


DEFAULT_BASE_URL = "https://defaultverifier.com"


def b64url_decode(data: str) -> bytes:
    data = data.strip()
    if data.startswith("base64url:"):
        data = data[len("base64url:"):]
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def http_get_json(url: str) -> dict:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "sar-python-example/0.1",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def extract_core_fields(receipt: dict) -> dict:
    excluded = {"receipt_id", "sig", "sig_alg", "_perf", "_ext", "jws", "payload", "envelope"}
    return {k: v for k, v in receipt.items() if k not in excluded}


def normalize_receipt_shape(data: dict) -> dict:
    if "receipt_v0_1" in data and isinstance(data["receipt_v0_1"], dict):
        return data["receipt_v0_1"]
    return data


def get_public_key_from_registry(registry: dict, kid: str) -> bytes:
    keys = registry.get("keys", [])
    for key in keys:
        if key.get("kid") == kid:
            pub = key.get("public_key_b64") or key.get("public_key") or key.get("x")
            if not pub:
                raise ValueError(f"Key {kid} found but no public key field present")
            return b64url_decode(pub)
    raise ValueError(f"kid not found in registry: {kid}")


def verify_receipt(base_url: str, receipt_id: str) -> bool:
    receipt_url = f"{base_url.rstrip('/')}/settlement-witness/receipt/{receipt_id}"
    registry_url = f"{base_url.rstrip('/')}/.well-known/sar-keys.json"

    receipt_data = http_get_json(receipt_url)
    receipt = normalize_receipt_shape(receipt_data)
    registry = http_get_json(registry_url)

    core = extract_core_fields(receipt)
    canonical = jcs.canonicalize(core)
    digest = hashlib.sha256(canonical).hexdigest()
    expected_receipt_id = f"sha256:{digest}"

    print("Fetched receipt_id: ", receipt.get("receipt_id"))
    print("Recomputed ID:     ", expected_receipt_id)

    if receipt.get("receipt_id") != expected_receipt_id:
        print("FAIL: receipt_id mismatch")
        return False

    kid = receipt.get("verifier_kid")
    sig = receipt.get("sig")
    if not kid or not sig:
        print("FAIL: missing verifier_kid or sig")
        return False

    public_key = get_public_key_from_registry(registry, kid)
    sig_bytes = b64url_decode(sig)

    try:
        VerifyKey(public_key).verify(hashlib.sha256(canonical).digest(), sig_bytes)
    except Exception as e:
        print(f"FAIL: signature verification failed: {e}")
        return False

    print("PASS: signature verified")
    print("kid: ", kid)
    print("verdict: ", receipt.get("verdict"))
    print("reason_code: ", receipt.get("reason_code"))
    print("ts: ", receipt.get("ts"))
    return True


def main():
    parser = argparse.ArgumentParser(description="Verify a SAR receipt from DefaultVerifier")
    parser.add_argument("receipt_id", help="Receipt ID, e.g. sha256:...")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Base URL of verifier")
    args = parser.parse_args()

    ok = verify_receipt(args.base_url, args.receipt_id)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()