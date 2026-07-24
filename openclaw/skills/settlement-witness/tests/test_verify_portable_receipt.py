"""Tests for the skill's Portable SAR verification entry point. Runs the
same shared fixture corpus used by the canonical conformance tests in
default-settlement-verifier/portable/. Does not import or touch
verify_receipt.py (the existing wallet-bound verifier)."""
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
PORTABLE_DIR = REPO_ROOT / "portable"
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_portable_receipt.py"

sys.path.insert(0, str(PORTABLE_DIR))

FIXTURES = json.loads((PORTABLE_DIR / "fixtures" / "portable-sar-fixtures.json").read_text())
KEYS_PATH = PORTABLE_DIR / "fixtures" / "portable-sar-fixture-keys.json"

EXPECTED = {
    "01_valid_portable": "VERIFIED",
    "04_tampered_signed_field": "REJECTED_RECEIPT_ID_MISMATCH",
    "06_unknown_key": "REJECTED_UNKNOWN_KEY",
    "07_spoofed_key": "REJECTED_INVALID_SIGNATURE",
    "09_malformed_version": "REJECTED_NOT_PORTABLE_CANDIDATE",
    "11_walletbound_presented_as_portable": "REJECTED_NOT_PORTABLE_CANDIDATE",
    "12_metadata_grafted_walletbound": "REJECTED_PROFILE_NOT_AUTHORIZED",
}


def run_cli(receipt_obj, tmp_path):
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt_obj))
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), str(receipt_path), "--keys", str(KEYS_PATH), "--json"],
        capture_output=True,
        text=True,
    )
    return json.loads(proc.stdout)


def test_skill_portable_verification_matrix(tmp_path):
    for name, expected_status in EXPECTED.items():
        result = run_cli(FIXTURES[name], tmp_path)
        assert result["status"] == expected_status, f"{name}: expected {expected_status}, got {result['status']} ({result.get('reason')})"


def test_verified_receipts_never_attest_wallet_binding(tmp_path):
    for name in ("01_valid_portable", "02_unsigned_counterparty", "14_ambiguous_envelope"):
        result = run_cli(FIXTURES[name], tmp_path)
        assert result["status"] == "VERIFIED"
        assert result["wallet_binding_attested"] is False


def test_unsigned_counterparty_reported_but_not_attested(tmp_path):
    result = run_cli(FIXTURES["02_unsigned_counterparty"], tmp_path)
    assert result["status"] == "VERIFIED"
    assert result["unsigned_claims"].get("counterparty") == "0xUNSIGNED_PORTABLE"
    assert result["wallet_binding_attested"] is False
