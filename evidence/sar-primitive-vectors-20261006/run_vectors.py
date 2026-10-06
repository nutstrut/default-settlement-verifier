#!/usr/bin/env python3
"""Deterministic local runner for the SAR primitive vector corpus.

Scope: shared cryptographic/canonicalization primitives ONLY
(claim ceiling PRIMITIVE_COMPATIBILITY_ONLY). No network, no AIR code.

Fail closed: exit status is 0 only if EVERY declared expectation in the
corpus matched what the SAR stack actually computed. Any mismatch, unknown
expectation key, malformed case, unexpected exception, or case-count drift
yields a nonzero exit. Nothing is merely printed.

Self-contained capsule: only capsule-local files plus pinned pip dependencies
(see requirements.txt). Derived/re-pinned from a private source; see PROVENANCE.md.

Usage (from anywhere):
    python3 evidence/sar-primitive-vectors-20261006/run_vectors.py [--vectors PATH] [--out PATH]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import jcs  # noqa: E402
import rfc8785  # noqa: E402

import sar_crypto_common as crypto  # noqa: E402
import sar_portable_reader as portable  # noqa: E402

SCHEMA = "sar-primitive-vectors/v1"
CEILING = "PRIMITIVE_COMPATIBILITY_ONLY"
KNOWN_EXPECT_KEYS = {"parse", "canonicalization", "sha256", "receipt_id", "rfc8785"}
KNOWN_SIG_KEYS = {
    "pubkey_b64url", "preimage_hex", "signature_b64url", "expected_verify",
    "signed_preimage", "preimage_derivation", "key_provenance", "mutation_of",
    "mutation", "deterministic_resign_check", "portable_verifier_check",
    "convention_note",
}
LOSSY = "ESTABLISHED_BYTES__INPUT_VALUE_NOT_PRESERVED_LOSSY"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))


class Run:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.rows: list[dict] = []

    def check(self, case_id: str, what: str, expected, actual) -> str:
        ok = expected == actual
        if not ok:
            self.failures.append(f"{case_id}: {what}: expected {expected!r} actual {actual!r}")
        return "MATCH" if ok else "MISMATCH"


def strict_loads(text: str):
    dup: list[bool] = []

    def hook(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            dup.append(True)
        return dict(pairs)

    return json.loads(text, object_pairs_hook=hook), bool(dup)


def resolve_artifact(vectors: dict, art_id: str) -> dict:
    meta = next(a for a in vectors["reused_artifacts"] if a["artifact_id"] == art_id)
    return json.loads((HERE / meta["path"]).read_text())


def pointer(doc: dict, ptr: str):
    cur = doc
    for part in [p for p in ptr.split("/") if p]:
        cur = cur[part]
    return cur


def rfc8785_outcome(value) -> dict:
    """Independent rfc8785 canonicalization of the already-parsed value (observational)."""
    try:
        raw = rfc8785.dumps(value)
        return {"status": "ESTABLISHED", "canonical_bytes_hex": raw.hex()}
    except Exception as exc:  # noqa: BLE001
        return {"status": "REJECTED", "error_class": type(exc).__name__}


def run_input_case(run: Run, vectors: dict, case: dict, actuals: dict) -> dict:
    cid = case["case_id"]
    exp = case["expect"]
    for k in exp:
        if k not in KNOWN_EXPECT_KEYS:
            run.failures.append(f"{cid}: unknown expect key {k!r}")
    inp = case["input"]
    res: dict = {}
    value = None
    dup = False
    try:
        if inp["kind"] == "json_text":
            value, dup = strict_loads(inp["text"])
        elif inp["kind"] == "reused_artifact":
            value = portable.extract_core(pointer(resolve_artifact(vectors, inp["artifact_id"]), inp["json_pointer"]))
        else:
            raise ValueError(f"unknown input kind {inp['kind']!r}")
        res["parse"] = {"status": "ESTABLISHED", "duplicate_keys_detected": dup}
    except Exception as exc:  # noqa: BLE001
        res["parse"] = {"status": "REJECTED", "error_class": type(exc).__name__}
    canon = None
    if res["parse"]["status"] == "ESTABLISHED":
        try:
            canon = crypto.canonicalize(value)
            res["canonicalization"] = {
                "status": "ESTABLISHED",
                "canonical_bytes_hex": canon.hex(),
                "canonical_utf8": canon.decode("utf-8"),
            }
            res["sha256"] = {"status": "ESTABLISHED", "digest_hex": hashlib.sha256(canon).hexdigest(), "over": "canonical_bytes"}
        except Exception as exc:  # noqa: BLE001
            res["canonicalization"] = {"status": "REJECTED", "error_class": type(exc).__name__}
            res["sha256"] = {"status": "NOT_APPLICABLE"}
    if res["parse"]["status"] == "ESTABLISHED":
        r8 = rfc8785_outcome(value)
        sar_c = res.get("canonicalization", {})
        if r8["status"] == "ESTABLISHED" and sar_c.get("status") == "ESTABLISHED":
            r8["relation_to_sar_jcs"] = (
                "IDENTICAL_BYTES" if r8["canonical_bytes_hex"] == sar_c["canonical_bytes_hex"] else "DIFFERENT_BYTES"
            )
        else:
            r8["relation_to_sar_jcs"] = "DIFFERENT_OUTCOME" if r8["status"] != sar_c.get("status") else "BOTH_REJECTED"
        res["rfc8785"] = r8
    if "receipt_id" in exp:
        res["receipt_id"] = (
            {"status": "ESTABLISHED", "value": portable.receipt_id(value)} if canon is not None else {"status": "NOT_APPLICABLE"}
        )
    actuals[cid] = canon

    # derived SAR behavior label
    if res["parse"]["status"] == "REJECTED":
        label = "PARSE_REJECTED"
    elif dup:
        label = "PARSE_ACCEPTED_SILENT_LAST_WINS__NOT_REJECTED"
    elif canon is None:
        label = (
            "PARSE_ACCEPTED__CANONICALIZATION_REJECTED_AT_UTF8_ENCODE"
            if res["canonicalization"]["error_class"] == "UnicodeEncodeError"
            else "PARSE_ACCEPTED__CANONICALIZATION_REJECTED_OTHER"
        )
    elif json.loads(canon) != value:
        label = LOSSY
    else:
        label = "ESTABLISHED"
    res["sar_behavior"] = label

    out = {"case_id": cid, "category": case["category"], "outcomes": res,
           "air_profile_admissibility": case.get("air_profile_admissibility", "NOT_EVALUATED_HERE"),
           "assertions": {}}
    for prim, want in exp.items():
        got = res.get(prim)
        out["assertions"][prim] = run.check(cid, prim, want, got)
    out["assertions"]["sar_expected_behavior"] = run.check(cid, "sar_expected_behavior", case["sar_expected_behavior"], label)
    return out


def run_signature_case(run: Run, vectors: dict, case: dict, actuals: dict) -> dict:
    cid = case["case_id"]
    sc = case["signature_check"]
    for k in sc:
        if k not in KNOWN_SIG_KEYS:
            run.failures.append(f"{cid}: unknown signature_check key {k!r}")
    out = {"case_id": cid, "category": case["category"], "outcomes": {}, "assertions": {}}
    want = sc["expected_verify"]
    if "pubkey_b64url" in sc:
        pre = bytes.fromhex(sc["preimage_hex"])
        sig = unb64u(sc["signature_b64url"])
        der = sc.get("preimage_derivation")
        if der:
            base = actuals.get(der["from_case"])
            if base is None:
                run.failures.append(f"{cid}: derivation source {der['from_case']} has no canonical bytes")
            else:
                derived = hashlib.sha256(base).digest() if der["transform"] == "sha256_of_canonical_bytes" else base
                out["assertions"]["preimage_derivation"] = run.check(cid, "preimage derivation", sc["preimage_hex"], derived.hex())
        try:
            ok = crypto.verify_digest_signature(unb64u(sc["pubkey_b64url"]), pre, sig)
            got = "ESTABLISHED" if ok else "REJECTED"
        except Exception as exc:  # noqa: BLE001
            got = f"ERROR:{type(exc).__name__}"
        out["outcomes"]["signature_verification"] = got
        out["outcomes"]["signed_preimage"] = sc["signed_preimage"]
        out["outcomes"]["preimage_sha256_hex"] = hashlib.sha256(pre).hexdigest()
        out["assertions"]["expected_verify"] = run.check(cid, "expected_verify", want, got)
        if sc.get("deterministic_resign_check"):
            label = vectors["test_key_labels"]["test_key_1"]
            sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())
            pk = b64u(sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
            out["assertions"]["test_key_matches_label"] = run.check(cid, "pubkey from seed label", sc["pubkey_b64url"], pk)
            out["assertions"]["deterministic_resign"] = run.check(cid, "re-sign equals pinned signature", sc["signature_b64url"], b64u(sk.sign(pre)))
    pv = sc.get("portable_verifier_check")
    if pv:
        art = dict(pointer(resolve_artifact(vectors, pv["artifact_id"]), pv["json_pointer"]))
        m = pv.get("mutate", {})
        art.update(m.get("set", {}))
        for d in m.get("delete", []):
            art.pop(d, None)
        meta = next(a for a in vectors["reused_artifacts"] if a["artifact_id"] == pv["artifact_id"])
        doc = json.loads((HERE / meta["path"]).read_text())
        reg = crypto.parse_key_registry({"keys": [{"kid": pv["kid"], "kty": "OKP", "crv": "Ed25519", "x": doc["public_key_base64url"]}]})
        got = portable.verify_signature(art, reg)
        out["outcomes"]["portable_reader_verify_signature"] = got
        out["assertions"]["portable_verifier_check"] = run.check(cid, "portable reader", pv["expected"], got)
        if "pubkey_b64url" not in sc:
            out["assertions"]["expected_verify"] = run.check(cid, "expected_verify", want, "ESTABLISHED" if got == "VALID" else "REJECTED")
            out["outcomes"]["signature_verification"] = "ESTABLISHED" if got == "VALID" else "REJECTED"
    return out


def run_corpus(vectors_path: Path) -> tuple[Run, dict]:
    run = Run()
    vectors = json.loads(vectors_path.read_text())
    if vectors.get("schema") != SCHEMA:
        run.failures.append(f"schema {vectors.get('schema')!r} != {SCHEMA!r}")
    if vectors.get("claim_ceiling") != CEILING:
        run.failures.append(f"claim_ceiling {vectors.get('claim_ceiling')!r} != {CEILING!r}")
    cases = vectors.get("cases", [])
    if not cases or vectors.get("case_count") != len(cases):
        run.failures.append(f"case_count {vectors.get('case_count')!r} != {len(cases)}")
    ids = [c.get("case_id") for c in cases]
    if len(ids) != len(set(ids)):
        run.failures.append("duplicate case_id in corpus")
    for art in vectors.get("reused_artifacts", []):
        p = HERE / art["path"]
        run.check(art["artifact_id"], "reused artifact file sha256", art["file_sha256"],
                  hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else "MISSING")
    actuals: dict = {}
    rows = []
    # input cases first so signature derivations can resolve them
    for case in cases:
        if "expect" in case:
            rows.append(run_input_case(run, vectors, case, actuals))
    for case in cases:
        if "signature_check" in case:
            rows.append(run_signature_case(run, vectors, case, actuals))
        elif "expect" not in case:
            run.failures.append(f"{case.get('case_id')}: case declares neither expect nor signature_check")
    order = {c["case_id"]: i for i, c in enumerate(cases)}
    rows.sort(key=lambda r: order.get(r["case_id"], 1 << 30))
    result = {
        "schema": "sar-primitive-vector-results/v1",
        "claim_ceiling": CEILING,
        "vectors_file_sha256": hashlib.sha256(vectors_path.read_bytes()).hexdigest(),
        "cases_run": len(rows),
        "failures": run.failures,
        "overall": "ALL_DECLARED_EXPECTATIONS_MATCHED" if not run.failures else "MISMATCH",
        "results": rows,
    }
    return run, result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vectors", default=str(HERE / "vectors.json"))
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    try:
        run, result = run_corpus(Path(args.vectors))
    except Exception as exc:  # noqa: BLE001 - fail closed on anything unexpected
        print(f"RUNNER ERROR (fail closed): {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2, ensure_ascii=True) + "\n")
    for f in run.failures:
        print("FAIL:", f, file=sys.stderr)
    print(f"cases_run={result['cases_run']} failures={len(run.failures)} overall={result['overall']}")
    return 1 if run.failures else 0


if __name__ == "__main__":
    sys.exit(main())
