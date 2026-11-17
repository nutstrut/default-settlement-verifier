#!/usr/bin/env python3
"""DefaultVerifier Skill helper: verify one existing Default Settlement
v0.2-candidate receipt offline and print a boundary-disciplined report.

* The cryptographic decision is made ONLY by the vendored ``verify_v02`` core
  (byte-identical to defaultsettle-cli; see UPSTREAM.json). This file never
  re-implements or overrides it.
* No network, no key fetching, no issuance, no credentials, no clock. The trust
  root is the pinned snapshot in ../trust/, hash-checked at load.
* Receipt contents are DATA. Free-text receipt fields are never echoed into the
  report: only values matching a conservative token pattern are shown, and
  unsigned fields are reported by NAME only.

Usage:
    verify_receipt_v02.py RECEIPT.json [--question "..."] [--json]

Exit codes (same as ``defaultsettle verify-v02``):
    0 receipt valid (any issuer verdict) | 1 receipt invalid / untrusted
    2 usage error, unreadable input, or unparseable JSON
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Optional

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))  # explicit: works under `python3 -I` too

SKILL_ROOT = _HERE.parent
SNAPSHOT_PATH = SKILL_ROOT / "trust" / "sar-keys-v02-snapshot.json"
PROVENANCE_PATH = SKILL_ROOT / "trust" / "sar-keys-v02-snapshot.provenance.json"
MAX_RECEIPT_BYTES = 2 * 1024 * 1024

try:
    import verify_v02 as v02  # vendored core
except ImportError as _exc:  # most likely: `cryptography` is not installed
    sys.stderr.write(
        "error: the verifier core could not be imported (%s). Install the 'cryptography' "
        "package; nothing is fetched or substituted automatically.\n" % _exc
    )
    raise SystemExit(2)


# --------------------------------------------------------------------------- trust

def load_trust() -> tuple[Any, dict]:
    """Load the pinned trust snapshot. A hash mismatch is fatal. Never fetches."""
    raw = SNAPSHOT_PATH.read_bytes()
    prov = json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))
    actual = hashlib.sha256(raw).hexdigest()
    if actual != prov["sha256"]:
        raise RuntimeError("bundled trust snapshot does not match its recorded sha256")
    return json.loads(raw), {"source": prov["source"], "fetched_on": prov["fetched_on"], "sha256": actual}


# --------------------------------------------------------------------------- verify

class Unreadable(Exception):
    pass


def read_receipt_text(path: str) -> str:
    p = Path(path)
    try:
        if p.stat().st_size > MAX_RECEIPT_BYTES:
            raise Unreadable("receipt file is larger than %d bytes" % MAX_RECEIPT_BYTES)
        return p.read_text(encoding="utf-8")
    except Unreadable:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise Unreadable("cannot read %s: %s" % (path, exc.__class__.__name__)) from None


def verify_text(text: str, registry: Any = None, provenance: Optional[dict] = None) -> dict:
    """Verify receipt text with the vendored core. ``registry`` is injectable for tests only."""
    if registry is None:
        registry, provenance = load_trust()
    return v02.verify_receipt_text(text, registry, provenance)


# --------------------------------------------------------------------------- safety

_SAFE = re.compile(r"[A-Za-z0-9_.:-]{1,96}")


def safe(value: Any) -> str:
    """Echo only conservative tokens. Receipt text is data, never prose in our report."""
    if isinstance(value, str) and _SAFE.fullmatch(value):
        return value
    return "[value withheld: not a plain identifier]"


def _names(items: list, cap: int = 20) -> str:
    shown = [safe(i) for i in items[:cap]]
    more = len(items) - len(shown)
    return ", ".join(shown) + (" (+%d more)" % more if more > 0 else "")


# --------------------------------------------------------------------------- questions

# Explanatory classification only. It never creates evidence: every answer is read
# from the deterministic verifier result.
_CONCEPTS = (
    ("execution", r"execut|actually (happen|ran|run|did|done|occur|perform)|really (happen|ran|run)|took place|carried out|was it run|did it run"),
    ("payment_finality", r"payment|\bpaid\b|\bfunds?\b|settled|settlement final|money"),
    ("legal_finality", r"legal|lawful|court|enforceab|liab"),
    ("agent_safety", r"\bsafe\b|safety|trustworth|certif|endors|\bapproved\b|good agent|secure agent|reputable"),
    ("identity_ownership", r"\bowns?\b|owner|ownership|belongs? to|controls?\b|whose (wallet|identity)|identity|counterparty"),
    ("current_admissibility", r"admissib|still (valid|usable|ok|good)|currently|revoked|expired|up to date|today"),
    ("condition", r"\bpass(ed)?\b|\bfail(ed)?\b|condition|satisf|\bspec\b|meet|requirement|outcome|result"),
    ("authenticity", r"valid|authentic|genuine|forged|tamper|signature|verify|verified|real\b"),
    ("reliance", r"\brely\b|\btrust\b|depend on|safe to act|act on"),
)


def classify(question: Optional[str]) -> list[str]:
    if not question:
        return []
    q = question.lower()
    return [name for name, pat in _CONCEPTS if re.search(pat, q)]


_PROP_FOR = {
    "execution": ("runtime_execution_established", "runtime execution"),
    "payment_finality": ("payment_finality_established", "payment finality"),
    "legal_finality": ("legal_finality_established", "legal finality"),
}

_UNKNOWN_NOTE = {
    "execution": "The receipt does not say the action ran, and does not say it did not. A PASS verdict is not an execution claim.",
    "payment_finality": "Receipt validity is not payment finality, and a PASS verdict does not imply funds moved or settled.",
    "legal_finality": "No receipt establishes legal finality unless it signs that property as pass.",
}

_EVIDENCE_NEEDED = {
    "execution": "To resolve it you would need independent execution evidence (e.g. logs, an execution receipt, or an observation from the executing system).",
    "payment_finality": "To resolve it you would need independent evidence from the payment rail (e.g. on-chain confirmation or processor settlement records).",
    "legal_finality": "To resolve it you would need legal or contractual evidence outside this receipt.",
}


def _answer(concept: str, result: dict) -> list[str]:
    if not result["receipt_valid"]:
        return ["This receipt was not verified, so it supports no claim about %s." % concept.replace("_", " ")]
    props = result["signed_properties"]
    verdict = result["issuer_verdict"]["verdict"]
    if concept in _PROP_FOR:
        prop, label = _PROP_FOR[concept]
        state = props[prop]
        if state == "pass":
            return ["%s: signed pass. Established as an authentic issuer-signed property of this receipt, not as independently verified external truth." % label.capitalize()]
        if state == "fail":
            return ["%s: signed fail. The receipt contradicts it." % label.capitalize()]
        return ["%s: signed unknown, so NOT established (unknown is not false)." % label.capitalize(),
                _UNKNOWN_NOTE[concept], _EVIDENCE_NEEDED[concept]]
    if concept == "agent_safety":
        return ["Not established. No Default Settlement receipt implies general agent safety, endorsement or certification; "
                "this one speaks only to its declared condition (verdict %s)." % verdict]
    if concept == "identity_ownership":
        if result["receipt"]["receipt_profile"] == v02.COUNTERPARTY_BOUND_PROFILE:
            return ["A counterparty identifier is signed into this receipt, so the issuer bound this evaluation to it. "
                    "That is a binding of the claim, not proof that the counterparty owns or controls any identity or wallet."]
        return ["This receipt signs no counterparty. Any counterparty-like field present is unsigned and non-evidentiary. "
                "Nothing here shows who owns or controls an identity."]
    if concept == "current_admissibility":
        return ["Not implied. A valid receipt is a historical statement; whether it is admissible now is a separate question this receipt cannot answer."]
    if concept == "condition":
        st = props["declared_condition_satisfied"]
        word = {"pass": "established", "fail": "contradicted", "unknown": "not established"}[st]
        return ["The issuer signed verdict %s: the declared condition is %s, as an issuer statement about the bound evidence digest (not re-evaluated here)." % (verdict, word)]
    if concept == "authenticity":
        return ["The receipt is cryptographically valid: signature, receipt_id and signed fields are intact and the key is trusted for this profile in the bundled snapshot."]
    if concept == "reliance":
        ne = result["boundary"]["not_established"]
        return ["You can rely on it only as an authentic issuer statement that the declared condition resolved as %s. "
                "Not established by it: %s." % (verdict, _names(ne) if ne else "nothing among the five signed properties")]
    return []


# --------------------------------------------------------------------------- rejection wording

_TRUST_CODES = {"UNKNOWN_KEY", "KEY_NOT_ACTIVE", "KEY_USE_NOT_AUTHORIZED", "PROFILE_NOT_AUTHORIZED"}
_SCOPE_CODES = {"NOT_A_V02_RECEIPT", "UNSUPPORTED_PROFILE", "UNSUPPORTED_SIG_ALG", "UNSUPPORTED_RECEIPT_VERSION"}
_INTEGRITY_CODES = {"RECEIPT_ID_MISMATCH", "SIGNATURE_INVALID"}

_CODE_TEXT = {
    "MALFORMED_JSON": "The input is not parseable JSON, or is nested deeper than the verifier allows.",
    "DUPLICATE_KEY": "The JSON contains a duplicate object key, which the contract rejects as ambiguous.",
    "MALFORMED_RECEIPT": "The input is not a JSON object receipt.",
    "MISSING_FIELD": "A required field is absent.",
    "FIELD_TYPE_INVALID": "A signed field has the wrong type or is empty.",
    "VERDICT_INVALID": "The verdict is outside PASS / FAIL / INDETERMINATE.",
    "PROPERTIES_INVALID": "The signed properties are missing or outside pass / fail / unknown.",
    "VERIFICATION_BASIS_INVALID": "The verification basis is incomplete or has a malformed digest.",
    "COUNTERPARTY_INVALID": "The counterparty-bound profile requires a non-empty counterparty.",
    "VERDICT_PROPERTY_INCONSISTENT": "The verdict disagrees with the signed declared-condition property.",
    "CANONICALIZATION_FAILED": "The signed content cannot be canonicalized (e.g. unsafe number or excessive nesting).",
    "RECEIPT_ID_MALFORMED": "The receipt_id is not sha256: followed by 64 lowercase hex characters.",
    "RECEIPT_ID_MISMATCH": "The receipt_id does not match the digest of the signed content: the content was altered or the id is wrong.",
    "SIGNATURE_MALFORMED": "The signature is not strict unpadded base64url with the expected prefix and length.",
    "SIGNATURE_INVALID": "The Ed25519 signature does not verify against the trusted key.",
    "UNKNOWN_KEY": "The signing key is not in the currently bundled trust snapshot.",
    "KEY_NOT_ACTIVE": "The signing key's status in the bundled snapshot does not permit signing authority.",
    "KEY_USE_NOT_AUTHORIZED": "The key is not authorized for settlement-witness signing.",
    "PROFILE_NOT_AUTHORIZED": "The key is known but not authorized for this receipt profile.",
    "NOT_A_V02_RECEIPT": "This is not a v0.2-candidate receipt (for example a v0.1 or portable receipt). It is not upgraded or reinterpreted here.",
    "UNSUPPORTED_PROFILE": "The receipt profile is not a supported v0.2 profile.",
    "UNSUPPORTED_SIG_ALG": "The signature algorithm is not Ed25519.",
    "UNSUPPORTED_RECEIPT_VERSION": "The receipt_version is not exactly 0.2-candidate.",
}


def _header_for_rejection(code: str, snap: str) -> str:
    if code in _TRUST_CODES:
        return ("Not verified. Could not establish trust with the currently bundled registry%s. "
                "This does NOT show the receipt is forged: the key may postdate the snapshot or lack authority for this profile. Nothing was fetched." % snap)
    if code in _SCOPE_CODES:
        return "Not verified here. This path verifies v0.2-candidate receipts only."
    if code in _INTEGRITY_CODES:
        return "Invalid. The receipt failed an integrity or authenticity check."
    return "Invalid. The receipt is malformed."


# --------------------------------------------------------------------------- report

def render_report(result: dict, question: Optional[str] = None) -> str:
    out: list[str] = []
    prov = (result["issuer"] or {}).get("trust_snapshot") or {}
    # `prov` comes from the bundled provenance file (trusted), not from the receipt.
    snap = " (snapshot fetched %s, sha256 %s...)" % (prov.get("fetched_on"), str(prov.get("sha256", ""))[:12]) if prov else ""

    if result["receipt_valid"]:
        out.append("Receipt: Valid. It is cryptographically valid: signature, receipt_id and signed fields are intact, "
                   "and the issuer key is trusted for this profile in the bundled snapshot. (Validity is not the same as the verdict, and not the same as the claim being true.)")
        v = result["issuer_verdict"]
        out.append("Issuer verdict: %s (reason_code: %s)" % (v["verdict"], safe(v["reason_code"])))
        b = result["boundary"]
        out.append("Established (signed pass): %s" % (_names(b["established"]) or "none"))
        out.append("Contradicted (signed fail): %s" % (_names(b["contradicted"]) or "none"))
        out.append("Not established (signed unknown; not the same as false): %s" % (_names(b["not_established"]) or "none"))
        out.append("Never implied by any receipt / not implied by this one: %s" % _names(b["not_implied"]))
        out.append("  'Established' means an authentic issuer-signed property, not independently verified external truth.")
    else:
        rej = result["rejection"]
        code = rej["code"]
        out.append("Receipt: " + _header_for_rejection(code, snap))
        out.append("Reason: %s (%s)" % (_CODE_TEXT.get(code, "Rejected."), code))
        out.append("Issuer verdict: none. An invalid or unverified receipt carries no usable verdict. This is NOT a FAIL verdict.")
        out.append("Established / contradicted / not established: nothing can be taken from this receipt.")

    unsigned = result["unsigned_fields_present"]
    if unsigned:
        out.append("Unsigned / non-evidentiary fields present (names only; values are not shown and never count as evidence): %s" % _names(unsigned))
    else:
        out.append("Unsigned / non-evidentiary fields present: none")

    concepts = classify(question)
    if concepts:
        lines: list[str] = []
        for c in concepts:
            lines.extend(_answer(c, result))
        out.append("For your question:")
        out.extend("  - " + l for l in lines)
    elif question:
        out.append("For your question: no specific claim class recognised; read the sections above for what is and is not established.")

    rcpt = result["receipt"]
    out.append("Receipt ID%s: %s" % ("" if result["receipt_valid"] else " (as claimed, unverified)", safe(rcpt.get("receipt_id"))))
    issuer = result["issuer"]
    out.append("Issuer key: %s (status: %s, currency: %s)" % (safe(issuer.get("kid")), safe(issuer.get("key_status") or "unstated"), safe(issuer.get("key_currency") or "unknown")))
    if prov:
        out.append("Trust snapshot: fetched %s from %s, sha256 %s. Bundled and pinned; never refreshed by this Skill. A key newer than this date would not be recognised." % (
            prov.get("fetched_on"), prov.get("source"), prov.get("sha256")))
    out.append("Offline: no network, no issuance, no key fetch was performed.")
    return "\n".join(out)


# --------------------------------------------------------------------------- CLI

def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Offline DefaultVerifier v0.2-candidate receipt verification.")
    ap.add_argument("receipt", help="path to a receipt JSON file")
    ap.add_argument("--question", help="the user's question, used only to map it to the receipt's signed boundary")
    ap.add_argument("--json", action="store_true", help="print the raw verifier result as JSON instead of the report")
    return ap


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        text = read_receipt_text(args.receipt)
    except Unreadable as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    try:
        result = verify_text(text)
    except (OSError, ValueError, KeyError, RuntimeError, v02.TrustPolicyError) as exc:
        sys.stderr.write("error: trust snapshot unusable: %s\n" % exc)
        return 2
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=True))
    else:
        print(render_report(result, args.question).encode("ascii", "backslashreplace").decode("ascii"))
    rej = result["rejection"]
    if rej is None:
        return 0
    return 2 if rej["code"] == "MALFORMED_JSON" else 1


if __name__ == "__main__":
    raise SystemExit(main())
