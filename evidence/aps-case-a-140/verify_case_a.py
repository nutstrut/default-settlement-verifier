#!/usr/bin/env python3
"""Independent AuthorityDelegationV1 chain verifier for APS Case A (#140).

Written from draft-pidlisnyi-aps-04 Sections 3.4, 4.1, 4.2, 4.3, 4.5, 4.6, 8.2.1.
Does NOT use the producer verify.mjs, the APS SDK, or any producer code.
Only third-party dependency: `cryptography` (generic Ed25519).

Sequencing: structural inputs are loaded with every `expected` member stripped;
both cases are evaluated and the observed results are frozen (hashed) BEFORE the
`expected` members are read from the file for comparison.

Usage: repro.py <path-to-case-a-neutral-vector.CANDIDATE.json>
"""
import copy, hashlib, json, re, sys
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

ID_LABEL = b"APS-AUTHORITY-DELEGATION-ID-V1"
SIG_LABEL = b"APS-AUTHORITY-DELEGATION-SIGNATURE-V1"
TOP_KEYS = {"record_type", "version", "delegation_id", "parent_delegation_id", "issuer", "subject",
            "verification_method", "issued_at", "nonce", "authority", "signature"}
FACETS = ["scope", "spend", "depth", "time", "reputation", "values", "reversibility"]
PROFILES = {"scope": "aps-hierarchical-v1", "reputation": "aps-score-0-100-v1",
            "values": "aps-values-identifiers-v1", "reversibility": "aps-tci-v1"}
REV_ORDER = ["tentative", "compensable", "irreversible"]
TS_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z$")
AMT_RE = re.compile(r"^(0|[1-9][0-9]*)$")
HEX_RE = lambda n: re.compile(r"^[0-9a-f]{%d}$" % n)
SEG_RE = re.compile(r"^[\x21-\x7e]+$")


# ---------- RFC 8785 JCS (subset sufficient for I-JSON with strings, ints, bool, null) ----------
def jcs(v):
    if v is None: return "null"
    if v is True: return "true"
    if v is False: return "false"
    if isinstance(v, int): return str(v)
    if isinstance(v, float): raise ValueError("float not used in this profile")
    if isinstance(v, str): return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list): return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))  # UTF-16 code unit order
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k]) for k in keys) + "}"
    raise TypeError(type(v))


def delegation_id_of(rec):
    body = {k: x for k, x in rec.items() if k not in ("delegation_id", "signature")}
    return "sha256:" + hashlib.sha256(ID_LABEL + b"\x00" + jcs(body).encode("utf-8")).hexdigest()


def sig_preimage(rec):
    body = {k: x for k, x in rec.items() if k != "signature"}
    return SIG_LABEL + b"\x00" + jcs(body).encode("utf-8")


def ts(s):
    m = TS_RE.match(s) if isinstance(s, str) else None
    if not m or int(m.group(6)) > 59:
        return None
    try:
        y, mo, d, h, mi, se, ms = map(int, m.groups())
        return datetime(y, mo, d, h, mi, se, ms * 1000, tzinfo=timezone.utc)
    except ValueError:
        return None


def is_int(x): return isinstance(x, int) and not isinstance(x, bool)


# ---------- grant coverage (4.2 Scope) ----------
def grant_ok(g):
    if not isinstance(g, str): return False
    if g == "*": return True
    segs = g.split(":")
    return all(SEG_RE.match(s) and ("*" not in s or (s == "*" and i == len(segs) - 1 and i > 0))
               for i, s in enumerate(segs))


def covers(p, c):
    if p == "*" or p == c: return True
    if p.endswith(":*"):
        pre = p[:-2]
        return c == pre or c.startswith(pre + ":")
    return False


# ---------- phase 1: closed schema and canonical values ----------
def check_schema(r):
    """Returns (state, reasons-list). state in {None, 'invalid', 'unsupported'}."""
    if not isinstance(r, dict): return "invalid", ["SCHEMA"]
    if r.get("record_type") != "aps:authority-delegation:v1" or r.get("version") != "1.0":
        return "unsupported", ["UNSUPPORTED_RECORD_TYPE_OR_VERSION"]
    bad = []
    if set(r) != TOP_KEYS: bad.append("top-level keys not closed set")
    if not (isinstance(r.get("delegation_id"), str) and re.match(r"^sha256:[0-9a-f]{64}$", r["delegation_id"])): bad.append("delegation_id format")
    p = r.get("parent_delegation_id")
    if not (p is None or (isinstance(p, str) and re.match(r"^sha256:[0-9a-f]{64}$", p))): bad.append("parent_delegation_id format")
    for k in ("issuer", "subject", "verification_method"):
        if not (isinstance(r.get(k), str) and r[k]): bad.append(k)
    if ts(r.get("issued_at")) is None: bad.append("issued_at")
    if not (isinstance(r.get("nonce"), str) and HEX_RE(32).match(r["nonce"])): bad.append("nonce")
    if not (isinstance(r.get("signature"), str) and HEX_RE(128).match(r["signature"])): bad.append("signature format")
    a = r.get("authority")
    if not isinstance(a, dict) or list(sorted(a)) != sorted(FACETS):
        bad.append("authority must contain exactly seven facets"); return "invalid", bad
    prof_unsup = False
    for f, pid in PROFILES.items():
        fa = a[f]
        if not isinstance(fa, dict) or "profile" not in fa: bad.append(f + " shape"); continue
        if fa["profile"] != pid: prof_unsup = True
    if bad: return "invalid", bad
    if prof_unsup: return "unsupported", ["UNSUPPORTED_PROFILE"]
    sc, sp, dp, tm, rp, vl, rv = (a[f] for f in FACETS)
    if set(sc) != {"profile", "grants"} or not isinstance(sc["grants"], list) or not sc["grants"] \
            or not all(grant_ok(g) for g in sc["grants"]): bad.append("scope")
    else:
        g = sc["grants"]
        if g != sorted(set(g), key=lambda s: s.encode()): bad.append("scope grants not sorted/unique")
        for i, x in enumerate(g):
            if any(i != j and covers(y, x) for j, y in enumerate(g)): bad.append("scope grants redundant")
    if sp.get("mode") == "unbounded":
        if set(sp) != {"mode"}: bad.append("spend unbounded shape")
    elif sp.get("mode") == "bounded":
        if set(sp) != {"mode", "unit", "per_action", "cumulative"} or not isinstance(sp["unit"], str) \
                or not all(isinstance(sp[k], str) and AMT_RE.match(sp[k]) and int(sp[k]) <= 9223372036854775807
                           for k in ("per_action", "cumulative")):
            bad.append("spend bounded shape/amounts")
        elif int(sp["per_action"]) > int(sp["cumulative"]): bad.append("per_action > cumulative")
    else: bad.append("spend mode")
    if set(dp) != {"remaining"} or not is_int(dp["remaining"]) or not 0 <= dp["remaining"] <= 255: bad.append("depth")
    if set(tm) != {"not_before", "not_after"} or ts(tm["not_before"]) is None or ts(tm["not_after"]) is None \
            or not ts(tm["not_before"]) < ts(tm["not_after"]): bad.append("time")
    if set(rp) != {"profile", "ceiling"} or not is_int(rp["ceiling"]) or not 0 <= rp["ceiling"] <= 100: bad.append("reputation")
    if set(vl) != {"profile", "required"} or not isinstance(vl["required"], list) \
            or not all(isinstance(x, str) for x in vl["required"]) \
            or vl["required"] != sorted(set(vl["required"]), key=lambda s: s.encode()): bad.append("values")
    if set(rv) != {"profile", "ceiling"} or rv["ceiling"] not in REV_ORDER: bad.append("reversibility")
    return ("invalid", bad) if bad else (None, [])


# ---------- phase 9: attenuation (4.2) ----------
def attenuation(parent, child):
    pa, ca = parent["authority"], child["authority"]
    res = {}
    res["scope"] = all(any(covers(p, c) for p in pa["scope"]["grants"]) for c in ca["scope"]["grants"])
    ps, cs = pa["spend"], ca["spend"]
    if ps["mode"] == "bounded":
        res["spend"] = cs["mode"] == "bounded" and cs["unit"] == ps["unit"] \
            and int(cs["per_action"]) <= int(ps["per_action"]) and int(cs["cumulative"]) <= int(ps["cumulative"])
    else:
        res["spend"] = True  # bounded or unbounded child under unbounded parent
    res["depth"] = pa["depth"]["remaining"] > 0 and ca["depth"]["remaining"] <= pa["depth"]["remaining"] - 1
    pt, ct = pa["time"], ca["time"]
    res["time_containment"] = ts(pt["not_before"]) <= ts(ct["not_before"]) and ts(ct["not_after"]) <= ts(pt["not_after"])
    res["reputation"] = ca["reputation"]["ceiling"] <= pa["reputation"]["ceiling"]
    res["values"] = set(pa["values"]["required"]) <= set(ca["values"]["required"])
    res["reversibility"] = REV_ORDER.index(ca["reversibility"]["ceiling"]) <= REV_ORDER.index(pa["reversibility"]["ceiling"])
    return res


def verify_chain(chain, trust, revoked_ids, evaluated_at):
    """Phase-major evaluation per 4.3. Returns dict with state/valid/failure_codes/failure_index + per-phase detail."""
    at = ts(evaluated_at)
    out = {"phases": {}}
    keys = trust["verification_keys"]
    n = len(chain)

    def fail(state, code, idx, phase):
        out.update(state=state, valid=False, failure_codes=[code], failure_index=idx, failed_phase=phase)
        return out

    # P1 closed schema / canonical values
    detail = []
    first = None
    for i, r in enumerate(chain):
        st, why = check_schema(r)
        detail.append({"index": i, "ok": st is None, "detail": why})
        if st and first is None: first = (st, i, why)
    out["phases"]["1_schema"] = detail
    if first: return fail(first[0], "SCHEMA" if first[0] == "invalid" else first[2][0], first[1], "1_schema")

    # P2 delegation_id
    detail, first = [], None
    for i, r in enumerate(chain):
        calc = delegation_id_of(r)
        ok = calc == r["delegation_id"]
        detail.append({"index": i, "ok": ok, "recomputed": calc, "claimed": r["delegation_id"]})
        if not ok and first is None: first = i
    out["phases"]["2_delegation_id"] = detail
    if first is not None: return fail("invalid", "DELEGATION_ID_MISMATCH", first, "2_delegation_id")

    # P3 key resolution + signature
    detail, first = [], None
    for i, r in enumerate(chain):
        vm = r["verification_method"]
        d = {"index": i, "verification_method": vm}
        if not vm.startswith(r["issuer"] + "#"):
            d.update(ok=False, reason="verification_method not bound to issuer")
        elif vm not in keys:
            d.update(ok=False, reason="KEY_NOT_FOUND", state="indeterminate")
        else:
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys[vm])).verify(
                    bytes.fromhex(r["signature"]), sig_preimage(r))
                d.update(ok=True)
            except InvalidSignature:
                d.update(ok=False, reason="SIGNATURE_INVALID")
            except ValueError:
                d.update(ok=False, reason="KEY_MATERIAL_MALFORMED", state="indeterminate")
        detail.append(d)
        if not d["ok"] and first is None: first = d
    out["phases"]["3_key_and_signature"] = detail
    if first: return fail(first.get("state", "invalid"), first["reason"], first["index"], "3_key_and_signature")

    # P4 duplicates / cycle
    ids = [r["delegation_id"] for r in chain]
    out["phases"]["4_duplicates"] = {"ok": len(set(ids)) == len(ids)}
    if len(set(ids)) != len(ids):
        return fail("invalid", "DUPLICATE_ID", [i for i, x in enumerate(ids) if ids.index(x) != i][0], "4_duplicates")

    # P5 root trust
    root = chain[0]
    ok = any(t["issuer"] == root["issuer"] and t["subject"] == root["subject"] for t in trust["roots"])
    out["phases"]["5_root_trust"] = {"ok": ok, "root_issuer": root["issuer"], "root_subject": root["subject"]}
    if not ok: return fail("invalid", "ROOT_NOT_TRUSTED", 0, "5_root_trust")

    # P6 parent linkage
    detail, first = [], None
    for i, r in enumerate(chain):
        ok = (r["parent_delegation_id"] is None) if i == 0 else (r["parent_delegation_id"] == chain[i - 1]["delegation_id"])
        detail.append({"index": i, "ok": ok})
        if not ok and first is None: first = i
    out["phases"]["6_parent_link"] = detail
    if first is not None: return fail("invalid", "BROKEN_PARENT_LINK", first, "6_parent_link")

    # P7 issuer-to-subject continuity
    detail, first = [], None
    for i in range(1, n):
        ok = chain[i]["issuer"] == chain[i - 1]["subject"]
        detail.append({"index": i, "ok": ok})
        if not ok and first is None: first = i
    out["phases"]["7_issuer_subject_continuity"] = detail
    if first is not None: return fail("invalid", "ISSUER_DISCONTINUITY", first, "7_issuer_subject_continuity")

    # P8 child issuance time (non-root): not_before >= issued_at; issued while parent valid
    detail, first = [], None
    for i in range(1, n):
        c, p = chain[i], chain[i - 1]
        iss = ts(c["issued_at"])
        nb_ok = ts(c["authority"]["time"]["not_before"]) >= iss
        par_ok = ts(p["authority"]["time"]["not_before"]) <= iss < ts(p["authority"]["time"]["not_after"])
        detail.append({"index": i, "not_before_not_before_issued_at": nb_ok, "issued_while_parent_valid": par_ok})
        if not (nb_ok and par_ok) and first is None: first = i
    out["phases"]["8_child_issuance_time"] = detail
    if first is not None: return fail("invalid", "CHILD_ISSUANCE_TIME", first, "8_child_issuance_time")

    # P9 seven facet comparisons
    detail, first = [], None
    for i in range(1, n):
        res = attenuation(chain[i - 1], chain[i])
        detail.append({"index": i, **res})
        if not all(res.values()) and first is None: first = i
    out["phases"]["9_attenuation"] = detail
    if first is not None: return fail("invalid", "ATTENUATION_VIOLATION", first, "9_attenuation")

    # P10 current validity at evaluated_at, half-open [not_before, not_after)
    detail, first = [], None
    for i, r in enumerate(chain):
        t = r["authority"]["time"]
        ok = ts(t["not_before"]) <= at < ts(t["not_after"])
        detail.append({"index": i, "ok": ok})
        if not ok and first is None: first = i
    out["phases"]["10_current_validity"] = detail
    if first is not None: return fail("invalid", "NOT_CURRENTLY_VALID", first, "10_current_validity")

    # P11 revocation state for every member (revocation state taken as established/fresh; see report)
    detail, first = [], None
    for i, r in enumerate(chain):
        rev = r["delegation_id"] in revoked_ids
        detail.append({"index": i, "revoked": rev})
        if rev and first is None: first = i
    out["phases"]["11_revocation"] = detail
    if first is not None: return fail("invalid", "REVOKED", first, "11_revocation")

    out.update(state="valid", valid=True, failure_codes=[])
    return out


def brief(r):
    d = {"state": r["state"], "valid": r["valid"], "failure_codes": r["failure_codes"]}
    if "failure_index" in r: d["failure_index"] = r["failure_index"]
    return d


def negative_controls(v):
    base = v["chain"]; trust = v["trust_anchors"]; at = v["evaluated_at"]
    c0, c1 = base[0]["delegation_id"], base[1]["delegation_id"]
    out = {}
    def run(name, chain, revoked=(), when=at):
        out[name] = brief(verify_chain(chain, trust, set(revoked), when))
    # (a) flip one signature byte on child
    ch = copy.deepcopy(base); s = bytearray.fromhex(ch[1]["signature"]); s[0] ^= 1; ch[1]["signature"] = s.hex()
    run("mutate_signature_byte_child", ch)
    # (b) change an id-relevant field (child nonce) leaving delegation_id as-is
    ch = copy.deepcopy(base); ch[1]["nonce"] = "00000000000000000000000000000003"
    run("mutate_id_relevant_field_child_nonce", ch)
    # (c) break parent link (re-id + re-sign is impossible w/o private key, so id check fires first -> also test with consistent id for phase-6 isolation below)
    ch = copy.deepcopy(base); ch[1]["parent_delegation_id"] = "sha256:" + "0" * 64
    run("break_parent_link_child (unresigned)", ch)
    # (d) time window
    run("evaluated_after_child_not_after_2026-12-15", base, when="2026-12-15T00:00:00.000Z")
    run("evaluated_before_child_not_before_2026-01-15", base, when="2026-01-15T00:00:00.000Z")
    run("evaluated_exactly_at_child_not_after_2026-12-01 (half-open)", base, when="2026-12-01T00:00:00.000Z")
    # (e) revoke child, not ancestor
    run("revoke_child_only", base, revoked=[c1])
    run("revoke_both", base, revoked=[c0, c1])
    # (f) wrong trust root
    t2 = copy.deepcopy(trust); t2["roots"][0]["issuer"] = "aps:agent:someone-else"
    out["untrusted_root"] = brief(verify_chain(base, t2, set(), at))
    # (g) key swap: child verified against root key
    t3 = copy.deepcopy(trust); t3["verification_keys"]["aps:agent:test-parent-agent#key-1"] = trust["verification_keys"]["aps:agent:test-root-principal#key-1"]
    out["wrong_key_for_parent"] = brief(verify_chain(base, t3, set(), at))
    return out



def resigned_controls(v):
    """Phase-isolating controls using LOCALLY GENERATED throwaway keys (not the vector's keys)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as S
    base = v["chain"]; at = v["evaluated_at"]
    ka, kb = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    pub = lambda k: k.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw).hex()
    r0, r1 = base[0]["issuer"], base[1]["issuer"]
    trust = {"roots": [{"issuer": r0, "subject": r1}],
             "verification_keys": {base[0]["verification_method"]: pub(ka), base[1]["verification_method"]: pub(kb)}}
    def seal(rec, key):
        rec = {k: x for k, x in rec.items() if k not in ("delegation_id", "signature")}
        rec["delegation_id"] = delegation_id_of(rec)
        rec["signature"] = key.sign(sig_preimage(rec)).hex()
        return rec
    def build(mut=None):
        a = seal(copy.deepcopy(base[0]), ka)
        c = copy.deepcopy(base[1]); c["parent_delegation_id"] = a["delegation_id"]
        if mut: mut(c)
        return [a, seal(c, kb)]
    out = {}
    out["resigned_baseline_valid"] = brief(verify_chain(build(), trust, set(), at))
    out["resigned_broken_parent_link"] = brief(verify_chain(build(lambda c: c.__setitem__("parent_delegation_id", "sha256:" + "0" * 64)), trust, set(), at))
    def wide(c): c["authority"]["scope"]["grants"] = ["net:*"]
    out["resigned_scope_widened"] = brief(verify_chain(build(wide), trust, set(), at))
    def deep(c): c["authority"]["depth"]["remaining"] = 4
    out["resigned_depth_not_decremented"] = brief(verify_chain(build(deep), trust, set(), at))
    def sp(c): c["authority"]["spend"]["cumulative"] = "100001"
    out["resigned_spend_widened"] = brief(verify_chain(build(sp), trust, set(), at))
    def rep(c): c["authority"]["reputation"]["ceiling"] = 91
    out["resigned_reputation_widened"] = brief(verify_chain(build(rep), trust, set(), at))
    def rv(c): c["authority"]["reversibility"]["ceiling"] = "irreversible"
    out["resigned_reversibility_widened"] = brief(verify_chain(build(rv), trust, set(), at))
    def tw(c): c["authority"]["time"]["not_after"] = "2027-06-01T00:00:00.000Z"
    out["resigned_time_widened"] = brief(verify_chain(build(tw), trust, set(), at))
    def vv(c): c["authority"]["values"]["required"] = []; 
    def issuer(c): c["issuer"] = "aps:agent:other"; c["verification_method"] = "aps:agent:other#key-1"
    out["resigned_issuer_discontinuity"] = brief(verify_chain(build(issuer), {**trust, "verification_keys": {**trust["verification_keys"], "aps:agent:other#key-1": pub(kb)}}, set(), at))
    return out

def main(path):
    raw = open(path, "rb").read()
    print("vector sha256:", hashlib.sha256(raw).hexdigest(), "bytes:", len(raw))
    v = json.loads(raw)
    # --- strip every `expected` member BEFORE evaluation ---
    cases = [{k: x for k, x in c.items() if k != "expected"} for c in v["cases"]]
    v_in = {k: x for k, x in v.items() if k != "cases"}
    assert all("expected" not in json.dumps(c) for c in cases)

    full = {}
    observed = {}
    for c in cases:
        r = verify_chain(v_in["chain"], v_in["trust_anchors"], set(c["revocation_state"]["revoked_delegation_ids"]), v_in["evaluated_at"])
        full[c["case_id"]] = r
        observed[c["case_id"]] = brief(r)
    frozen = json.dumps(observed, sort_keys=True)
    print("OBSERVED (frozen) sha256:", hashlib.sha256(frozen.encode()).hexdigest())
    print(json.dumps(full, indent=1))
    print("NEGATIVE CONTROLS:")
    nc = negative_controls(v_in)
    print(json.dumps(nc, indent=1))

    print("RESIGNED CONTROLS (local throwaway keys):")
    print(json.dumps(resigned_controls(v_in), indent=1))

    # --- only now read expected ---
    print("COMPARISON (expected read after freeze):")
    allok = True
    for c in v["cases"]:
        exp, obs = c["expected"], observed[c["case_id"]]
        # spec 4.3 defines no failure-code vocabulary; code compare is on the producer's label
        agree = all(obs.get(k) == exp.get(k) for k in exp)
        allok &= agree
        print(c["case_id"], "AGREES" if agree else "DISAGREES", "observed=", obs, "expected=", exp)
    sys.exit(0 if allok else 1)


if __name__ == "__main__":
    main(sys.argv[1])
