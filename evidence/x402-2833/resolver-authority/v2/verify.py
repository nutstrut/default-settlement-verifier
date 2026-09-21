#!/usr/bin/env python3
"""Deterministic local evaluator for the x402 #2833 resolver-authority V2 vector."""
import hashlib
import json
import pathlib
import unittest

FIXTURE = pathlib.Path(__file__).with_name("x402-2833-resolver-authority-vector-v2-20260921.json")

def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

def commitment_id(authority):
    return "sha256:" + hashlib.sha256(canonical_bytes(authority)).hexdigest()

def evaluate(fixture, case, resolver_name, supplied_commitment_id=None):
    authority = case["authority_commitment"]
    resolver = fixture["resolutions"][resolver_name]
    evidence_valid = fixture["shared_inputs"]["evidence"]["valid"] is True
    lifecycle_bound = fixture["shared_inputs"]["lifecycle"]["bound"] is True
    resolution_valid = resolver["internally_valid"] is True and evidence_valid and lifecycle_bound
    if authority is None:
        return {"evidence_valid": evidence_valid, "lifecycle_bound": lifecycle_bound, "resolution_valid": resolution_valid,
                "resolver_authorized": False, "authority_prior": False, "conflict_rule_applied": False,
                "transition_allowed": False, "classification": "BLOCKED", "reason": "NO_PRECOMMITTED_AUTHORITY",
                "authority_commitment_id": None}
    authority_id = commitment_id(authority)
    supplied = supplied_commitment_id == authority_id
    prior = authority.get("commitment_sequence", -1) < fixture["shared_inputs"]["evidence"]["observed_sequence"]
    tuple_value = {"resolver_id": resolver["resolver_id"], "check_set_id": resolver["check_set_id"], "permitted_successor_state": resolver["successor_state"]}
    exact = tuple_value in authority["authorized_resolutions"]
    if not supplied:
        authorized = False
        reason = "NO_PRECOMMITTED_AUTHORITY"
    elif not authority["authorized_resolutions"]:
        authorized = False
        reason = "NO_AUTHORIZED_RESOLUTIONS"
    elif not prior:
        authorized = False
        reason = "AUTHORITY_NOT_PRIOR"
    elif not exact:
        authorized = False
        reason = "RESOLVER_NOT_PREAUTHORIZED"
    else:
        authorized = True
        reason = "AUTHORIZED_CANDIDATE"
    return {"evidence_valid": evidence_valid, "lifecycle_bound": lifecycle_bound, "resolution_valid": resolution_valid,
            "resolver_authorized": authorized, "authority_prior": prior, "conflict_rule_applied": False,
            "transition_allowed": False, "classification": "BLOCKED", "reason": reason, "authority_commitment_id": authority_id}

def evaluate_case(fixture, case):
    cid = None if case["authority_commitment"] is None else commitment_id(case["authority_commitment"])
    results = {name: evaluate(fixture, case, name, cid) for name in fixture["resolutions"]}
    authorized = [name for name, result in results.items() if result["resolution_valid"] and result["resolver_authorized"]]
    states = {fixture["resolutions"][name]["successor_state"] for name in authorized}
    if len(authorized) == 1:
        winner = authorized[0]
        results[winner].update(transition_allowed=True, classification="ALLOWED", reason="AUTHORIZED_RESOLUTION")
    elif len(authorized) > 1 and len(states) == 1:
        for name in authorized:
            results[name].update(transition_allowed=True, classification="ALLOWED", reason="SAME_AUTHORIZED_SUCCESSOR")
    elif len(authorized) > 1:
        rule = case["authority_commitment"].get("conflict_rule")
        order = rule.get("order", []) if isinstance(rule, dict) and rule.get("type") == "priority_order" else []
        ranked = [name for name in order if name in {fixture["resolutions"][n]["resolution_id"] for n in authorized}]
        if len(ranked) == len(authorized) and len(set(ranked)) == len(authorized):
            winner_id = ranked[0]
            winner = next(name for name in authorized if fixture["resolutions"][name]["resolution_id"] == winner_id)
            for name in authorized:
                results[name]["conflict_rule_applied"] = True
                if name == winner:
                    results[name].update(transition_allowed=True, classification="ALLOWED", reason="PRECOMMITTED_CONFLICT_RULE")
                else:
                    results[name]["reason"] = "PRECOMMITTED_CONFLICT_RULE_NON_SELECTED"
            results["operative_successor_state"] = fixture["resolutions"][winner]["successor_state"]
        else:
            for name in authorized:
                results[name].update(classification="BLOCKED_INDETERMINATE", reason="CONFLICT_RULE_MISSING" if not rule else "CONFLICT_UNRESOLVED")
    return results

class VectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def assert_case(self, case_id):
        case = next(case for case in self.fixture["cases"] if case["id"] == case_id)
        actual = evaluate_case(self.fixture, case)
        for name, expected in case["expected"].items():
            if isinstance(expected, dict):
                self.assertEqual({key: actual[name][key] for key in expected}, expected, case_id)
            else:
                self.assertEqual(actual.get(name), expected, case_id)

    def test_NULL_AUTHORITY_BLOCKED(self): self.assert_case("case-null-authority")
    def test_EMPTY_AUTHORITY_SET_BLOCKED(self): self.assert_case("case-empty-authority-set")
    def test_AUTHORIZED_A_ALLOWED(self): self.assert_case("case-only-A-authorized")
    def test_UNAUTHORIZED_B_BLOCKED(self): self.assert_case("case-only-A-authorized")
    def test_LATE_AUTHORITY_BLOCKED(self): self.assert_case("case-late-authority")
    def test_EQUAL_SEQUENCE_AUTHORITY_NOT_PRIOR(self): self.assert_case("case-equal-sequence-authority")
    def test_MULTIPLE_AUTHORIZED_PRIORITY_RESOLVES(self): self.assert_case("case-two-candidate-priority-order")
    def test_THREE_CANDIDATE_PRIORITY_ORDER_RESOLVES(self): self.assert_case("case-three-candidate-priority-order")
    def test_MULTIPLE_AUTHORIZED_NO_RULE_BLOCKED_INDETERMINATE(self): self.assert_case("case-multiple-authorized-no-rule")

    def test_RESOLVER_SUBSTITUTION_BLOCKED(self): self._assert_substitution("resolver_id", "resolver-X")
    def test_CHECK_SET_SUBSTITUTION_BLOCKED(self): self._assert_substitution("check_set_id", "check-set-X")
    def test_SUCCESSOR_SUBSTITUTION_BLOCKED(self): self._assert_substitution("successor_state", "state-X")

    def _assert_substitution(self, field, value):
        case = next(case for case in self.fixture["cases"] if case["id"] == "case-only-A-authorized")
        candidate = dict(self.fixture["resolutions"]["resolver_A"])
        candidate[field] = value
        fixture = {**self.fixture, "resolutions": {"candidate": candidate}}
        result = evaluate(fixture, case, "candidate", commitment_id(case["authority_commitment"]))
        self.assertTrue(result["resolution_valid"])
        self.assertFalse(result["resolver_authorized"])
        self.assertFalse(result["transition_allowed"])

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(VectorTests)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    print(f"resolver_authority_vector_v2={'ok' if result.wasSuccessful() else 'failed'} named_behaviors={result.testsRun}")
    raise SystemExit(0 if result.wasSuccessful() else 1)
