#!/usr/bin/env python3
"""Small deterministic evaluator for the local x402 #2833 authority vector."""
import hashlib
import json
import pathlib
import unittest


FIXTURE = pathlib.Path(__file__).with_name("x402-2833-resolver-authority-vector-20260919.json")


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def commitment_id(authority):
    return "sha256:" + hashlib.sha256(canonical_bytes(authority)).hexdigest()


def evaluate(fixture, case, resolver_name, authority_commitment_id=None):
    authority = case["authority_commitment"]
    resolver = fixture["resolutions"][resolver_name]
    evidence_valid = fixture["shared_inputs"]["evidence"]["valid"] is True
    lifecycle_bound = fixture["shared_inputs"]["lifecycle"]["bound"] is True
    resolution_valid = resolver["internally_valid"] is True and evidence_valid and lifecycle_bound
    authority_id = commitment_id(authority)
    commitment_supplied = authority_commitment_id == authority_id
    resolver_authorized = (
        commitment_supplied
        and authority["committed_before_evidence"] is True
        and {
            "resolver_id": resolver["resolver_id"],
            "check_set_id": resolver["check_set_id"],
            "permitted_successor_state": resolver["successor_state"],
        } in authority["authorized_resolutions"]
    )
    return {
        "evidence_valid": evidence_valid,
        "lifecycle_bound": lifecycle_bound,
        "resolution_valid": resolution_valid,
        "resolver_authorized": resolver_authorized,
        "conflict_rule_applied": False,
        "transition_allowed": False,
        "reason": "RESOLVER_NOT_PREAUTHORIZED" if not resolver_authorized else "AUTHORIZED_CANDIDATE",
        "authority_commitment_id": authority_id,
    }


def evaluate_case(fixture, case):
    cid = commitment_id(case["authority_commitment"])
    results = {name: evaluate(fixture, case, name, cid) for name in fixture["resolutions"]}
    authorized = [name for name, result in results.items() if result["resolution_valid"] and result["resolver_authorized"]]
    states = {fixture["resolutions"][name]["successor_state"] for name in authorized}
    rule = case["authority_commitment"]["conflict_rule"]
    if len(authorized) == 1:
        chosen = authorized[0]
        results[chosen]["transition_allowed"] = True
        results[chosen]["reason"] = "AUTHORIZED_RESOLUTION"
    elif len(authorized) > 1 and len(states) == 1:
        for name in authorized:
            results[name]["transition_allowed"] = True
            results[name]["reason"] = "SAME_AUTHORIZED_SUCCESSOR"
    elif len(authorized) > 1 and rule == "prefer_A":
        results["resolver_A"]["transition_allowed"] = True
        results["resolver_A"]["conflict_rule_applied"] = True
        results["resolver_B"]["conflict_rule_applied"] = True
        results["resolver_A"]["reason"] = results["resolver_B"]["reason"] = "PRECOMMITTED_CONFLICT_RULE"
        results["operative_successor_state"] = "state-A"
    elif len(authorized) > 1:
        for name in authorized:
            results[name]["reason"] = "CONFLICT_RULE_MISSING"
        results["classification"] = "BLOCKED_INDETERMINATE"
    return results


class VectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_required_cases(self):
        for case in self.fixture["cases"]:
            actual = evaluate_case(self.fixture, case)
            for name, expected in case["expected"].items():
                if isinstance(expected, dict):
                    self.assertEqual({k: actual[name][k] for k in expected}, expected, case["id"])
                else:
                    self.assertEqual(actual.get(name), expected, case["id"])

    def test_identity_and_check_set_substitution_stays_blocked(self):
        case = self.fixture["cases"][0]
        cid = commitment_id(case["authority_commitment"])
        mutated = dict(self.fixture["resolutions"]["resolver_A"])
        mutated["resolver_id"] = "resolver-B"
        self.assertFalse(evaluate({**self.fixture, "resolutions": {"resolver_A": mutated}}, case, "resolver_A", cid)["resolver_authorized"])
        mutated = dict(self.fixture["resolutions"]["resolver_A"])
        mutated["check_set_id"] = "check-set-B"
        self.assertFalse(evaluate({**self.fixture, "resolutions": {"resolver_A": mutated}}, case, "resolver_A", cid)["resolver_authorized"])

    def test_valid_evidence_and_lifecycle_do_not_create_authority(self):
        case = self.fixture["cases"][0]
        result = evaluate_case(self.fixture, case)["resolver_B"]
        self.assertTrue(result["evidence_valid"])
        self.assertTrue(result["lifecycle_bound"])
        self.assertTrue(result["resolution_valid"])
        self.assertFalse(result["resolver_authorized"])
        self.assertFalse(result["transition_allowed"])

    def test_cross_product_tuples_are_not_authorized(self):
        case = self.fixture["cases"][1]
        cid = commitment_id(case["authority_commitment"])
        for resolver_id, check_set_id, state in (
            ("resolver-A", "check-set-B", "state-A"),
            ("resolver-B", "check-set-A", "state-B"),
            ("resolver-A", "check-set-A", "state-B"),
        ):
            candidate = {
                "resolver_id": resolver_id,
                "check_set_id": check_set_id,
                "successor_state": state,
                "internally_valid": True,
            }
            fixture = {**self.fixture, "resolutions": {"candidate": candidate}}
            result = evaluate(fixture, case, "candidate", cid)
            self.assertTrue(result["resolution_valid"])
            self.assertFalse(result["resolver_authorized"])
            self.assertFalse(result["transition_allowed"])


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(VectorTests)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    print(f"resolver_authority_vector={'ok' if result.wasSuccessful() else 'failed'} tests={result.testsRun}")
    raise SystemExit(0 if result.wasSuccessful() else 1)
