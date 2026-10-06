"""Capsule-local assurance controls for the SAR primitive vector corpus.

Proves the corpus runner is exit-code-enforced: the pristine corpus passes, and each
bounded corruption of a pinned expectation/input makes it exit nonzero (no false PASS).
Also executes the +-2^53 family against BOTH jcs and rfc8785 directly, independent of
the declared corpus. Not a general runner-assurance framework.
"""
import copy
import json
import subprocess
import sys
from pathlib import Path

import jcs
import pytest
import rfc8785

D = Path(__file__).resolve().parents[1]
RUNNER = D / "run_vectors.py"
VECTORS = D / "vectors.json"


def _run(path):
    return subprocess.run([sys.executable, str(RUNNER), "--vectors", str(path)], capture_output=True, text=True)


def _case(v, cid):
    return next(c for c in v["cases"] if c["case_id"] == cid)


def test_pristine_corpus_passes():
    r = _run(VECTORS)
    assert r.returncode == 0, r.stderr
    assert "cases_run=27 failures=0 overall=ALL_DECLARED_EXPECTATIONS_MATCHED" in r.stdout


def test_retained_results_are_current(tmp_path):
    out = tmp_path / "r.json"
    subprocess.run([sys.executable, str(RUNNER), "--out", str(out)], check=True, capture_output=True)
    assert out.read_text() == (D / "results" / "primitive_results.json").read_text()


P53 = 2**53


@pytest.mark.parametrize(
    "n, jcs_emits",
    [(P53 - 1, P53 - 1), (P53, P53), (-P53, -P53), (P53 + 1, P53), (-(P53 + 1), -P53)],
)
def test_jcs_0_2_1_2pow53_family(n, jcs_emits):
    # SAR side: emits exactly at +-2^53; +-(2^53+1) silently becomes +-2^53 (lossy).
    assert jcs.canonicalize({"n": n}) == b'{"n":' + str(jcs_emits).encode() + b"}"


@pytest.mark.parametrize("n, ok", [(P53 - 1, True), (P53, False), (-P53, False), (P53 + 1, False), (-(P53 + 1), False)])
def test_rfc8785_0_1_4_2pow53_family(n, ok):
    # Independent side: observed behavior, asserted separately from jcs (no aggregate).
    if ok:
        assert rfc8785.dumps({"n": n}) == b'{"n":' + str(n).encode() + b"}"
    else:
        with pytest.raises(rfc8785.IntegerDomainError):
            rfc8785.dumps({"n": n})


MUTATIONS = {
    "pinned_sha256_corrupted": lambda v: _case(v, "INT-1")["expect"]["sha256"].update(digest_hex="0" * 64),
    "pinned_canonical_bytes_corrupted": lambda v: _case(v, "UTF16-1")["expect"]["canonicalization"].update(canonical_bytes_hex="00"),
    "input_corrupted": lambda v: _case(v, "UTF16-1")["input"].update(text='{"a":3}'),
    "negative_signature_expected_flipped": lambda v: _case(v, "ED-2-MUT-SIG")["signature_check"].update(expected_verify="ESTABLISHED"),
    "positive_signature_corrupted": lambda v: _case(v, "ED-2")["signature_check"].update(signature_b64url="A" * 86),
    "dup_key_expectation_flipped": lambda v: _case(v, "DUP-1")["expect"]["parse"].update(duplicate_keys_detected=False),
    "case_count_drift": lambda v: v.update(case_count=v["case_count"] + 1),
    "unknown_expect_key": lambda v: _case(v, "INT-1")["expect"].update(bogus={"status": "ESTABLISHED"}),
    # added in the public capsule: the rfc8785 side must also affect exit status
    "rfc8785_expectation_flipped": lambda v: _case(v, "NUM-2")["expect"]["rfc8785"].update(status="ESTABLISHED"),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_runner_fails_closed_on_corruption(name, tmp_path):
    v = copy.deepcopy(json.loads(VECTORS.read_text()))
    MUTATIONS[name](v)
    p = tmp_path / "vectors.json"
    p.write_text(json.dumps(v))
    r = _run(p)
    assert r.returncode != 0, f"{name}: runner falsely passed"
    assert "ALL_DECLARED_EXPECTATIONS_MATCHED" not in r.stdout
