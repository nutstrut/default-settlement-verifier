from __future__ import annotations

import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_public_bundle as cb  # noqa: E402

ROOT = cb.SKILL_ROOT


@pytest.fixture()
def bundle(tmp_path):
    out = tmp_path / "bundle"
    cb.build(out)
    return out


def test_correct_bundle_passes(bundle):
    assert cb.check(bundle) == []


def test_zip_bundle_passes_and_tests_in_zip_fail(bundle, tmp_path):
    z = tmp_path / "b.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for p in bundle.rglob("*"):
            if p.is_file():
                zf.write(p, p.relative_to(bundle).as_posix())
    assert cb.check(z) == []
    with zipfile.ZipFile(z, "a") as zf:
        zf.writestr("tests/test_x.py", "")
    assert any("forbidden file" in e for e in cb.check(z))


def test_tests_dir_fails(bundle):
    (bundle / "tests").mkdir()
    (bundle / "tests" / "test_x.py").write_text("")
    assert any("tests/" in e for e in cb.check(bundle))


def test_vectors_fail(bundle):
    (bundle / "references" / "vectors.json").write_text("{}")
    assert any("vectors" in e for e in cb.check(bundle))


def test_missing_runtime_file_fails(bundle):
    (bundle / "scripts" / "verify_v02.py").unlink()
    assert "missing required file: scripts/verify_v02.py" in cb.check(bundle)


@pytest.mark.parametrize("name", ["scripts/__pycache__/x.cpython-312.pyc", "scripts/x.pyc", ".pytest_cache/v"])
def test_cache_files_fail(bundle, name):
    p = bundle / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"")
    assert any("forbidden file" in e for e in cb.check(bundle))


@pytest.mark.parametrize("name", ["MAINTAINING.md", "UPSTREAM.json", "PUBLIC_BUNDLE.json"])
def test_repository_only_files_fail(bundle, name):
    (bundle / name).write_text("x")
    assert any("repository-only" in e for e in cb.check(bundle))


def test_unexpected_file_fails(bundle):
    (bundle / "notes.txt").write_text("x")
    assert "unexpected file: notes.txt" in cb.check(bundle)


def test_internal_path_in_text_fails(bundle):
    p = bundle / "README.md"
    p.write_text(p.read_text() + "\n/home/someone/dev\n")
    assert any("/home/" in e for e in cb.check(bundle))


def test_manifest_lists_only_existing_runtime_files():
    m = cb.load_manifest()
    for rel in m["files"]:
        assert (ROOT / rel).is_file(), rel
    assert not any(f.startswith("tests/") or "vectors" in f for f in m["files"])


def test_example_verifies_through_bundle_with_network_disabled(bundle, tmp_path):
    guard = tmp_path / "nonet.py"
    guard.write_text("import socket, runpy, sys\n"
                     "def _b(*a, **k): raise RuntimeError('network disabled')\n"
                     "socket.socket.connect = _b\nsocket.create_connection = _b\nsocket.getaddrinfo = _b\n"
                     "sys.argv = sys.argv[1:]\n"
                     "runpy.run_path(sys.argv[0], run_name='__main__')\n")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    p = subprocess.run([sys.executable, "-B", str(guard), str(bundle / "scripts" / "verify_receipt_v02.py"),
                        str(bundle / "examples" / "receipt-indeterminate.json")],
                       capture_output=True, text=True, env=env, cwd=str(bundle))
    assert p.returncode == 0, p.stderr
    assert "Issuer verdict: INDETERMINATE" in p.stdout and "Receipt: Valid." in p.stdout
    assert not list(bundle.rglob("*.pyc"))


def test_public_text_claim_ceiling():
    bad = ["used by developers", "industry standard", "production proven", "prevents fraud", "trusted by", "certifies agents"]
    for rel in cb.load_manifest()["files"]:
        if rel.endswith(".md"):
            t = (ROOT / rel).read_text().lower()
            for b in bad:
                assert b not in t, (rel, b)


def test_skill_frontmatter_public_fields():
    t = (ROOT / "SKILL.md").read_text()
    head = t.split("---")[1]
    assert "name: defaultverifier" in head and "version: 0.1.0" in head
    assert "homepage: https://defaultverifier.com" in head
    assert "settlement-witness" in t and "NOT_A_V02_RECEIPT" in t
