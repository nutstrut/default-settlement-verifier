from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import stat
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
    paths = cb.manifest_paths(m)
    assert len(paths) == 9
    for f in m["files"]:
        assert (ROOT / f["path"]).is_file(), f["path"]
        assert hashlib.sha256((ROOT / f["path"]).read_bytes()).hexdigest() == f["sha256"]
        assert (ROOT / f["path"]).stat().st_size == f["size"]
    assert not any(f.startswith("tests/") or "vectors" in f for f in paths)


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
    for rel in cb.manifest_paths(cb.load_manifest()):
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


SNAP = "trust/sar-keys-v02-snapshot.json"


def _mkzip(bundle, z, extra=()):
    with zipfile.ZipFile(z, "w") as zf:
        for p in sorted(bundle.rglob("*")):
            if p.is_file():
                zf.write(p, p.relative_to(bundle).as_posix())
        for name, data in extra:
            zf.writestr(name, data)
    return z


def test_snapshot_hash_pinned_and_unmodified():
    m = {f["path"]: f for f in cb.load_manifest()["files"]}
    assert m[SNAP]["sha256"].startswith("1a8baffe")
    assert hashlib.sha256((ROOT / SNAP).read_bytes()).hexdigest() == m[SNAP]["sha256"]


@pytest.mark.parametrize("name", ["SKILL.md", "README.md", "scripts/verify_v02.py", "examples/receipt-indeterminate.json",
                                  SNAP, "trust/sar-keys-v02-snapshot.provenance.json"])
def test_modified_file_fails_hash(bundle, name):
    p = bundle / name
    p.write_bytes(p.read_bytes() + b"\n")
    assert "sha256 mismatch against manifest: %s" % name in cb.check(bundle)


@pytest.mark.parametrize("extra", [
    [("SKILL.md", b"x")],                                  # same path, different content
    [("scripts/verify_v02.py", None)],                     # nested, exact duplicate
    [("README.md", None)],                                 # exact duplicate bytes
    [("skill.md", b"x")],                                  # case collision
])
def test_duplicate_zip_entries_fail(bundle, tmp_path, extra):
    def data(n, d):
        return (bundle / n).read_bytes() if d is None else d
    z = _mkzip(bundle, tmp_path / "d.zip", [(n, data(n, d)) for n, d in extra])
    assert any("duplicate" in e for e in cb.check(z))


def test_unicode_normalization_collision_fails(bundle, tmp_path):
    z = _mkzip(bundle, tmp_path / "u.zip", [("caf\u00e9.txt", b"a"), ("cafe\u0301.txt", b"b")])
    assert any("duplicate" in e for e in cb.check(z))


def test_symlink_replacing_required_file_fails_dir(bundle, tmp_path):
    target = tmp_path / "real.md"
    target.write_bytes((bundle / "README.md").read_bytes())
    (bundle / "README.md").unlink()
    (bundle / "README.md").symlink_to(target)
    assert any("symlink not allowed: README.md" in e for e in cb.check(bundle))


def test_symlink_directory_fails(bundle, tmp_path):
    real = tmp_path / "realdir"
    real.mkdir()
    (real / "a.txt").write_text("x")
    (bundle / "linkdir").symlink_to(real, target_is_directory=True)
    assert any("symlink not allowed: linkdir" in e for e in cb.check(bundle))


def test_symlink_bundle_root_fails(bundle, tmp_path):
    link = tmp_path / "root-link"
    link.symlink_to(bundle, target_is_directory=True)
    assert any("symlink" in e for e in cb.check(link))


def test_fifo_fails(bundle):
    os.mkfifo(bundle / "pipe")
    assert any("non-regular file not allowed: pipe" in e for e in cb.check(bundle))


def test_zip_symlink_entry_fails(bundle, tmp_path):
    z = tmp_path / "s.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for p in sorted(bundle.rglob("*")):
            if p.is_file() and p.name != "README.md":
                zf.write(p, p.relative_to(bundle).as_posix())
        i = zipfile.ZipInfo("README.md")
        i.create_system = 3
        i.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(i, "SKILL.md")
    errs = cb.check(z)
    assert any("symlink/non-regular zip entry" in e for e in errs)
    assert "missing required file: README.md" in errs or any("README.md" in e for e in errs)


@pytest.mark.parametrize("name", ["../foo", "/etc/foo", "./tests/x", "..\\foo", "C:\\Windows\\x", "C:/x", "a/../../b",
                                  "scripts\\..\\..\\x", "scripts/../../x", "/", ".hidden", "scripts/.hidden"])
def test_zip_path_safety(bundle, tmp_path, name):
    z = _mkzip(bundle, tmp_path / "p.zip", [(name, b"x")])
    assert cb.check(z) != []


def test_zip_is_not_extracted(bundle, tmp_path, monkeypatch):
    z = _mkzip(bundle, tmp_path / "n.zip", [("../escape.txt", b"x")])
    monkeypatch.chdir(tmp_path)
    cb.check(z)
    assert not (tmp_path.parent / "escape.txt").exists() and not (tmp_path / "escape.txt").exists()


@pytest.mark.parametrize("text", [
    "key sk-" + "A1b2C3d4E5f6G7h8I9j0",
    "tok ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2",
    "AKIA" + "ABCDEFGHIJKLMNOP",
    "-----BEGIN RSA " + "PRIVATE KEY-----",
    "Authorization: Bearer " + "abcdEFGH1234abcdEFGH1234",
    "API_KEY=" + "abcdEFGH1234abcdEFGH",
    "export SECRET=" + "abcdEFGH1234abcdEFGH",
    "TOKEN: " + "abcdEFGH1234abcdEFGH",
    "see http://localhost:8080/x",
    "host 127.0.0.1",
    "host 10.1.2.3",
    "host 192.168.0.5",
    "host 172.20.1.1",
    "/home/ubuntu/morpheus",
    "/Users/someone/x",
    "claude/defaultverifier-prepublish-20261121",
    "in dsv-prepublish-wt",
    "a git worktree",
])
def test_bad_patterns_fail(bundle, text):
    p = bundle / "README.md"
    p.write_text(p.read_text() + "\n" + text + "\n")
    errs = cb.check(bundle)
    assert any("README.md" in e and "sha256" not in e for e in errs), errs


def test_legitimate_public_data_passes_scan():
    sig = "A" * 86 + "=="
    txt = ("https://defaultverifier.com and https://defaultverifier.com/.well-known/sar-keys.json "
           "receipt_id sha256:" + "ab12" * 16 + " signature " + sig + " 8.8.8.8 172.32.0.1 11.0.0.1 TOKEN_COUNT=5")
    assert cb.scan_text("x", txt, cb.load_manifest()["forbidden_text"]) == []


def test_shipped_files_have_no_scan_findings():
    for f in cb.manifest_paths(cb.load_manifest()):
        assert cb.scan_text(f, (ROOT / f).read_text(), cb.load_manifest()["forbidden_text"]) == [], f


def test_provenance_public_registry_url_present_and_allowed(bundle):
    prov = json.loads((bundle / "trust/sar-keys-v02-snapshot.provenance.json").read_text())
    assert prov["source"] == "https://defaultverifier.com/.well-known/sar-keys.json"
    assert cb.check(bundle) == []


def test_changelog_is_timeless():
    t = (ROOT / "CHANGELOG.md").read_text().lower()
    for bad in ("not yet published", "published", "released publicly", "clawhub", "available on"):
        assert bad not in t


def test_description_keeps_routing_phrases_without_overclaim():
    head = (ROOT / "SKILL.md").read_text().split("---")[1]
    assert "verify this receipt" in head and len(head) < 1400
    assert "only what the signed receipt establishes" in head


def test_renamed_vector_file_hidden_in_bundle_fails(bundle):
    (bundle / "references" / "notes.json").write_bytes((ROOT / "tests" / "fixtures" / "vectors.json").read_bytes())
    errs = cb.check(bundle)
    assert "unexpected file: references/notes.json" in errs
