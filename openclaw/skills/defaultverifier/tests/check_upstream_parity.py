#!/usr/bin/env python3
"""Release gate: prove the vendored verifier, trust snapshot and vectors are identical to
the canonical defaultsettle-cli source. Run before merge/release; it is NOT part of the
ordinary offline test run and it FAILS (never skips) when the upstream cannot be verified.

    python3 openclaw/skills/defaultverifier/tests/check_upstream_parity.py --cli-repo /path/to/defaultsettle-cli

Checks (every one is a hard failure):
  1. --cli-repo exists, is a git work tree, and contains the pinned commit from UPSTREAM.json.
  2. For every file in UPSTREAM.json: bytes of the upstream blob AT THE PINNED COMMIT hash to the
     pinned sha256 and equal the vendored bytes.
  3. Drift: the upstream HEAD version of each core file equals the pinned version (if upstream moved,
     the gate fails until the vendored copy is deliberately refreshed; see README "Refreshing").
  4. Representative execution parity: the canonical CLI `verify-v02` output equals the helper's
     verifier_result for every vector verifiable against the bundled snapshot (production policy).

Read-only toward the upstream repo: only `git cat-file/show/rev-parse` run there, with optional
locks disabled and bytecode writing off. No network, no cloning, no fetching.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_SKILL_ROOT = HERE.parent
VECTORS_UPSTREAM_PATH = "tests/fixtures/v02/vectors.json"


class Gate(Exception):
    """A release-gate failure."""


def _git(repo: Path, *args: str) -> bytes:
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    p = subprocess.run(["git", "--no-optional-locks", "-C", str(repo), *args],
                       capture_output=True, env=env, timeout=60)
    if p.returncode != 0:
        raise Gate("git %s failed: %s" % (" ".join(args), p.stderr.decode("utf-8", "replace").strip()[:200]))
    return p.stdout


def _upstream_rel(meta_upstream: str) -> str:
    # UPSTREAM.json "upstream" for vectors carries a human note; the real path is fixed.
    return VECTORS_UPSTREAM_PATH if meta_upstream.startswith("tests/fixtures/v02/vectors.json") else meta_upstream


def check_static(cli_repo: Path, skill_root: Path = DEFAULT_SKILL_ROOT) -> list[str]:
    """Checks 1-3. Returns human-readable PASS lines; raises Gate on the first failure."""
    log: list[str] = []
    cli_repo = Path(cli_repo)
    if not cli_repo.is_dir():
        raise Gate("canonical CLI checkout not found at %s: release gate cannot verify upstream" % cli_repo)
    try:
        _git(cli_repo, "rev-parse", "--is-inside-work-tree")
    except Gate:
        raise Gate("%s is not a git work tree: cannot verify upstream commit" % cli_repo)
    pins = json.loads((skill_root / "UPSTREAM.json").read_text(encoding="utf-8"))
    commit = pins["source_commit"]
    _git(cli_repo, "cat-file", "-e", commit + "^{commit}")
    log.append("pinned upstream commit present: %s" % commit)
    head = _git(cli_repo, "rev-parse", "HEAD").decode().strip()
    log.append("upstream HEAD: %s" % head)
    for rel, meta in sorted(pins["files"].items()):
        up = _upstream_rel(meta["upstream"])
        vendored = (skill_root / rel).read_bytes()
        pinned = _git(cli_repo, "show", "%s:%s" % (commit, up))
        edits = meta.get("local_edits")
        if edits:
            # The only permitted deviation from byte-identity: a declared set of top-level JSON string
            # fields. Pinned upstream blob hash, vendored hash, and the exact field-level difference
            # are all checked, so this is no weaker than byte-identity for everything else.
            if hashlib.sha256(pinned).hexdigest() != meta.get("upstream_sha256"):
                raise Gate("%s: upstream blob at %s does not match the upstream_sha256 pinned in UPSTREAM.json" % (up, commit[:7]))
            if hashlib.sha256(vendored).hexdigest() != meta["sha256"]:
                raise Gate("%s: vendored bytes do not match the sha256 pinned in UPSTREAM.json" % rel)
            try:
                up_obj, my_obj = json.loads(pinned), json.loads(vendored)
            except ValueError:
                raise Gate("%s: local_edits require JSON on both sides" % rel)
            expected = dict(up_obj)
            for field, ed in edits.items():
                if expected.get(field) != ed["upstream"]:
                    raise Gate("%s: upstream field %r is not the declared %r" % (up, field, ed["upstream"]))
                expected[field] = ed["skill"]
            if my_obj != expected:
                raise Gate("%s: vendored copy differs from upstream beyond the declared local_edits" % rel)
            log.append("identical to upstream at pinned commit except declared local_edits %s: %s (sha256 %s)" % (
                sorted(edits), rel, meta["sha256"][:12]))
            latest = _git(cli_repo, "show", "HEAD:" + up)
            if latest != pinned:
                raise Gate("DRIFT: %s changed upstream between %s and HEAD %s; refresh the vendored copy deliberately" % (up, commit[:7], head[:7]))
            continue
        if hashlib.sha256(pinned).hexdigest() != meta["sha256"]:
            raise Gate("%s: upstream blob at %s does not match the sha256 pinned in UPSTREAM.json" % (up, commit[:7]))
        if vendored != pinned:
            raise Gate("%s: vendored bytes differ from upstream at %s" % (rel, commit[:7]))
        log.append("byte-identical at pinned commit: %s == %s (sha256 %s)" % (rel, up, meta["sha256"][:12]))
        latest = _git(cli_repo, "show", "HEAD:" + up)
        if latest != pinned:
            raise Gate("DRIFT: %s changed upstream between %s and HEAD %s; refresh the vendored copy deliberately" % (up, commit[:7], head[:7]))
    log.append("no upstream drift on any vendored file between pinned commit and HEAD")
    return log


_CLI_DRIVER = (
    "import sys, runpy\n"
    "sys.dont_write_bytecode = True\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "sys.argv = ['defaultsettle', 'verify-v02', sys.argv[2]]\n"
    "runpy.run_module('defaultsettle.cli', run_name='__main__')\n"
)


def check_cli_exec(cli_repo: Path, skill_root: Path = DEFAULT_SKILL_ROOT) -> list[str]:
    """Check 4. Compares canonical CLI output with the helper's verifier_result."""
    suite = json.loads((skill_root / "tests" / "fixtures" / "vectors.json").read_text(encoding="utf-8"))
    sys.path.insert(0, str(skill_root / "scripts"))
    sys.dont_write_bytecode = True
    import verify_receipt_v02 as h  # noqa: E402

    cases = [c for c in suite["cases"] if c["trust_policy"] != "test" and "receipt_raw" not in c]
    if len(cases) < 5:
        raise Gate("expected several bundled-snapshot vectors for execution parity, found %d" % len(cases))
    n_valid = n_invalid = 0
    with tempfile.TemporaryDirectory() as td:
        for c in cases:
            f = Path(td) / "r.json"
            f.write_text(json.dumps(c["receipt"]), encoding="utf-8")
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
            theirs = subprocess.run([sys.executable, "-B", "-c", _CLI_DRIVER, str(cli_repo), str(f)],
                                    capture_output=True, text=True, env=env, timeout=60)
            try:
                their_json = json.loads(theirs.stdout)
            except ValueError:
                raise Gate("%s: canonical CLI printed no JSON (exit %s): %s" % (c["id"], theirs.returncode, theirs.stderr.strip()[:200]))
            mine = h.verify_text(f.read_text(encoding="utf-8"))
            if mine != their_json:
                raise Gate("%s: helper verifier result differs from canonical CLI output" % c["id"])
            if h.json_output(mine)["canonical_result_sha256"] != hashlib.sha256(
                    json.dumps(their_json, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest():
                raise Gate("%s: canonical_result_sha256 does not identify the canonical CLI output" % c["id"])
            if mine["receipt_valid"]:
                n_valid += 1
            else:
                n_invalid += 1
    if not (n_valid and n_invalid):
        raise Gate("execution parity must cover both valid and invalid receipts (valid=%d invalid=%d)" % (n_valid, n_invalid))
    return ["canonical CLI output == helper verifier result on %d bundled-snapshot vectors (%d valid, %d invalid)" % (
        n_valid + n_invalid, n_valid, n_invalid)]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Release-gate parity check against a canonical defaultsettle-cli checkout.")
    ap.add_argument("--cli-repo", required=True, help="path to a local defaultsettle-cli git checkout (read only)")
    ap.add_argument("--skill-root", default=str(DEFAULT_SKILL_ROOT), help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    try:
        lines = check_static(Path(args.cli_repo), Path(args.skill_root))
        lines += check_cli_exec(Path(args.cli_repo), Path(args.skill_root))
    except Gate as exc:
        print("RELEASE GATE FAIL: %s" % exc)
        return 1
    for line in lines:
        print("ok  " + line)
    print("RELEASE GATE PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
