#!/usr/bin/env python3
"""Publication-bundle content gate (offline; publishes and uploads nothing).

    check_public_bundle.py --build OUT_DIR   # copy exactly the manifest's files to OUT_DIR (scratch)
    check_public_bundle.py --write-hashes    # (maintainer) refresh sha256/size of each file in PUBLIC_BUNDLE.json
    check_public_bundle.py BUNDLE            # validate a directory or .zip against PUBLIC_BUNDLE.json

Public bundle inputs must contain regular files only. Fails on: duplicate or colliding entry names,
symlinks and other non-regular files, unsafe paths (absolute, traversal, backslash, drive letters),
tests/vectors/caches, repository-only or unexpected files, missing files, bytes that differ from the
manifest sha256, secret-like strings, internal paths/endpoints, and an oversized bundle.
ZIPs are inspected entry by entry and never extracted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath

SKILL_ROOT = Path(__file__).resolve().parent.parent

# Targeted patterns only (no broad entropy heuristics: receipt ids, hashes and signatures must pass).
SECRET_PATTERNS = [
    ("PEM private key header", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("sk- style API key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("embedded bearer token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}")),
    ("secret assignment", re.compile(
        r"(?i)\b[A-Z0-9_]*(?:API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD)[A-Z0-9_]*\s*[:=]\s*[\"']?[A-Za-z0-9._~+/=-]{16,}")),
]
INTERNAL_PATTERNS = [
    ("local path /home/", re.compile(r"/home/")),
    ("local path /Users/", re.compile(r"/Users/")),
    ("localhost", re.compile(r"(?i)\blocalhost\b")),
    ("loopback address", re.compile(r"\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")),
    ("RFC1918 address", re.compile(
        r"(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])")),
    ("worktree name", re.compile(r"(?i)\bworktrees?\b|\b[a-z0-9-]+-wt\b")),
    ("working branch name", re.compile(r"\bclaude/[A-Za-z0-9._-]+")),
]


def load_manifest(root: Path = SKILL_ROOT) -> dict:
    return json.loads((root / "PUBLIC_BUNDLE.json").read_text(encoding="utf-8"))


def manifest_paths(m: dict) -> list[str]:
    return [f["path"] for f in m["files"]]


def build(out: Path, root: Path = SKILL_ROOT) -> None:
    m = load_manifest(root)
    if out.exists():
        raise SystemExit("refusing to build into existing path %s" % out)
    for rel in manifest_paths(m):
        dest = out / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / rel, dest)


def write_hashes(root: Path = SKILL_ROOT) -> None:
    m = load_manifest(root)
    m["files"] = [{"path": f["path"], "sha256": hashlib.sha256((root / f["path"]).read_bytes()).hexdigest(),
                   "size": (root / f["path"]).stat().st_size} for f in sorted(m["files"], key=lambda f: f["path"])]
    (root / "PUBLIC_BUNDLE.json").write_text(json.dumps(m, indent=2) + "\n", encoding="utf-8")


def _fold(name: str) -> str:
    return unicodedata.normalize("NFC", name).casefold()


def _unsafe_path(name: str) -> str | None:
    if not name or "\\" in name or "\x00" in name:
        return "backslash/NUL/empty name"
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return "absolute path"
    parts = name.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return "empty, '.' or '..' path component"
    return None


def _read_bundle(path: Path) -> tuple[list[tuple[str, bytes | None]], list[str]]:
    """Return ([(name, data)], structural_errors). Never extracts; never follows symlinks."""
    entries: list[tuple[str, bytes | None]] = []
    errs: list[str] = []
    if path.is_symlink():
        return [], ["bundle path itself is a symlink: %s" % path]
    if path.is_dir():
        for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
            for n in sorted(dirnames + filenames):
                full = Path(dirpath) / n
                rel = full.relative_to(path).as_posix()
                mode = os.lstat(full).st_mode
                if stat.S_ISLNK(mode):
                    errs.append("symlink not allowed: %s" % rel)
                    entries.append((rel, None))
                elif stat.S_ISDIR(mode):
                    continue
                elif not stat.S_ISREG(mode):
                    errs.append("non-regular file not allowed: %s" % rel)
                    entries.append((rel, None))
                else:
                    entries.append((rel, full.read_bytes()))
        return entries, errs
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for i in z.infolist():  # raw entry list: duplicates are preserved here
                if i.filename.endswith("/"):
                    why = _unsafe_path(i.filename[:-1])
                    if why:
                        errs.append("unsafe zip directory entry %r (%s)" % (i.filename, why))
                    continue
                mode = i.external_attr >> 16
                if mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                    errs.append("symlink/non-regular zip entry not allowed: %s" % i.filename)
                    entries.append((i.filename, None))
                    continue
                entries.append((i.filename, z.read(i)))
        return entries, errs
    raise ValueError("%s is neither a directory nor a zip file" % path)


def scan_text(name: str, text: str, forbidden_text: list[str]) -> list[str]:
    errs = []
    for needle in forbidden_text:
        if needle in text:
            errs.append("internal/forbidden text %r in %s" % (needle, name))
    for label, rx in SECRET_PATTERNS + INTERNAL_PATTERNS:
        if rx.search(text):
            errs.append("%s detected in %s" % (label, name))
    return errs


def check(bundle: Path, root: Path = SKILL_ROOT) -> list[str]:
    """Return a list of failures (empty = PASS)."""
    m = load_manifest(root)
    try:
        entries, errs = _read_bundle(bundle)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        return ["cannot read bundle: %s" % exc]
    errs = list(errs)
    expected = {f["path"]: f for f in m["files"]}
    seen: dict[str, str] = {}
    files: dict[str, bytes] = {}
    for name, data in entries:
        why = _unsafe_path(name)
        if why:
            errs.append("unsafe path %r (%s)" % (name, why))
            continue
        key = _fold(name)
        if key in seen:
            errs.append("duplicate or colliding entry: %r vs %r" % (name, seen[key]))
            continue
        seen[key] = name
        if data is not None:
            files[name] = data
    for name in sorted(files):
        for pat in m["forbidden_path_patterns"]:
            if pat in name:
                errs.append("forbidden file (%s): %s" % (pat, name))
                break
        else:
            if name in m["repository_only"] or any(r.endswith("/") and name.startswith(r) for r in m["repository_only"]):
                errs.append("repository-only file in bundle: %s" % name)
            elif name not in expected:
                errs.append("unexpected file: %s" % name)
    present = {_fold(n) for n in seen.values()}
    for name in sorted(expected):
        if name not in files and _fold(name) not in present:
            errs.append("missing required file: %s" % name)
    for name, meta in sorted(expected.items()):
        data = files.get(name)
        if data is not None and hashlib.sha256(data).hexdigest() != meta["sha256"]:
            errs.append("sha256 mismatch against manifest: %s" % name)
    for name, data in sorted(files.items()):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            errs.append("non-text file: %s" % name)
            continue
        errs.extend(scan_text(name, text, m["forbidden_text"]))
    total = sum(len(d) for d in files.values())
    if total > m["max_total_bytes"]:
        errs.append("bundle too large: %d > %d bytes" % (total, m["max_total_bytes"]))
    return errs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("bundle", nargs="?")
    ap.add_argument("--build", metavar="OUT_DIR")
    ap.add_argument("--write-hashes", action="store_true")
    a = ap.parse_args(argv)
    if a.write_hashes:
        write_hashes()
        print("manifest hashes refreshed")
        return 0
    if a.build:
        build(Path(a.build))
        print("built scratch bundle at %s" % a.build)
        return 0
    if not a.bundle:
        ap.error("bundle path required")
    errs = check(Path(a.bundle))
    for e in errs:
        print("BUNDLE FAIL: " + e)
    if errs:
        return 1
    entries, _ = _read_bundle(Path(a.bundle))
    print("BUNDLE PASS: %d files, %d bytes" % (len(entries), sum(len(d) for _, d in entries)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
