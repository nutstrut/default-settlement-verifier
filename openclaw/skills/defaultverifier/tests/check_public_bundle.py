#!/usr/bin/env python3
"""Publication-bundle content gate (offline; publishes and uploads nothing).

    check_public_bundle.py --build OUT_DIR   # copy exactly the manifest's files to OUT_DIR (scratch)
    check_public_bundle.py BUNDLE            # validate a directory or .zip against PUBLIC_BUNDLE.json

Fails on: tests/vectors/caches/.pyc, repository-only or other unexpected files, missing required
files, internal paths or wording in shipped text, and an oversized bundle.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import zipfile
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent


def load_manifest(root: Path = SKILL_ROOT) -> dict:
    return json.loads((root / "PUBLIC_BUNDLE.json").read_text(encoding="utf-8"))


def build(out: Path, root: Path = SKILL_ROOT) -> None:
    m = load_manifest(root)
    if out.exists():
        raise SystemExit("refusing to build into existing path %s" % out)
    for rel in m["files"]:
        dest = out / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / rel, dest)


def _read_bundle(path: Path) -> dict[str, bytes]:
    if path.is_dir():
        return {p.relative_to(path).as_posix(): p.read_bytes() for p in sorted(path.rglob("*")) if p.is_file()}
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            return {i.filename: z.read(i) for i in z.infolist() if not i.is_dir()}
    raise ValueError("%s is neither a directory nor a zip file" % path)


def check(bundle: Path, root: Path = SKILL_ROOT) -> list[str]:
    """Return a list of failures (empty = PASS)."""
    m = load_manifest(root)
    try:
        files = _read_bundle(bundle)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        return ["cannot read bundle: %s" % exc]
    errs: list[str] = []
    allowed = set(m["files"])
    for name in sorted(files):
        for pat in m["forbidden_path_patterns"]:
            if pat in name:
                errs.append("forbidden file (%s): %s" % (pat, name))
                break
        else:
            if name in m["repository_only"] or any(r.endswith("/") and name.startswith(r) for r in m["repository_only"]):
                errs.append("repository-only file in bundle: %s" % name)
            elif name not in allowed:
                errs.append("unexpected file: %s" % name)
    for name in sorted(allowed - set(files)):
        errs.append("missing required file: %s" % name)
    for name, data in sorted(files.items()):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            errs.append("non-text file: %s" % name)
            continue
        for needle in m["forbidden_text"]:
            if needle in text:
                errs.append("internal/forbidden text %r in %s" % (needle, name))
    total = sum(len(d) for d in files.values())
    if total > m["max_total_bytes"]:
        errs.append("bundle too large: %d > %d bytes" % (total, m["max_total_bytes"]))
    return errs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("bundle", nargs="?")
    ap.add_argument("--build", metavar="OUT_DIR")
    a = ap.parse_args(argv)
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
    files = _read_bundle(Path(a.bundle))
    print("BUNDLE PASS: %d files, %d bytes" % (len(files), sum(map(len, files.values()))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
