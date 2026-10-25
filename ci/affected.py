#!/usr/bin/env python3
"""Affected-code selection for Casa1 tests.

Maps changed Rust files to test-name prefixes so only tests that exercise
changed code run ("no cold code"). This is a static approximation: a changed
module selects adversarial tests living in that module (plus its parent
``mod.rs`` changes). Root-level files (lib.rs/main.rs) affect everything.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _git(*args: str) -> list[str]:
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def default_base() -> str:
    explicit = os.environ.get("CASA1_BASE_REF")
    if explicit:
        return explicit
    # A dirty worktree is measured against HEAD (only the pending change is
    # affected). A clean checkout is measured against the branch base.
    if _git("status", "--porcelain"):
        return "HEAD"
    for candidate in ("origin/main", "origin/master", "main"):
        if _git("rev-parse", "--verify", "--quiet", candidate):
            return candidate
    return "HEAD"


def changed_rs_files(base: str | None = None) -> list[pathlib.Path]:
    base = base or default_base()
    # Fail closed: an unresolvable base must never silently select no tests.
    verified = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", base],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if verified.returncode != 0:
        print(
            f"::error::affected-test base {base!r} cannot be resolved; "
            "fetch the base history or pass --base <commit>",
            file=sys.stderr,
        )
        raise SystemExit(1)
    tracked = set(_git("diff", "--name-only", base))
    tracked |= set(_git("diff", "--name-only", "HEAD"))
    untracked = set(_git("ls-files", "--others", "--exclude-standard"))
    files: list[pathlib.Path] = []
    for raw in sorted(tracked | untracked):
        if not raw.endswith(".rs"):
            continue
        path = ROOT / raw
        if path.is_file():
            files.append(path)
    return files


def _src_module_prefix(path: pathlib.Path) -> str:
    relative = path.relative_to(ROOT)
    parts = list(relative.with_suffix("").parts)
    if parts and parts[0] == "src":
        parts = parts[1:]
    if parts and parts[-1] in ("lib", "main"):
        return ""  # crate root change: every test may be affected
    if parts and parts[-1] == "mod":
        parts = parts[:-1]
    return "::".join(parts)


def affected_prefixes(files: list[pathlib.Path]) -> tuple[set[str], set[str]]:
    """Return (module prefixes, changed integration-test target stems)."""
    prefixes: set[str] = set()
    test_targets: set[str] = set()
    for path in files:
        relative = path.relative_to(ROOT)
        if relative.parts and relative.parts[0] == "tests":
            test_targets.add(path.stem)
        elif relative.parts and relative.parts[0] == "src":
            prefixes.add(_src_module_prefix(path))
    return prefixes, test_targets


def name_matches(name: str, prefixes: set[str]) -> bool:
    if "" in prefixes:
        return True
    return any(name == prefix or name.startswith(prefix + "::") for prefix in prefixes)


def describe(files: list[pathlib.Path]) -> str:
    prefixes, targets = affected_prefixes(files)
    parts = []
    if prefixes:
        parts.append("modules: " + ", ".join(sorted(p or "<crate>" for p in prefixes)))
    if targets:
        parts.append("test targets: " + ", ".join(sorted(targets)))
    return "; ".join(parts) if parts else "no affected Rust files"


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else None
    files = changed_rs_files(base)
    prefixes, targets = affected_prefixes(files)
    print(f"affected files: {len(files)}")
    for path in files:
        print(f"  {path.relative_to(ROOT)}")
    print(describe(files))
    for prefix in sorted(prefixes):
        print(f"prefix: {prefix!r}")
    for target in sorted(targets):
        print(f"test-target: {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
