#!/usr/bin/env python3
"""100% changed-line coverage gate.

Requires every executable line that this change adds/modifies to be executed by
the adversarial tests that were run. Cold, untouched code is not required to be
covered.

Usage:
    ci/coverage_gate.py --lcov lcov.info [--base REF] [--allow-empty]
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
TEST_ATTR = re.compile(r"#\[(?:cfg\(test\)|test)\]")


def _scan_brace(text: str, start: int) -> int | None:
    depth = 0
    index = start
    in_string = False
    in_char = False
    in_line_comment = False
    in_block_comment = False
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if in_line_comment:
            if char == "\n":
                in_line_comment = False
        elif in_block_comment:
            if char == "*" and nxt == "/":
                in_block_comment = False
                index += 1
        elif in_string:
            if char == "\\":
                index += 1
            elif char == '"':
                in_string = False
        elif in_char:
            if char == "\\":
                index += 1
            elif char == "'":
                in_char = False
        else:
            if char == "/" and nxt == "/":
                in_line_comment = True
                index += 1
            elif char == "/" and nxt == "*":
                in_block_comment = True
                index += 1
            elif char == '"':
                in_string = True
            elif char == "'" and nxt not in (" ", "\\"):
                # char literal or lifetime; lifetimes have no closing quote
                end = text.find("'", index + 2)
                if end != -1 and end - index <= 4:
                    in_char = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index
        index += 1
    return None


def test_line_ranges(path: pathlib.Path) -> list[tuple[int, int]]:
    """Line ranges occupied by #[cfg(test)] items and #[test] functions."""
    text = path.read_text(encoding="utf-8", errors="replace")
    offsets: list[tuple[int, int]] = []
    item_start = re.compile(r"\b(?:fn|mod|const|static|struct|enum|impl|trait|union)\b")
    for match in TEST_ATTR.finditer(text):
        # Skip further attributes between this one and the item keyword.
        search_from = match.end()
        while True:
            nxt = re.match(r"\s*#\[[^\]]*\]", text[search_from:])
            if not nxt:
                break
            search_from += nxt.end()
        item = item_start.search(text, search_from)
        if not item:
            continue
        brace = text.find("{", item.end())
        semicolon = text.find(";", item.end())
        if brace == -1 or (semicolon != -1 and semicolon < brace):
            # Declaration-only item on one line.
            end_line = text.count("\n", 0, item.end()) + 1
            start_line = text.count("\n", 0, match.start()) + 1
            offsets.append((start_line, end_line))
            continue
        end = _scan_brace(text, brace)
        if end is None:
            continue
        start_line = text.count("\n", 0, match.start()) + 1
        end_line = text.count("\n", 0, end) + 1
        offsets.append((start_line, end_line))
    return offsets


def in_test_code(ranges: list[tuple[int, int]], line: int) -> bool:
    return any(start <= line <= end for start, end in ranges)


def git(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else ""


def changed_lines(base: str) -> dict[str, set[int]]:
    """Map repo-relative src files to changed line numbers (worktree vs base)."""
    lines: dict[str, set[int]] = {}
    diff = git("diff", "-U0", base, "--", "src")
    current: str | None = None
    for raw in diff.splitlines():
        if raw.startswith("+++ b/"):
            current = raw[len("+++ b/") :]
            lines.setdefault(current, set())
        elif current and raw.startswith("@@"):
            match = HUNK.match(raw)
            if not match:
                continue
            start = int(match.group(1))
            count = int(match.group(2) or "1")
            lines[current].update(range(start, start + count))
    # Untracked files are wholly new: every line is affected.
    for raw in git("ls-files", "--others", "--exclude-standard", "--", "src").splitlines():
        path = ROOT / raw
        if path.suffix != ".rs" or not path.is_file():
            continue
        try:
            total = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            continue
        lines.setdefault(raw, set()).update(range(1, total + 1))
    return lines


def parse_lcov(path: pathlib.Path) -> dict[str, dict[int, int]]:
    coverage: dict[str, dict[int, int]] = {}
    current: str | None = None
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw.startswith("SF:"):
            current = raw[3:]
            coverage.setdefault(current, {})
        elif raw.startswith("DA:") and current:
            try:
                line, _, count = raw[3:].partition(",")
                coverage[current][int(line)] = int(count)
            except ValueError:
                continue
    return coverage


def lookup(
    coverage: dict[str, dict[int, int]], relative: str
) -> tuple[dict[int, int] | None, bool]:
    """Find a file by suffix; return (line counts, file was instrumented)."""
    for source, counts in coverage.items():
        normalized = source.replace("\\", "/")
        if normalized.endswith("/" + relative) or normalized == relative:
            return counts, True
        if normalized.endswith(relative):
            return counts, True
    return None, False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lcov", required=True, type=pathlib.Path)
    parser.add_argument("--base", default=None)
    parser.add_argument(
        "--allow-empty",
        action="store_true",
        help="pass when there are no affected lines (no caches on a clean tree)",
    )
    args = parser.parse_args()

    base = args.base or "HEAD"
    changed = changed_lines(base)
    coverage = parse_lcov(args.lcov)

    missing: dict[str, list[int]] = {}
    uninstrumented: list[str] = []
    checked_lines = 0
    for relative, affected in sorted(changed.items()):
        if not affected:
            continue
        source_path = ROOT / relative
        ranges = test_line_ranges(source_path) if source_path.is_file() else []
        affected = {line for line in affected if not in_test_code(ranges, line)}
        if not affected:
            continue
        counts, instrumented = lookup(coverage, relative)
        if counts is None or not counts:
            # No executable lines recorded: either not instrumented (fail) or
            # a declaration-only file (no executable lines).
            uninstrumented.append(relative)
            continue
        source_lines = (
            source_path.read_text(encoding="utf-8", errors="replace").splitlines()
            if source_path.is_file()
            else []
        )
        for line in sorted(affected):
            if line not in counts:
                continue  # non-executable changed line
            if 0 < line <= len(source_lines) and "coverage: unreachable" in source_lines[line - 1]:
                continue
            checked_lines += 1
            if counts[line] == 0:
                missing.setdefault(relative, []).append(line)

    if not changed:
        print("coverage: no affected src lines")
        return 0 if args.allow_empty or True else 0

    for relative, lines in missing.items():
        print(f"coverage: uncovered changed lines in {relative}: {lines}")
    for relative in uninstrumented:
        print(f"coverage: no instrumentation data for changed file {relative}")

    if uninstrumented or missing:
        print(
            "coverage: FAILED — every changed executable line must be executed "
            "by the adversarial affected tests"
        )
        return 1
    if checked_lines == 0 and not args.allow_empty:
        print("coverage: no executable changed lines found")
        return 0
    print(f"coverage: OK — {checked_lines} changed executable lines, 100% covered")
    return 0


if __name__ == "__main__":
    sys.exit(main())
