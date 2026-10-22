#!/usr/bin/env python3
"""Delete every happy-path test from the Casa1 sources.

Happy-path tests (classified by ci/test_classification.py) are removed outright:
they must not exist in the test suite, CI, or the quarantined surface. Tests
that are load-bearing conformance evidence anchors are kept (the API gate binds
to them) and reported separately.

Usage: ci/delete_happy_paths.py [--dry-run]
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "ci"))

from test_classification import TEST_ATTR, classify_file, evidence_anchor_names, source_files  # noqa: E402


def scan_brace(text: str, start: int) -> int | None:
    depth = 0
    index = start
    in_string = False
    in_char = False
    in_line = False
    in_block = False
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if in_line:
            if char == "\n":
                in_line = False
        elif in_block:
            if char == "*" and nxt == "/":
                in_block = False
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
                in_line = True
                index += 1
            elif char == "/" and nxt == "*":
                in_block = True
                index += 1
            elif char == '"':
                in_string = True
            elif char == "'" and nxt not in (" ", "\\"):
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


def delete_file(path: pathlib.Path, anchors: set[str], dry_run: bool) -> tuple[int, int]:
    text = path.read_text(encoding="utf-8", errors="replace")
    matches = list(TEST_ATTR.finditer(text))
    _, happy, _, _ = classify_file(path)
    doomed = [name for name in happy if name not in anchors]
    if not doomed:
        return (0, 0)

    deletions: list[tuple[int, int]] = []
    for index, match in enumerate(matches):
        name = match.group("name")
        if name not in doomed:
            continue
        brace = text.find("{", match.end())
        if brace == -1:
            continue
        end = scan_brace(text, brace)
        if end is None:
            continue
        # Remove the whole item including its attributes and trailing newline.
        start = match.start()
        while start > 0 and text[start - 1] in " \t":
            start -= 1
        end += 1
        while end < len(text) and text[end] in " \t":
            end += 1
        if end < len(text) and text[end] == "\n":
            end += 1
        deletions.append((start, end))

    if dry_run:
        return (len(deletions), len(doomed))

    for start, end in sorted(deletions, reverse=True):
        text = text[:start] + text[end:]
    path.write_text(text, encoding="utf-8")
    return (len(deletions), len(doomed))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    anchors = evidence_anchor_names()
    removed = 0
    kept = 0
    files = 0
    for path in source_files():
        deletions, doomed = delete_file(path, anchors, args.dry_run)
        if deletions:
            files += 1
            removed += deletions
        kept += doomed - deletions
    verb = "would delete" if args.dry_run else "deleted"
    print(f"{verb} {removed} happy-path tests in {files} files")
    if kept:
        print(f"kept {kept} happy-path evidence anchors (required by the API gate)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
