#!/usr/bin/env python3
"""
Replace brittle test assertions (assert!(result.is_ok()), assert!(result.is_err()))
with informative assertions that show actual values on failure.

Safety:
  * By default this runs in --dry-run mode: diffs are printed and NO file is
    modified.  Pass --write to write changes back.
  * Only tests/ files are rewritten.  Production code (src/) is never touched.
  * Keyword/type-name receivers (self, Self, Some, None, Ok, Err, Result, ...)
    are excluded so the generated format string `{ident:?}` always names a real
    binding (format!("{self:?}") is a compile error, E0424).
  * Method-call rewrites introduce a `let` binding, which is only valid in
    statement position.  They are therefore restricted to asserts that start
    a line and end a line, and the argument list is scanned with a balanced-
    paren parser (skipping string/char literals) instead of a fragile [^)]*
    regex.
  * When --write is used, originals are backed up; after rewriting,
    `cargo check --tests` is run to verify the tree still compiles and the
    backups are restored if verification fails (--no-verify to skip).

Usage:
  python3 fix_brittle_asserts.py [--write] [--no-verify] [--quiet]
"""

import argparse
import difflib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

# Receivers that are keywords, type names, or enum variants.  They can never
# be referenced as `{ident:?}` in a format string (or are not bindings at all).
KEYWORD_RECEIVERS = frozenset(
    (
        "self", "Self", "Some", "None", "Ok", "Err", "Result",
        "crate", "super", "fn", "let", "mut", "const", "static",
        "enum", "struct", "trait", "impl", "mod", "use", "pub",
        "match", "if", "else", "while", "for", "loop", "return",
        "break", "continue", "true", "false", "as", "async", "await",
        "in", "move", "ref", "type", "unsafe", "where", "dyn", "extern",
    )
)

# assert!(<ident>.is_ok()) / assert!(<ident>.is_err()) with a simple
# identifier receiver.  The replacement is still an expression, so this is
# valid in any position; keyword receivers are rejected by the replacer.
SIMPLE_RECEIVER = re.compile(
    r"assert!\(([a-zA-Z_][a-zA-Z0-9_]*)\.is_(ok|err)\(\)\)"
)

# arg of assert!(<receiver>.<method>(<args>).is_ok()) — exactly one
# method call on a simple identifier receiver, with balanced args.
METHOD_CALL_ARG = re.compile(
    r"^([a-zA-Z_][a-zA-Z0-9_]*)\.([a-zA-Z_][a-zA-Z0-9_]*)\((.*)\)\.is_(ok|err)\(\)$",
    re.DOTALL,
)


def find_test_files():
    test_files = []
    for root, dirs, files in os.walk(REPO_ROOT / "tests"):
        for f in files:
            if f.endswith(".rs"):
                test_files.append(Path(root) / f)
    return sorted(test_files)


def rewrite_simple(content):
    """Replace assert!(ident.is_ok()) / assert!(ident.is_err()) with an
    informative variant.  Returns (new_content, count)."""

    def repl(match):
        ident = match.group(1)
        if ident in KEYWORD_RECEIVERS:
            return match.group(0)
        verb = match.group(2)
        expected = "Ok" if verb == "ok" else "Err"
        return 'assert!({0}.is_{1}(), "expected {2}, got {{{0}:?}}")'.format(
            ident, verb, expected
        )

    new_content = SIMPLE_RECEIVER.sub(repl, content)
    count = sum(
        1
        for m in SIMPLE_RECEIVER.finditer(content)
        if m.group(1) not in KEYWORD_RECEIVERS
    )
    return new_content, count


def skip_literals(content, i):
    """Advance past a string or char literal at i (which is a quote char).
    Returns the index just after the literal, or the original index if the
    literal never closes."""
    quote = content[i]
    j = i + 1
    while j < len(content):
        if content[j] == "\\":
            j += 2
            continue
        if content[j] == quote:
            return j + 1
        j += 1
    return i


def find_matching_paren(content, start):
    """Return the index of the paren matching the one at `start`, skipping
    string/char literals.  Returns -1 if unbalanced."""
    depth = 0
    i = start
    while i < len(content):
        ch = content[i]
        if ch in ('"', "'"):
            i = skip_literals(content, i)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def is_balanced_parens(text):
    """True if parens in text are balanced left-to-right, ignoring parens
    inside string/char literals."""
    depth = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if ch in ('"', "'"):
            i = skip_literals(text, i)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return False
        i += 1
    return depth == 0


def rewrite_method_calls(content):
    """Replace assert!(receiver.method(args).is_ok()) and the .is_err()
    variant, but only when the assert is in statement position (starts a
    line, ends a line) so the introduced `let` binding is valid.
    Returns (new_content, count)."""
    pieces = []
    pos = 0
    count = 0

    while True:
        search_from = pos
        m = None
        while True:
            m = re.search(r"assert!\(", content[search_from:])
            if m is None:
                break
            abs_start = search_from + m.start()
            line_start = content.rfind("\n", 0, abs_start) + 1
            if content[line_start:abs_start].strip() == "":
                break
            search_from = abs_start + 1
        if m is None:
            pieces.append(content[pos:])
            break

        abs_start = search_from + m.start()
        open_paren = abs_start + m.end() - m.start() - 1
        close_paren = find_matching_paren(content, open_paren)
        if close_paren == -1:
            pieces.append(content[pos : abs_start + 1])
            pos = abs_start + 1
            continue

        # The assert must be the whole statement: only whitespace (and an
        # optional trailing ';') may follow on the closing line.
        line_end = content.find("\n", close_paren)
        if line_end == -1:
            line_end = len(content)
        tail = content[close_paren + 1 : line_end]
        if not re.fullmatch(r"[ \t]*;?[ \t]*", tail):
            pieces.append(content[pos : abs_start + 1])
            pos = abs_start + 1
            continue

        arg = content[open_paren + 1 : close_paren]
        call = METHOD_CALL_ARG.match(arg)
        if call is None or not is_balanced_parens(call.group(3)):
            pieces.append(content[pos : abs_start + 1])
            pos = abs_start + 1
            continue

        receiver = call.group(1)
        if receiver in KEYWORD_RECEIVERS:
            pieces.append(content[pos : abs_start + 1])
            pos = abs_start + 1
            continue

        # Reconstruct the method-call expression exactly (group(0) also
        # includes the trailing .is_ok()/.is_err() which must be dropped).
        expr = "{}.{}({})".format(
            call.group(1), call.group(2), call.group(3)
        )
        indent = content[line_start:abs_start]
        var = "_result"
        while var in content:
            var += "_"
        verb = call.group(4)
        expected = "Ok" if verb == "ok" else "Err"
        replacement = (
            "{indent}let {var} = {expr};\n"
            "{indent}assert!({var}.is_{verb}(), "
            '"expected {expected}, got {{{var}:?}}")'
        ).format(
            indent=indent, var=var, expr=expr, verb=verb, expected=expected
        )

        pieces.append(content[pos:line_start])
        pieces.append(replacement)
        pieces.append(content[close_paren + 1 : line_end])
        pieces.append("\n")
        pos = line_end + 1
        count += 1

    return "".join(pieces), count


def diff(original, rewritten, filepath):
    return "\n".join(
        difflib.unified_diff(
            original.splitlines(),
            rewritten.splitlines(),
            fromfile=f"{filepath} (before)",
            tofile=f"{filepath} (after)",
            lineterm="",
        )
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--write",
        action="store_true",
        help="write changes back to files (default is dry-run only)",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="skip the cargo check --tests verification after --write",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="only print summaries (no per-file output)",
    )
    args = parser.parse_args()

    all_files = find_test_files()
    if not all_files:
        print("No tests/ files found to process.")
        return 0

    if not args.quiet:
        print(f"Processing {len(all_files)} files...")

    total_replacements = 0
    changed = []

    for filepath in all_files:
        original = filepath.read_text()
        content, n1 = rewrite_simple(original)
        content, n2 = rewrite_method_calls(content)
        n = n1 + n2

        if content == original:
            continue
        total_replacements += n
        changed.append((filepath, original, content))
        if args.quiet:
            continue
        print(f"  {filepath}: {n} replacement(s)")
        if not args.write:
            print(diff(original, content, filepath))

    if not changed:
        print("\nNo brittle assertions found.")
        return 0

    if not args.write:
        print(
            f"\n{total_replacements} replacement(s) in {len(changed)} file(s) "
            "(dry run — re-run with --write to apply)."
        )
        return 0

    backup_dir = Path(tempfile.mkdtemp(prefix="casa1-brittle-asserts-"))
    try:
        for filepath, original, _ in changed:
            (backup_dir / filepath.name).write_text(original)
        for filepath, _, content in changed:
            filepath.write_text(content)

        if not args.no_verify:
            if not args.quiet:
                print("\nVerifying with `cargo check --tests` ...")
            result = subprocess.run(
                ["cargo", "check", "--tests"],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                for filepath, original, _ in changed:
                    filepath.write_text(original)
                print(
                    "\n!! cargo check --tests failed after rewriting; "
                    "all changes were restored (use --no-verify to skip "
                    "verification if the tree was already broken).",
                    file=sys.stderr,
                )
                print(result.stdout[-4000:], file=sys.stderr)
                print(result.stderr[-4000:], file=sys.stderr)
                return 1
            if not args.quiet:
                print("Verification passed — rewritten files still compile.")

        print(
            f"\nApplied {total_replacements} replacement(s) in "
            f"{len(changed)} file(s)."
        )
        return 0
    finally:
        shutil.rmtree(backup_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
