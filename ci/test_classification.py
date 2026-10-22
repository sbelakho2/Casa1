#!/usr/bin/env python3
"""Classify Casa1 tests and record each test's pinned expectation.

Rules:
- A test is ADVERSARIAL only if it exercises a failure/edge condition (name
  keyword or error-status tokens) AND pins an exact expectation:
  assert_eq!/assert_ne!/assert_matches!, an exact panic message, or an exact
  error/status comparison.
- A test with failure signals but no pinned expectation is VAGUE: it is not
  run by sanctioned tooling, because its outcome is not precisely known.
- Everything else is HAPPY-PATH and is not run.

Outputs (with --write):
  ci/adversarial-tests.txt   names that may run
  ci/happy-path-tests.txt    success-path tests (not run)
  ci/vague-tests.txt         failure-ish but unpinned (not run)
  ci/expectations.json       test name -> exact expected assertions

`--check` regenerates in memory and fails if the checked-in files are stale.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

TEST_ATTR = re.compile(
    r"(?P<attrs>(?:^[ \t]*#\[[^\n]*\][^\n]*\n)*)"
    r"^[ \t]*#\[test\][^\n]*\n"
    r"(?P<post>(?:[ \t]*#\[[^\n]*\][^\n]*\n)*)"
    r"[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?fn[ \t]+(?P<name>\w+)",
    re.MULTILINE,
)

ADVERSARIAL_NAME = re.compile(
    r"invalid|reject|missing|malformed|error|fail|wrong|double|overflow|timeout|"
    r"busy|cancel|deny|forbid|unsupported|mismatch|corrupt|truncat|abort|stale|"
    r"race|deadlock|exhaust|leak|panic|bad|illegal|closed|evict|loss|drop|"
    r"out_of_order|duplicate|unavailable|fallback|fuzz|tamper|garbage|negative|"
    r"edge|boundary|adversarial|stress|churn|never_crashes|no_races|overlap|concurren|parallel|slice|barrier|worker|pump|migration|race",
    re.IGNORECASE,
)

ERROR_ASSERT = re.compile(
    r"unwrap_err|expect_err|is_err\s*\(|Err\s*\(|E_INVALIDARG|E_FAIL|E_POINTER|"
    r"E_NOINTERFACE|E_OUTOFMEMORY|E_ACCESSDENIED|E_ILLEGAL|AUDCLNT_E_|MF_E_|"
    r"DPNERR_|WINCODEC_ERR|STG_E_|TYPE_E_|RPC_S_|XACTENGINE_E_|HRESULT_FROM_WIN32|"
    r"STATUS_[A-Z_]+|ERROR_[A-Z_]+|NERR_[A-Z_]+|MK_E_|CO_E_|REGDB_E_|"
    r"assert!\s*\([^)]*!\s*\w+"
)

PIN_CALLS = ("assert_eq!", "assert_ne!", "assert_matches!")
SHOULD_PANIC = re.compile(r'should_panic\s*\(\s*expected\s*=\s*"([^"]+)"')

# Tests that shell out to cargo re-trigger builds inside a test; never run them
# from the sanctioned runner (they duplicate compute).
META_TEST = re.compile(r'Command::new\(\s*"cargo"\s*\)|cargo test|--list', re.MULTILINE)


def source_files() -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    files.extend(sorted((ROOT / "src").rglob("*.rs")))
    files.extend(sorted((ROOT / "tests").glob("*.rs")))
    return [path for path in files if "target" not in path.parts]


def extract_call(text: str, start: int) -> str:
    """Return the balanced macro/function call text beginning at `start`."""
    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return re.sub(r"\s+", " ", text[start : index + 1]).strip()
    return re.sub(r"\s+", " ", text[start:]).strip()


def pinned_expectations(header: str, body: str) -> list[str]:
    expectations: list[str] = []
    panic = SHOULD_PANIC.search(header)
    if panic:
        expectations.append(f'should_panic(expected = "{panic.group(1)}")')
    for name in PIN_CALLS:
        position = 0
        while True:
            found = body.find(name, position)
            if found == -1:
                break
            opening = body.find("(", found)
            if opening == -1:
                break
            expectations.append(extract_call(body, opening))
            position = found + len(name)
            if len(expectations) >= 6:
                return expectations
    # Exact status/error equality written as assert!(x == STATUS_...) is also a
    # pinned expectation.
    for match in re.finditer(
        r"assert!\(\s*[^;]*?(STATUS_[A-Z_]+|ERROR_[A-Z_]+|E_[A-Z_]+|AUDCLNT_E_[A-Z_]+|"
        r"MF_E_[A-Z_]+|DPNERR_[A-Z_]+|WINCODEC_ERR_[A-Z_]+)[^;]*?\)",
        body,
    ):
        expectations.append(re.sub(r"\s+", " ", match.group(0)).strip())
    return expectations


def evidence_anchor_names() -> set[str]:
    coverage = ROOT / "src" / "api_coverage.rs"
    if not coverage.is_file():
        return set()
    suites = re.findall(r"casa1-conformance:([A-Za-z0-9_:]+)", coverage.read_text(encoding="utf-8"))
    return {suite.rsplit(":", 1)[-1] for suite in suites}


def classify_file(path: pathlib.Path) -> tuple[dict[str, list[str]], set[str], set[str], set[str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    matches = list(TEST_ATTR.finditer(text))
    adversarial: dict[str, list[str]] = {}
    happy: set[str] = set()
    vague: set[str] = set()
    meta: set[str] = set()
    for index, match in enumerate(matches):
        name = match.group("name")
        body_end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        body = text[match.end() : body_end]
        header = match.group("attrs") + match.group("post")
        expectations = pinned_expectations(header, body)
        if META_TEST.search(body):
            meta.add(name)
            continue
        failure_signal = bool(ADVERSARIAL_NAME.search(name) or ERROR_ASSERT.search(body))
        if not failure_signal:
            happy.add(name)
        elif not expectations:
            vague.add(name)
        else:
            adversarial[name] = expectations
    return adversarial, happy, vague, meta


def gather() -> tuple[dict[str, list[str]], set[str], set[str], set[str], set[str]]:
    adversarial: dict[str, list[str]] = {}
    happy: set[str] = set()
    vague: set[str] = set()
    meta: set[str] = set()
    for path in source_files():
        bad, good, weak, special = classify_file(path)
        for name, expectations in bad.items():
            adversarial.setdefault(name, [])
            for expectation in expectations:
                if expectation not in adversarial[name]:
                    adversarial[name].append(expectation)
        happy |= good
        vague |= weak
        meta |= special
    anchors = evidence_anchor_names()
    anchor_tests = (happy | vague) & anchors
    happy -= set(adversarial) | anchor_tests
    vague -= set(adversarial) | anchor_tests
    meta -= set(adversarial)
    return adversarial, happy, vague, meta, anchor_tests


def manifest_paths() -> dict[str, pathlib.Path]:
    directory = ROOT / "ci"
    return {
        "adversarial": directory / "adversarial-tests.txt",
        "happy": directory / "happy-path-tests.txt",
        "vague": directory / "vague-tests.txt",
        "meta": directory / "meta-tests.txt",
        "anchors": directory / "evidence-anchors.txt",
        "expectations": directory / "expectations.json",
    }


def render(
    adversarial: dict[str, list[str]],
    happy: set[str],
    vague: set[str],
    meta: set[str],
    anchors: set[str],
) -> dict[str, str]:
    def listing(items: set[str]) -> str:
        return "\n".join(sorted(items)) + ("\n" if items else "")

    return {
        "adversarial": listing(set(adversarial)),
        "happy": listing(happy),
        "vague": listing(vague),
        "meta": listing(meta),
        "anchors": listing(anchors),
        "expectations": json.dumps(
            {name: expectations for name, expectations in sorted(adversarial.items())},
            indent=1,
            sort_keys=True,
        )
        + "\n",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true",
                        help="fail when checked-in manifests are stale")
    args = parser.parse_args()

    adversarial, happy, vague, meta, anchors = gather()
    total = len(adversarial) + len(happy) + len(vague) + len(meta) + len(anchors)
    print(f"adversarial (pinned, run): {len(adversarial)}")
    print(f"happy-path (quarantined): {len(happy)}")
    print(f"vague (unpinned, not run): {len(vague)}")
    print(f"meta/cargo-invoking (not run): {len(meta)}")
    print(f"evidence anchors (compiled, not run): {len(anchors)}")
    if total:
        print(f"adversarial share: {len(adversarial) / total:.1%}")

    rendered = render(adversarial, happy, vague, meta, anchors)
    paths = manifest_paths()
    if args.write:
        for key, path in paths.items():
            path.write_text(rendered[key], encoding="utf-8")
        print("wrote " + ", ".join(str(path.relative_to(ROOT)) for path in paths.values()))
    if args.check:
        stale = [
            str(path.relative_to(ROOT))
            for key, path in paths.items()
            if not path.is_file() or path.read_text(encoding="utf-8") != rendered[key]
        ]
        if stale:
            print("stale manifests: " + ", ".join(stale))
            print("run: python3 ci/test_classification.py --write")
            return 1
        print("manifests up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
