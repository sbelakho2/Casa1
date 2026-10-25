#!/usr/bin/env python3
"""Fold commit-bound api-report provenance into release-evidence.json.

The CI workflow uploads `api-completeness-<sha>` (report + provenance sidecar)
for the exact commit. This helper binds that evidence into the release
evidence record, keeping ci/check_release_gate.sh checks satisfied:

  * `api_report`                     basename of the report in the evidence dir
  * `api_report_sha256`              sha256 of the report bytes
  * `api_report_canonical_sha256`    sha256 of the report's canonical form
  * `api_report_provenance`          the full sidecar content (inline object)
  * `api_report_provenance_sha256`   sha256 of the canonical inline provenance
  * `tree`                           HEAD tree hash recorded by the sidecar
  * `api_report_ci_run_id/url`       optional CI run that produced the artifact
  * `test_manifest`                  basename of the compiled test manifest
  * `test_manifest_sha256`           sha256 of the manifest bytes
  * `test_manifest_canonical_sha256` canonical manifest digest (the manifest
                                     hash recorded inside the document)

The outer evidence file and, when given, its embedded peer copy are written
with identical bytes (the release gate requires them byte-identical).

Usage:
    python3 ci/fold_api_report_provenance.py \
        --evidence e2e-evidence/release-evidence.json \
        --peer e2e-evidence/steam-e2e-evidence/release-evidence.json \
        --report e2e-evidence/api-completeness.json \
        --provenance e2e-evidence/api-completeness.json.provenance.json \
        --test-manifest e2e-evidence/test-manifest.json \
        [--ci-run-id <id>] [--ci-run-url <url>]

Fails closed (non-zero, message on stderr) on any missing file, parse error,
hash mismatch, stale/unbound manifest, or cross-file commit/tree disagreement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys

CI_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(CI_DIR)
sys.path.insert(0, CI_DIR)

from evidence_manifest import manifest_digest, verify_document  # noqa: E402

REQUIRED_PROVENANCE_FIELDS = (
    "commit",
    "tree",
    "report",
    "report_sha256",
    "canonical_report_sha256",
)


def fail(message: str) -> None:
    print(f"!! {message}", file=sys.stderr)


def sha256_file(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Fold commit-bound api-report provenance into release-evidence.json"
    )
    parser.add_argument("--evidence", required=True, help="release-evidence.json to update")
    parser.add_argument("--peer", default="", help="embedded copy that must stay byte-identical")
    parser.add_argument("--report", required=True, help="api-completeness.json from CI")
    parser.add_argument("--provenance", required=True, help="provenance sidecar from CI")
    parser.add_argument(
        "--test-manifest",
        required=True,
        help="compiled test manifest from the CI test job",
    )
    parser.add_argument("--ci-run-id", default="", help="CI run id that produced the artifact")
    parser.add_argument("--ci-run-url", default="", help="CI run URL for the record")
    args = parser.parse_args(argv)

    for path in (args.evidence, args.report, args.provenance, args.test_manifest):
        if not os.path.isfile(path):
            fail(f"required file not found: {path}")
            return 1
    if args.peer and not os.path.isfile(args.peer):
        fail(f"peer evidence copy not found: {args.peer}")
        return 1

    try:
        with open(args.provenance, encoding="utf-8") as handle:
            provenance = json.load(handle)
    except Exception as exc:  # noqa: BLE001 - CLI must report parse failures
        fail(f"cannot parse provenance {args.provenance}: {exc}")
        return 1
    if not isinstance(provenance, dict):
        fail(f"provenance is not a JSON object: {args.provenance}")
        return 1
    missing = [f for f in REQUIRED_PROVENANCE_FIELDS if not provenance.get(f)]
    if missing:
        fail(f"provenance is missing required fields: {', '.join(missing)}")
        return 1
    if provenance.get("determinism", {}).get("reproducible") is not True:
        fail("provenance does not attest reproducibility (determinism.reproducible is not true)")
        return 1

    report_sha = sha256_file(args.report)
    if report_sha != provenance["report_sha256"]:
        fail(
            "report sha256 mismatch: provenance records "
            f"{provenance['report_sha256']}, {args.report} yields {report_sha}"
        )
        return 1

    canonicalizer = os.path.join(os.path.dirname(os.path.abspath(__file__)), "canonical_api_report.py")
    proc = subprocess.run(
        [sys.executable, canonicalizer, args.report],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        fail(f"cannot canonicalize report {args.report}: {proc.stderr.strip()}")
        return 1
    canonical_sha = proc.stdout.strip()
    if canonical_sha != provenance["canonical_report_sha256"]:
        fail(
            "canonical report sha256 mismatch: provenance records "
            f"{provenance['canonical_report_sha256']}, recomputation yields {canonical_sha}"
        )
        return 1

    try:
        with open(args.evidence, encoding="utf-8") as handle:
            evidence = json.load(handle)
    except Exception as exc:  # noqa: BLE001 - CLI must report parse failures
        fail(f"cannot parse evidence {args.evidence}: {exc}")
        return 1
    if not isinstance(evidence, dict):
        fail(f"evidence is not a JSON object: {args.evidence}")
        return 1

    evidence_commit = evidence.get("commit", "")
    if evidence_commit and evidence_commit != provenance["commit"]:
        fail(
            f"evidence commit ({evidence_commit}) does not match provenance commit "
            f"({provenance['commit']})"
        )
        return 1
    evidence_tree = evidence.get("tree", "")
    if evidence_tree and evidence_tree != provenance["tree"]:
        fail(
            f"evidence tree ({evidence_tree}) does not match provenance tree "
            f"({provenance['tree']})"
        )
        return 1

    try:
        with open(args.test_manifest, encoding="utf-8") as handle:
            test_manifest = json.load(handle)
    except Exception as exc:  # noqa: BLE001 - CLI must report parse failures
        fail(f"cannot parse test manifest {args.test_manifest}: {exc}")
        return 1
    manifest_errors = verify_document(test_manifest, require_head=True)
    if manifest_errors:
        for error in manifest_errors:
            fail(f"test manifest: {error}")
        return 1
    if test_manifest.get("commit") != provenance["commit"]:
        fail(
            f"test manifest commit ({test_manifest.get('commit')}) does not match "
            f"provenance commit ({provenance['commit']})"
        )
        return 1
    if test_manifest.get("tree") != provenance["tree"]:
        fail(
            f"test manifest tree ({test_manifest.get('tree')}) does not match "
            f"provenance tree ({provenance['tree']})"
        )
        return 1
    test_manifest_sha = sha256_file(args.test_manifest)
    test_manifest_digest = manifest_digest(test_manifest)

    inline_provenance = json.loads(canonical_json(provenance))
    evidence["api_report"] = os.path.basename(args.report)
    evidence["api_report_sha256"] = report_sha
    evidence["api_report_canonical_sha256"] = canonical_sha
    evidence["api_report_provenance"] = inline_provenance
    evidence["api_report_provenance_sha256"] = hashlib.sha256(
        canonical_json(inline_provenance).encode("utf-8")
    ).hexdigest()
    evidence["test_manifest"] = os.path.basename(args.test_manifest)
    evidence["test_manifest_sha256"] = test_manifest_sha
    evidence["test_manifest_canonical_sha256"] = test_manifest_digest
    evidence["tree"] = provenance["tree"]
    if args.ci_run_id:
        evidence["api_report_ci_run_id"] = args.ci_run_id
    if args.ci_run_url:
        evidence["api_report_ci_run_url"] = args.ci_run_url

    payload = json.dumps(evidence, indent=2).encode("utf-8")
    for path in (args.evidence, args.peer):
        if not path:
            continue
        with open(path, "wb") as handle:
            handle.write(payload)

    if args.peer:
        with open(args.evidence, "rb") as lhs, open(args.peer, "rb") as rhs:
            if lhs.read() != rhs.read():
                fail(f"folded evidence differs between {args.evidence} and {args.peer}")
                return 1

    print(
        "api-report provenance + test manifest folded: "
        f"commit={provenance['commit']} tree={provenance['tree']} "
        f"report_sha256={report_sha} canonical={canonical_sha} "
        f"test_manifest_sha256={test_manifest_sha} "
        f"test_manifest_canonical={test_manifest_digest}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
