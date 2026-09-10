#!/usr/bin/env python3
"""Canonical form/digest for the casa1-oracle api-completeness report.

The report carries exactly one volatile top-level field, `generated_at`,
written when the report is generated. Every other field is produced from
BTreeMap-backed state and serialises deterministically, so canonicalization
drops `generated_at` and re-serialises the JSON with sorted keys and compact
separators.

Usage:
    python3 ci/canonical_api_report.py <report.json>          # canonical sha256
    python3 ci/canonical_api_report.py --hash <report.json>   # canonical sha256
    python3 ci/canonical_api_report.py --json <report.json>   # canonical JSON

Exit status is non-zero (message on stderr) if the report cannot be parsed or
is not a JSON object.
"""

from __future__ import annotations

import hashlib
import json
import sys

VOLATILE_TOP_LEVEL_FIELDS = ("generated_at",)


def canonical_bytes(report_path: str) -> bytes:
    with open(report_path, "rb") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{report_path} is not a JSON object")
    for field in VOLATILE_TOP_LEVEL_FIELDS:
        data.pop(field, None)
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def main(argv: list[str]) -> int:
    args = list(argv)
    if args and args[0] in ("-h", "--help"):
        print(
            "usage: canonical_api_report.py [--hash|--json] <report.json>",
            file=sys.stdout,
        )
        return 0
    mode = "--hash"
    if args and args[0] in ("--hash", "--json"):
        mode = args.pop(0)
    if len(args) != 1:
        print(
            "usage: canonical_api_report.py [--hash|--json] <report.json>",
            file=sys.stderr,
        )
        return 2
    try:
        canonical = canonical_bytes(args[0])
    except Exception as exc:  # noqa: BLE001 - CLI must report any parse failure
        print(f"!! cannot canonicalize {args[0]}: {exc}", file=sys.stderr)
        return 1
    if mode == "--json":
        try:
            sys.stdout.write(canonical.decode("utf-8"))
            sys.stdout.flush()
        except BrokenPipeError:
            return 0
    else:
        print(hashlib.sha256(canonical).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
