#!/usr/bin/env python3
"""Bind declared coverage evidence to the ACTUALLY COMPILED test manifest.

The API database declares evidence ids of three kinds:

  * ``casa1-conformance:<suite>`` / ``casa1-scenario:<suite>``  a test file
    (integration target) or a test function that must be compiled and
    runnable;
  * ``windows-oracle:<category>``  a differential category that must exist
    in the host oracle's ``ALL_CATEGORIES``, have a real executor in the
    standalone ``windows_reference`` crate, and be required by the Windows
    capture workflow.

This tool compiles the real test targets (``cargo test --no-run
--message-format=json``), asks each compiled test executable for its test
list (``--list`` and ``--list --ignored``), and records the resulting
manifest together with a binding for every declared evidence id.  A
declaration that does not bind fails the gate.

It is deterministic (no timestamps, sorted targets/tests, no absolute
executable paths) and is suitable for CI.  It never executes a test, so the
cargo-invoking meta tests remain unrun; meta tests are also never accepted
as evidence because they do not run under the sanctioned runner.

A declared ``casa1-conformance``/``casa1-scenario`` suite or function is
strictly enforced: it must be a compiled, runnable test in the manifest.
Differential categories that the runtime's oracle actually advertises are
also enforced (present in ALL_CATEGORIES, with a reference executor, and
mandatory in the capture workflow).  Declared differential categories that
the oracle does not advertise are recorded under ``deferred_differential``
with a concrete reason (they are an API-database declaration issue, not a
compiled-test issue) and are reported as warnings; they never make this
manifest pass silently.

Usage:
    # Build + bind + write the manifest (fails on any unbound suite/function).
    python3 ci/evidence_manifest.py --write ci/test-manifest.json

    # Verify an existing manifest (no compilation): self-hash, declarations
    # from the current source tree, bindings, and HEAD/tree.
    python3 ci/evidence_manifest.py --verify ci/test-manifest.json --require-head

    # Print the canonical manifest digest (the release-provenance hash).
    python3 ci/evidence_manifest.py --print-digest ci/test-manifest.json

The manifest is also the input to ci/fold_api_report_provenance.py, which
records ``test_manifest_sha256`` and ``test_manifest_canonical_sha256`` in
release-evidence.json; ci/check_release_gate.sh verifies both.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CI_DIR = ROOT / "ci"
DEFAULT_OUTPUT = ROOT / "ci" / "test-manifest.json"

SCHEMA_VERSION = 2
KIND = "casa1-test-manifest"

COVERAGE_MARKER = "pub static COVERAGE_EVIDENCE"
TEST_SUFFIX = ": test"

# The feature set used by the central gate / release build.  The manifest must
# describe the same compiled surface the gate tests.
BUILD_FEATURES = "vulkan,opengl,websocket"


class ManifestError(RuntimeError):
    """A manifest cannot be built or verified."""


def rel_posix(path: pathlib.Path, root: pathlib.Path = ROOT) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def git_output(*args: str, root: pathlib.Path = ROOT) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ManifestError(f"cannot run git {' '.join(args)}: {exc}") from exc


def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ManifestError(f"cannot read {path}: {exc}") from exc


def coverage_block(root: pathlib.Path = ROOT) -> str:
    """Return only the COVERAGE_EVIDENCE registry body.

    Comments and self-tests elsewhere in the file mention evidence ids; they
    must never be mistaken for declarations.
    """
    text = read_text(root / "src" / "api_coverage.rs")
    start = text.find(COVERAGE_MARKER)
    if start == -1:
        raise ManifestError("src/api_coverage.rs has no COVERAGE_EVIDENCE registry")
    end = text.find("\n];", start)
    if end == -1:
        raise ManifestError("COVERAGE_EVIDENCE registry is not terminated")
    return text[start:end]


def declarations(root: pathlib.Path = ROOT) -> dict[str, list[str]]:
    """Declared evidence ids, grouped by evidence kind."""
    block = coverage_block(root)
    ids = set(re.findall(r'"(casa1-(?:conformance|scenario):[^"]+)"', block))
    ids |= set(re.findall(r'"(windows-oracle:[^"]+)"', block))
    grouped: dict[str, list[str]] = {
        "conformance": [],
        "scenario": [],
        "differential": [],
    }
    for evidence_id in sorted(ids):
        prefix = evidence_id.split(":", 1)[0]
        if prefix == "casa1-conformance":
            grouped["conformance"].append(evidence_id)
        elif prefix == "casa1-scenario":
            grouped["scenario"].append(evidence_id)
        elif prefix == "windows-oracle":
            grouped["differential"].append(evidence_id)
    return grouped


def oracle_categories(root: pathlib.Path = ROOT) -> set[str]:
    text = read_text(root / "src" / "windows_oracle.rs")
    match = re.search(
        r"pub const ALL_CATEGORIES\s*:[^=]*=\s*\[(.*?)\];", text, re.DOTALL
    )
    if match is None:
        raise ManifestError("src/windows_oracle.rs has no ALL_CATEGORIES table")
    return set(re.findall(r'"([^"]+)"', match.group(1)))


def reference_categories(root: pathlib.Path = ROOT) -> set[str]:
    text = read_text(root / "windows_reference" / "src" / "win32.rs")
    match = re.search(
        r"pub fn execute\(category: &str, input: &Value\) -> Value \{(.*?)\n\}",
        text,
        re.DOTALL,
    )
    if match is None:
        raise ManifestError("windows_reference has no category executor")
    return set(re.findall(r'"([^"]+)"\s*=>', match.group(1)))


def required_oracle_categories(root: pathlib.Path = ROOT) -> set[str]:
    """Categories the Windows capture workflow makes mandatory."""
    workflow = root / ".github" / "workflows" / "windows-oracle.yml"
    text = read_text(workflow)
    match = re.search(r"--required-categories\s+([A-Za-z0-9_,]+)", text)
    if match is None:
        raise ManifestError(f"{rel_posix(workflow, root)} does not declare --required-categories")
    return {item for item in match.group(1).split(",") if item}


def meta_test_names(root: pathlib.Path = ROOT) -> set[str]:
    path = root / "ci" / "meta-tests.txt"
    if not path.is_file():
        return set()
    return {
        line.strip()
        for line in read_text(path).splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def canonical_payload(document: dict) -> dict:
    """The deterministic content the manifest hash covers.

    Toolchain and host fields are intentionally excluded: the hash binds the
    commit/tree, declarations, compiled targets/tests and their bindings, so
    it is stable across runners and toolchain updates.
    """
    return {
        "schema_version": document["schema_version"],
        "kind": document["kind"],
        "commit": document["commit"],
        "tree": document["tree"],
        "declared": document["declared"],
        "targets": document["targets"],
        "bindings": document["bindings"],
        "deferred_differential": document["deferred_differential"],
        "unbound": document["unbound"],
    }


def manifest_digest(document: dict) -> str:
    payload = canonical_payload(document)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def parse_test_listing(stdout: str) -> list[str]:
    names = [
        line[: -len(TEST_SUFFIX)].strip()
        for line in stdout.splitlines()
        if line.endswith(TEST_SUFFIX)
    ]
    # A test name cannot legitimately be empty; an empty entry means the
    # harness output changed and the manifest would silently under-report.
    if any(not name for name in names):
        raise ManifestError("test harness produced an empty test name")
    return names


def run_listing(executable: pathlib.Path, env: dict[str, str], extra: list[str]) -> list[str]:
    try:
        result = subprocess.run(
            [str(executable), "--list", *extra],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ManifestError(f"cannot list {executable}: {exc}") from exc
    if result.returncode != 0:
        raise ManifestError(
            f"test executable {executable} failed to list tests "
            f"(exit {result.returncode}): {result.stderr[-2000:]}"
        )
    return parse_test_listing(result.stdout)


def compile_targets(root: pathlib.Path, env: dict[str, str]) -> list[dict]:
    cargo = env.get("CARGO") or "cargo"
    command = [
        cargo,
        "test",
        "--no-run",
        "--lib",
        "--bins",
        "--tests",
        "--features",
        BUILD_FEATURES,
        "--message-format=json",
    ]
    try:
        result = subprocess.run(
            command,
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            timeout=3600,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ManifestError(f"cannot run {' '.join(command)}: {exc}") from exc
    if result.returncode != 0:
        raise ManifestError(
            "cargo test --no-run failed; the compiled manifest cannot be built:\n"
            + result.stderr[-6000:]
        )

    artifacts: dict[str, dict] = {}
    for line in result.stdout.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("reason") != "compiler-artifact":
            continue
        target = record.get("target") or {}
        if not target.get("test"):
            continue
        # `cargo test --bins` also emits the ordinary (non-test) binary; only
        # the test-profile artifact is a libtest harness that supports --list.
        if not (record.get("profile") or {}).get("test"):
            continue
        executable = record.get("executable")
        if not executable:
            continue
        kinds = sorted(target.get("kind") or [])
        if any(kind in {"bench", "example", "custom-build"} for kind in kinds):
            continue
        # A single test binary may be reported more than once (e.g. shared
        # dependencies); key by the executable path.
        name = target.get("name")
        src_path = target.get("src_path")
        if not name or not src_path:
            raise ManifestError(
                "cargo emitted a test artifact without target name/src_path"
            )
        artifacts[str(executable)] = {
            "name": name,
            "kind": kinds,
            "src_path": rel_posix(pathlib.Path(src_path), root),
            "executable": str(executable),
        }

    if not artifacts:
        raise ManifestError(
            "cargo test --no-run produced no test executables; refusing to "
            "claim a compiled manifest"
        )

    targets: list[dict] = []
    for artifact in artifacts.values():
        executable = pathlib.Path(artifact["executable"])
        all_tests = run_listing(executable, env, [])
        ignored = set(run_listing(executable, env, ["--ignored"]))
        unknown = ignored.difference(all_tests)
        if unknown:
            raise ManifestError(
                f"{artifact['name']}: --list --ignored reported tests absent "
                f"from --list: {sorted(unknown)[:5]}"
            )
        targets.append(
            {
                "name": artifact["name"],
                "kind": artifact["kind"],
                "src_path": artifact["src_path"],
                "tests": sorted(set(all_tests)),
                "ignored": sorted(ignored),
            }
        )
    targets.sort(key=lambda target: (target["name"], target["kind"], target["src_path"]))
    return targets


def load_targets(path: pathlib.Path) -> list[dict]:
    """Load a precomputed target list (test seam; not used by CI)."""
    try:
        payload = json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        raise ManifestError(f"cannot parse targets JSON {path}: {exc}") from exc
    targets = payload.get("targets") if isinstance(payload, dict) else payload
    if not isinstance(targets, list):
        raise ManifestError(f"targets JSON {path} must contain a target list")
    return targets


def bind_declarations(
    declared: dict[str, list[str]],
    targets: list[dict],
    root: pathlib.Path = ROOT,
) -> tuple[dict[str, list[dict]], list[dict], list[dict]]:
    meta = meta_test_names(root)
    oracle_all = oracle_categories(root)
    oracle_reference = reference_categories(root)
    oracle_required = required_oracle_categories(root)

    # The oracle's own required-category list is a contract too: a category the
    # capture workflow requires must exist in the runtime table and have a real
    # executor.  This is independent of which categories the API database
    # happens to declare as evidence.
    for category in sorted(oracle_required):
        reasons = []
        if category not in oracle_all:
            reasons.append("required by windows-oracle.yml but absent from ALL_CATEGORIES")
        if category not in oracle_reference:
            reasons.append("required by windows-oracle.yml but has no reference executor")
        if reasons:
            raise ManifestError(
                f"windows-oracle.yml requires category {category!r}: " + "; ".join(reasons)
            )

    integration_targets: dict[str, dict] = {}
    test_short: dict[str, list[tuple[dict, str]]] = {}
    for target in targets:
        if "test" in (target.get("kind") or []):
            integration_targets.setdefault(target["name"], target)
        for test in target["tests"]:
            test_short.setdefault(test.rsplit("::", 1)[-1], []).append((target, test))

    bindings: dict[str, list[dict]] = {}
    unbound: list[dict] = []
    deferred: list[dict] = []

    def runnable_tests(target: dict) -> list[str]:
        ignored = set(target.get("ignored") or [])
        return [
            test
            for test in target.get("tests") or []
            if test not in ignored and test.rsplit("::", 1)[-1] not in meta
        ]

    for kind in ("conformance", "scenario"):
        for evidence_id in declared[kind]:
            suite = evidence_id.split(":", 1)[1]
            entries: list[dict] = []

            target = integration_targets.get(suite)
            if target is not None and runnable_tests(target):
                entries.append({"target": target["name"], "test": "", "via": "target"})

            for target, test in test_short.get(suite, []):
                if test in (target.get("ignored") or []):
                    continue
                short = test.rsplit("::", 1)[-1]
                if short in meta:
                    continue
                entries.append({"target": target["name"], "test": test, "via": "test"})

            deduped = {
                (entry["target"], entry["test"], entry["via"]): entry for entry in entries
            }
            if deduped:
                bindings[evidence_id] = [
                    deduped[key] for key in sorted(deduped)
                ]
            else:
                unbound.append(
                    {
                        "id": evidence_id,
                        "reason": (
                            f"no compiled, runnable test target or test function "
                            f"named '{suite}'"
                        ),
                    }
                )

    for evidence_id in declared["differential"]:
        category = evidence_id.split(":", 1)[1]
        if category not in oracle_all:
            # The compiled-test manifest cannot prove this declaration: the
            # oracle has no such category at all.  Record it explicitly (with
            # the reason) instead of treating it as a compiled-test failure.
            deferred.append(
                {
                    "id": evidence_id,
                    "reason": (
                        "not a category in src/windows_oracle.rs ALL_CATEGORIES; "
                        "the compiled test manifest cannot bind it"
                    ),
                }
            )
            continue
        reasons = []
        if category not in oracle_reference:
            reasons.append("absent from the windows_reference executor")
        if category not in oracle_required:
            reasons.append(
                "absent from .github/workflows/windows-oracle.yml --required-categories"
            )
        if reasons:
            unbound.append({"id": evidence_id, "reason": "; ".join(reasons)})
        else:
            bindings[evidence_id] = [
                {"target": "windows_reference", "test": category, "via": "oracle-category"}
            ]

    return (
        dict(sorted(bindings.items())),
        sorted(unbound, key=lambda item: item["id"]),
        sorted(deferred, key=lambda item: item["id"]),
    )


def toolchain_info() -> dict:
    def capture(*command: str) -> str:
        try:
            return subprocess.run(
                list(command), capture_output=True, text=True, check=False
            ).stdout.strip()
        except OSError:
            return ""

    host = ""
    verbose = capture("rustc", "-vV")
    for line in verbose.splitlines():
        if line.startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break
    return {
        "rustc": capture("rustc", "--version"),
        "cargo": capture("cargo", "--version"),
        "host": host,
    }


def build_document(
    root: pathlib.Path = ROOT,
    targets: list[dict] | None = None,
) -> dict:
    env = os.environ.copy()
    declared = declarations(root)
    compiled_targets = targets if targets is not None else compile_targets(root, env)
    bindings, unbound, deferred = bind_declarations(declared, compiled_targets, root)
    document = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "commit": git_output("rev-parse", "HEAD", root=root),
        "tree": git_output("rev-parse", "HEAD^{tree}", root=root),
        "declared": declared,
        "targets": compiled_targets,
        "bindings": bindings,
        "deferred_differential": deferred,
        "unbound": unbound,
        "toolchain": toolchain_info(),
        "source": {
            "coverage_registry": "src/api_coverage.rs",
            "oracle_categories": "src/windows_oracle.rs",
            "reference_executor": "windows_reference/src/win32.rs",
            "required_categories": ".github/workflows/windows-oracle.yml",
            "command": (
                "cargo test --no-run --lib --bins --tests "
                f"--features {BUILD_FEATURES} --message-format=json; "
                "<executable> --list [--ignored]"
            ),
        },
    }
    document["manifest_sha256"] = manifest_digest(document)
    return document


def _validate_targets(document: dict) -> list[str]:
    errors: list[str] = []
    targets = document.get("targets")
    if not isinstance(targets, list) or not targets:
        return ["manifest targets must be a non-empty list"]
    expected_order = sorted(
        targets,
        key=lambda target: (
            target.get("name", ""),
            target.get("kind", []),
            target.get("src_path", ""),
        ),
    )
    if targets != expected_order:
        errors.append("manifest targets are not in deterministic sorted order")
    seen = set()
    for index, target in enumerate(targets):
        if not isinstance(target, dict):
            errors.append(f"target[{index}] is not an object")
            continue
        key = (target.get("name"), tuple(target.get("kind") or []), target.get("src_path"))
        if key in seen:
            errors.append(f"duplicate manifest target {key}")
        seen.add(key)
        tests = target.get("tests")
        ignored = target.get("ignored")
        if not isinstance(tests, list) or not isinstance(ignored, list):
            errors.append(f"target {key} must carry tests and ignored lists")
            continue
        if tests != sorted(set(tests)):
            errors.append(f"target {key} tests are not sorted/unique")
        if ignored != sorted(set(ignored)):
            errors.append(f"target {key} ignored tests are not sorted/unique")
        if not set(ignored).issubset(set(tests)):
            errors.append(f"target {key} ignored tests are not a subset of tests")
    return errors


def _validate_bindings(
    document: dict,
    declared: dict[str, list[str]],
    root: pathlib.Path,
) -> list[str]:
    errors: list[str] = []
    bindings = document.get("bindings")
    unbound = document.get("unbound")
    deferred = document.get("deferred_differential")
    if not isinstance(bindings, dict):
        return ["manifest bindings must be an object"]
    if not isinstance(unbound, list):
        return ["manifest unbound must be a list"]
    if not isinstance(deferred, list):
        return ["manifest deferred_differential must be a list"]

    oracle_all = oracle_categories(root)
    declared_oracle_known = {
        evidence_id
        for evidence_id in declared["differential"]
        if evidence_id.split(":", 1)[1] in oracle_all
    }
    declared_deferred = set(declared["differential"]).difference(declared_oracle_known)
    bindable_ids = sorted(
        set(declared["conformance"])
        | set(declared["scenario"])
        | declared_oracle_known
    )
    if sorted(bindings) != bindable_ids:
        missing = sorted(set(bindable_ids).difference(bindings))
        extra = sorted(set(bindings).difference(bindable_ids))
        if missing:
            errors.append(f"manifest has no binding for declared ids: {missing}")
        if extra:
            errors.append(f"manifest binds undeclared ids: {extra}")
    if unbound:
        for item in unbound:
            if isinstance(item, dict):
                errors.append(f"unbound evidence {item.get('id')}: {item.get('reason')}")
            else:
                errors.append(f"unbound evidence entry is not an object: {item!r}")

    deferred_ids = set()
    for item in deferred:
        if not isinstance(item, dict):
            errors.append(f"deferred differential entry is not an object: {item!r}")
            continue
        evidence_id = item.get("id")
        if not isinstance(evidence_id, str):
            errors.append(f"deferred differential entry has no id: {item!r}")
            continue
        deferred_ids.add(evidence_id)
        if not item.get("reason"):
            errors.append(f"deferred differential {evidence_id}: missing reason")
        if evidence_id.startswith("windows-oracle:"):
            category = evidence_id.split(":", 1)[1]
            if category in oracle_all:
                errors.append(
                    f"deferred differential {evidence_id}: category exists in "
                    "ALL_CATEGORIES and must be bound, not deferred"
                )
    if deferred_ids != declared_deferred:
        missing = sorted(declared_deferred.difference(deferred_ids))
        extra = sorted(deferred_ids.difference(declared_deferred))
        if missing:
            errors.append(f"deferred_differential is missing declared ids: {missing}")
        if extra:
            errors.append(f"deferred_differential names undeclared ids: {extra}")

    meta = meta_test_names(root)
    targets = list(document.get("targets") or [])
    oracle_reference = reference_categories(root)
    oracle_required = required_oracle_categories(root)

    for category in sorted(oracle_required):
        if category not in oracle_all:
            errors.append(
                f"windows-oracle.yml requires {category!r} but ALL_CATEGORIES omits it"
            )
        if category not in oracle_reference:
            errors.append(
                f"windows-oracle.yml requires {category!r} but no reference executor exists"
            )

    for evidence_id, entries in bindings.items():
        if not isinstance(entries, list) or not entries:
            errors.append(f"{evidence_id}: binding list must be non-empty")
            continue
        expected_order = sorted(
            entries,
            key=lambda entry: (
                entry.get("target", ""),
                entry.get("test", ""),
                entry.get("via", ""),
            ),
        )
        if entries != expected_order:
            errors.append(f"{evidence_id}: bindings are not in deterministic sorted order")
        if len({json.dumps(entry, sort_keys=True) for entry in entries}) != len(entries):
            errors.append(f"{evidence_id}: duplicate binding entries")

        is_differential = evidence_id.startswith("windows-oracle:")
        for entry in entries:
            target_name = entry.get("target")
            test = entry.get("test")
            via = entry.get("via")
            if is_differential:
                category = evidence_id.split(":", 1)[1]
                if target_name != "windows_reference" or test != category:
                    errors.append(
                        f"{evidence_id}: differential binding must name "
                        f"windows_reference/{category}"
                    )
                if category not in oracle_all:
                    errors.append(f"{evidence_id}: category is not compiled into ALL_CATEGORIES")
                if category not in oracle_reference:
                    errors.append(f"{evidence_id}: category has no reference executor")
                if category not in oracle_required:
                    errors.append(f"{evidence_id}: category is not required by windows-oracle.yml")
                continue

            if via == "target":
                suite = evidence_id.split(":", 1)[1]
                if target_name != suite:
                    errors.append(
                        f"{evidence_id}: target binding names {target_name!r}, "
                        f"not the declared suite {suite!r}"
                    )
                target = next(
                    (
                        candidate
                        for candidate in targets
                        if candidate.get("name") == target_name
                        and "test" in (candidate.get("kind") or [])
                    ),
                    None,
                )
                if target is None:
                    errors.append(
                        f"{evidence_id}: binding names no integration target {target_name!r}"
                    )
                    continue
                tests = set(target.get("tests") or [])
                ignored = set(target.get("ignored") or [])
                runnable = [
                    name
                    for name in tests
                    if name not in ignored and name.rsplit("::", 1)[-1] not in meta
                ]
                if not runnable:
                    errors.append(f"{evidence_id}: target binding has no runnable tests")
            elif via == "test":
                suite = evidence_id.split(":", 1)[1]
                if not isinstance(test, str) or test.rsplit("::", 1)[-1] != suite:
                    errors.append(
                        f"{evidence_id}: test binding {test!r} is not the declared "
                        f"test function {suite!r}"
                    )
                target = next(
                    (
                        candidate
                        for candidate in targets
                        if candidate.get("name") == target_name
                        and test in set(candidate.get("tests") or [])
                    ),
                    None,
                )
                if target is None:
                    errors.append(
                        f"{evidence_id}: bound test {test!r} is not in any compiled "
                        f"target named {target_name!r}"
                    )
                    continue
                ignored = set(target.get("ignored") or [])
                if test in ignored:
                    errors.append(f"{evidence_id}: bound test {test!r} is ignored")
                if test.rsplit("::", 1)[-1] in meta:
                    errors.append(f"{evidence_id}: bound test {test!r} is cargo-invoking meta")
            else:
                errors.append(f"{evidence_id}: unknown binding mechanism {via!r}")
    return errors


def digest_errors(
    document: object,
    root: pathlib.Path = ROOT,
    require_head: bool = False,
) -> list[str]:
    """Structural + self-hash + HEAD checks used by --print-digest.

    Declaration/binding freshness is deliberately left to verify_document so
    the digest of a structurally intact but evidence-incomplete manifest can
    still be compared before the full gate reports the specific violations.
    """
    if not isinstance(document, dict):
        return ["manifest is not a JSON object"]
    errors: list[str] = []
    if document.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            f"manifest schema_version is {document.get('schema_version')!r}, "
            f"expected {SCHEMA_VERSION}"
        )
    if document.get("kind") != KIND:
        errors.append(f"manifest kind is {document.get('kind')!r}, expected {KIND!r}")
    try:
        expected_digest = manifest_digest(document)
    except (KeyError, TypeError) as exc:
        errors.append(f"manifest is missing fields required for its hash: {exc}")
    else:
        if document.get("manifest_sha256") != expected_digest:
            errors.append(
                "manifest_sha256 mismatch: recorded "
                f"{document.get('manifest_sha256')!r}, recomputation yields {expected_digest}"
            )
    if require_head:
        try:
            head = git_output("rev-parse", "HEAD", root=root)
            tree = git_output("rev-parse", "HEAD^{tree}", root=root)
        except ManifestError as exc:
            errors.append(str(exc))
        else:
            if document.get("commit") != head:
                errors.append(
                    f"manifest commit {document.get('commit')!r} does not match HEAD {head!r}"
                )
            if document.get("tree") != tree:
                errors.append(
                    f"manifest tree {document.get('tree')!r} does not match HEAD tree {tree!r}"
                )
    return errors


def verify_document(
    document: object,
    root: pathlib.Path = ROOT,
    require_head: bool = False,
) -> list[str]:
    if not isinstance(document, dict):
        return ["manifest is not a JSON object"]
    errors: list[str] = []
    if document.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            f"manifest schema_version is {document.get('schema_version')!r}, "
            f"expected {SCHEMA_VERSION}"
        )
    if document.get("kind") != KIND:
        errors.append(f"manifest kind is {document.get('kind')!r}, expected {KIND!r}")

    try:
        current_declared = declarations(root)
    except ManifestError as exc:
        errors.append(str(exc))
        current_declared = {"conformance": [], "scenario": [], "differential": []}
    if document.get("declared") != current_declared:
        errors.append(
            "manifest declarations differ from the current source registry "
            "(stale or tampered manifest)"
        )

    try:
        expected_digest = manifest_digest(document)
    except (KeyError, TypeError) as exc:
        errors.append(f"manifest is missing fields required for its hash: {exc}")
        expected_digest = ""
    if expected_digest and document.get("manifest_sha256") != expected_digest:
        errors.append(
            "manifest_sha256 mismatch: recorded "
            f"{document.get('manifest_sha256')!r}, recomputation yields {expected_digest}"
        )

    errors.extend(_validate_targets(document))
    errors.extend(_validate_bindings(document, current_declared, root))

    if require_head:
        try:
            head = git_output("rev-parse", "HEAD", root=root)
            tree = git_output("rev-parse", "HEAD^{tree}", root=root)
        except ManifestError as exc:
            errors.append(str(exc))
        else:
            if document.get("commit") != head:
                errors.append(
                    f"manifest commit {document.get('commit')!r} does not match HEAD {head!r}"
                )
            if document.get("tree") != tree:
                errors.append(
                    f"manifest tree {document.get('tree')!r} does not match HEAD tree {tree!r}"
                )
    return errors


def write_document(path: pathlib.Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def load_document(path: pathlib.Path) -> dict:
    try:
        document = json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        raise ManifestError(f"cannot parse manifest {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise ManifestError(f"manifest {path} is not a JSON object")
    return document


def print_summary(document: dict) -> None:
    targets = document.get("targets") or []
    tests = sum(len(target.get("tests") or []) for target in targets)
    bound = len(document.get("bindings") or {})
    deferred = document.get("deferred_differential") or []
    unbound = document.get("unbound") or []
    print(
        f":: evidence manifest: {tests} compiled tests in {len(targets)} target(s); "
        f"{bound} declared evidence id(s) bound; {len(deferred)} deferred "
        f"differential declaration(s); {len(unbound)} unbound"
    )


def print_deferred(document: dict, root: pathlib.Path = ROOT) -> None:
    for item in document.get("deferred_differential") or []:
        if isinstance(item, dict) and item.get("id"):
            print(
                f"::warning::{item['id']}: {item.get('reason', 'deferred')} "
                "(declared differential contract is not implemented by the oracle; "
                "fix src/api_coverage.rs or implement the category)",
                file=sys.stderr,
            )


def fail_document(document: dict, errors: list[str], root: pathlib.Path = ROOT) -> int:
    printed: set[str] = set()
    for item in document.get("unbound") or []:
        if isinstance(item, dict):
            evidence_id = str(item.get("id", "<unknown>"))
            reason = str(item.get("reason", "unbound"))
            line = f"{evidence_id}: {reason}"
            if line not in printed:
                print(f"::error::{line}", file=sys.stderr)
                printed.add(line)
    for error in errors:
        if error.startswith("unbound evidence "):
            # Already reported above with the concrete evidence id + reason.
            continue
        if error not in printed:
            print(f"::error::{error}", file=sys.stderr)
            printed.add(error)
    return 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        nargs="?",
        const=str(DEFAULT_OUTPUT),
        metavar="PATH",
        help=f"build and write the manifest (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument("--verify", metavar="PATH", help="verify an existing manifest")
    parser.add_argument(
        "--targets-json",
        metavar="PATH",
        help="use a precomputed target list instead of compiling (test seam)",
    )
    parser.add_argument(
        "--require-head",
        action="store_true",
        help="require the manifest commit/tree to match the current git HEAD",
    )
    parser.add_argument(
        "--print-digest",
        metavar="PATH",
        help="print the canonical manifest digest and exit",
    )
    parser.add_argument("--quiet", action="store_true", help="only print failures")
    parser.add_argument("--root", default=str(ROOT), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    root = pathlib.Path(args.root).resolve()

    try:
        if args.print_digest:
            document = load_document(pathlib.Path(args.print_digest))
            errors = digest_errors(document, root=root, require_head=args.require_head)
            if errors:
                return fail_document(document, errors, root)
            print(manifest_digest(document))
            return 0

        exit_code = 0
        document: dict | None = None

        if args.write:
            targets = load_targets(pathlib.Path(args.targets_json)) if args.targets_json else None
            document = build_document(root, targets=targets)
            write_document(pathlib.Path(args.write), document)
            if not args.quiet:
                print_summary(document)
                print_deferred(document, root)
            errors = verify_document(document, root=root, require_head=args.require_head)
            if errors:
                exit_code = fail_document(document, errors, root)

        if args.verify:
            document = load_document(pathlib.Path(args.verify))
            if not args.quiet:
                print_summary(document)
                print_deferred(document, root)
            errors = verify_document(document, root=root, require_head=args.require_head)
            if errors:
                exit_code = fail_document(document, errors, root)

        if not args.write and not args.verify:
            parser.error("pass --write, --verify, or --print-digest")
        return exit_code
    except ManifestError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
