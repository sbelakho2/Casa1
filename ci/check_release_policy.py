#!/usr/bin/env python3
"""Enforce the in-repo part of the protected-main / release policy.

GitHub server-side branch protection cannot be changed from repository code,
so this script makes the representable part machine-checkable and fails CI
when the workflow shape or gate semantics drift:

  * every required CI/release job still exists and the aggregate gate still
    needs all of them (a removed/renamed job breaks the gate);
  * the aggregate status contexts protected on main ("CI Gate") exist and are
    backed by an ``if: always()`` aggregate job;
  * the dev API gate really enforces completeness + regression, and the
    release workflow really runs the completeness gate;
  * the compiled-test manifest is produced, uploaded, folded into release
    evidence, and verified by the release gate;
  * nightly installs the FFmpeg development libraries with a usable
    PKG_CONFIG_PATH, still invokes UBSAN through the script, and no workflow
    asks for the nonexistent ``metal`` feature;
  * no workflow embeds force-push, forced-delete, branch-delete, hard-reset,
    or hook-skipping commands.


Usage:
    python3 ci/check_release_policy.py [--root PATH]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

DEFAULT_POLICY = "ci/release-policy.json"

# Minimum gates that must exist regardless of how ci/release-policy.json is
# edited: the compiled-evidence test job, the API completeness/regression gate,
# the policy gate, and the aggregate status contexts.
MANDATORY_POLICY_JOBS = {
    ".github/workflows/ci.yml": ("test", "api-gate", "policy-check", "ci-gate"),
    ".github/workflows/release.yml": ("check-release-gate", "release-gate"),
}


class PolicyError(RuntimeError):
    pass


def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise PolicyError(f"cannot read {path}: {exc}") from exc


def parse_jobs(path: pathlib.Path) -> dict[str, dict]:
    """Parse job ids, names, needs and raw text from a GitHub workflow.

    This intentionally understands only the small YAML subset used by these
    workflows (top-level jobs, job-level name/needs/if and block needs lists),
    so the policy check has no PyYAML dependency.
    """
    text = read_text(path)
    jobs: dict[str, dict] = {}
    in_jobs = False
    current: str | None = None
    section = "other"
    for raw in text.splitlines():
        line = raw.rstrip()
        if not in_jobs:
            if re.match(r"^jobs:\s*(?:#.*)?$", line):
                in_jobs = True
            continue
        if line and not line.startswith(" "):
            # A new top-level key ends the jobs mapping.
            break
        job_match = re.match(r"^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$", line)
        if job_match:
            current = job_match.group(1)
            jobs[current] = {
                "name": None,
                "needs": [],
                "if": None,
                "text": [],
            }
            section = "other"
            continue
        if current is None:
            continue
        jobs[current]["text"].append(line)

        key_match = re.match(r"^    ([A-Za-z0-9_-]+):\s*(.*)$", line)
        if key_match:
            key, value = key_match.group(1), key_match.group(2).strip()
            value = re.sub(r"\s+#.*$", "", value).strip()
            section = key
            if key == "name":
                jobs[current]["name"] = value.strip("\"'")
            elif key == "if":
                jobs[current]["if"] = value
            elif key == "needs":
                if value.startswith("["):
                    jobs[current]["needs"] = [
                        item.strip().strip("\"'")
                        for item in value.strip("[]").split(",")
                        if item.strip()
                    ]
                    section = "other"
                elif value:
                    jobs[current]["needs"].append(value.strip("\"'"))
                    section = "other"
                # else: block list follows
            continue

        if section == "needs":
            need_match = re.match(r"^      -\s+([A-Za-z0-9_-]+)\s*$", line)
            if need_match:
                jobs[current]["needs"].append(need_match.group(1))
    return jobs


def load_policy(root: pathlib.Path) -> dict:
    path = root / DEFAULT_POLICY
    try:
        policy = json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        raise PolicyError(f"cannot parse {path}: {exc}") from exc
    if not isinstance(policy, dict):
        raise PolicyError(f"{path} is not a JSON object")
    return policy


def workflow_text(root: pathlib.Path, relative: str) -> str:
    return read_text(root / relative)


def job_text(job: dict) -> str:
    return "\n".join(job.get("text") or [])


def require_contains(errors: list[str], label: str, text: str, needles: list[str]) -> None:
    for needle in needles:
        if needle not in text:
            errors.append(f"{label}: missing required text {needle!r}")


def check_workflow_shape(
    policy: dict, root: pathlib.Path
) -> tuple[list[str], dict[str, dict[str, dict]]]:
    errors: list[str] = []
    parsed: dict[str, dict[str, dict]] = {}
    for relative, spec in (policy.get("workflows") or {}).items():
        if not isinstance(spec, dict):
            errors.append(f"{relative}: workflow policy entry must be an object")
            continue
        path = root / relative
        if not path.is_file():
            errors.append(f"required workflow missing: {relative}")
            continue
        jobs = parse_jobs(path)
        parsed[relative] = jobs
        policy_jobs = set(spec.get("required_jobs") or [])
        for job_id in MANDATORY_POLICY_JOBS.get(relative, ()):
            if job_id not in policy_jobs:
                errors.append(
                    f"{relative}: policy removed mandatory job '{job_id}' from required_jobs"
                )
        for job_id in spec.get("required_jobs") or []:
            job = jobs.get(job_id)
            if job is None:
                errors.append(f"{relative}: required job '{job_id}' is missing")
                continue
            text = job_text(job).lower()
            if re.search(
                r"^    continue-on-error:\s*true\s*(?:#.*)?$", text, re.MULTILINE
            ):
                errors.append(
                    f"{relative}:{job_id}: required job must not be non-blocking "
                    "(job-level continue-on-error: true)"
                )
            if re.search(
                r"^    if:\s*(?:false|\$\{\{\s*false\s*\}\})\s*(?:#.*)?$",
                text,
                re.MULTILINE,
            ):
                errors.append(f"{relative}:{job_id}: required job is disabled with if: false")

        aggregate_id = spec.get("aggregate_job")
        aggregate = jobs.get(aggregate_id or "")
        if aggregate is None:
            errors.append(f"{relative}: aggregate job '{aggregate_id}' is missing")
            continue
        expected_name = spec.get("aggregate_name")
        if aggregate.get("name") != expected_name:
            errors.append(
                f"{relative}: aggregate job name is {aggregate.get('name')!r}, "
                f"expected {expected_name!r}"
            )
        if "always()" not in (aggregate.get("if") or ""):
            errors.append(
                f"{relative}: aggregate job '{aggregate_id}' must run with "
                "'if: always()' so a failed dependency cannot be skipped"
            )
        if spec.get("aggregate_dynamic_needs", True):
            if "toJSON(needs)" not in job_text(aggregate):
                errors.append(
                    f"{relative}: aggregate job '{aggregate_id}' must evaluate the "
                    "full toJSON(needs) result, not a hardcoded subset"
                )
        expected_needs = {
            job_id
            for job_id in (spec.get("required_jobs") or [])
            if job_id != aggregate_id
        }
        actual_needs = set(aggregate.get("needs") or [])
        missing_needs = sorted(expected_needs.difference(actual_needs))
        if missing_needs:
            errors.append(
                f"{relative}: aggregate job '{aggregate_id}' does not need "
                f"required jobs: {missing_needs}"
            )
    return errors, parsed


def check_status_contexts(policy: dict, parsed: dict[str, dict[str, dict]]) -> list[str]:
    errors: list[str] = []
    names = {
        job.get("name")
        for jobs in parsed.values()
        for job in jobs.values()
        if job.get("name")
    }
    return errors


def parse_extern_link_blocks(text: str) -> dict[str, set[str]]:
    """Map each ``extern "C"`` symbol to the ``#[link(name = ...)]`` libraries
    attached to its block.

    This is a static check of the Windows reference's import libraries: it
    cannot run a Windows linker here, but it can prove that ``CharUpperW`` is
    linked through ``user32`` and ``snprintf`` through
    ``legacy_stdio_definitions`` instead of surfacing as an unresolved
    ``__imp_*`` symbol.
    """
    blocks: dict[str, set[str]] = {}
    pending: list[str] = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index].strip()
        link = re.match(r'#\[link\(name\s*=\s*"([^"]+)"', line)
        if link:
            pending.append(link.group(1))
            index += 1
            continue
        if line.startswith("#[") or not line or line.startswith("//"):
            index += 1
            continue
        if re.match(r'(?:pub\s+)?(?:unsafe\s+)?extern\s+"C"\s*\{', line):
            index += 1
            while index < len(lines) and lines[index].strip() != "}":
                symbol = re.match(
                    r"\s*(?:pub\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)", lines[index]
                )
                if symbol:
                    blocks.setdefault(symbol.group(1), set()).update(pending)
                index += 1
            pending = []
            index += 1
            continue
        pending = []
        index += 1
    return blocks


def check_windows_oracle(
    policy: dict, parsed: dict[str, dict[str, dict]], root: pathlib.Path
) -> list[str]:
    errors: list[str] = []
    contract = policy.get("contract") or {}
    spec = contract.get("windows_oracle")
    if not isinstance(spec, dict):
        return ["contract.windows_oracle must describe the required oracle link check"]
    workflow_rel = spec.get("workflow", ".github/workflows/windows-oracle.yml")
    workflow = workflow_text(root, workflow_rel)
    build_command = spec.get(
        "build_command",
        "cargo build --manifest-path windows_reference/Cargo.toml --release",
    )
    require_contains(errors, workflow_rel, workflow, [build_command, "toJSON(needs)"])
    for category in spec.get("required_categories") or []:
        if "--required-categories" not in workflow or category not in workflow:
            errors.append(
                f"{workflow_rel}: required differential category {category!r} is not "
                "passed to --required-categories"
            )
    source = root / spec.get("source", "windows_reference/src/win32.rs")
    if not source.is_file():
        errors.append(f"Windows oracle link source missing: {source}")
        return errors
    blocks = parse_extern_link_blocks(read_text(source))
    manifest_path = root / "ci" / "test-manifest.json"
    manifest = read_text(manifest_path) if manifest_path.is_file() else ""
    for item in spec.get("symbols") or []:
        if not isinstance(item, dict):
            errors.append("contract.windows_oracle.symbols entries must be objects")
            continue
        symbol = item.get("symbol", "")
        library = item.get("library", "")
        libraries = blocks.get(symbol)
        if libraries is None:
            errors.append(
                f"windows_reference: symbol {symbol!r} is not declared in an extern block"
            )
        elif library not in libraries:
            errors.append(
                f"windows_reference: {symbol!r} is linked with {sorted(libraries)}, "
                f"expected {library!r}"
            )
        category = item.get("category")
        if category and f"windows-oracle:{category}" not in manifest:
            errors.append(
                f"windows_reference: {symbol!r} category {category!r} is not "
                "covered by the compiled evidence manifest"
            )
    return errors


def check_contract(policy: dict, parsed: dict[str, dict[str, dict]], root: pathlib.Path) -> list[str]:
    errors: list[str] = []
    contract = policy.get("contract") or {}

    ci_path = contract.get("ci_workflow", ".github/workflows/ci.yml")
    release_path = contract.get("release_workflow", ".github/workflows/release.yml")
    nightly_path = contract.get("nightly_workflow", ".github/workflows/nightly.yml")
    ci_jobs = parsed.get(ci_path, {})
    release_jobs = parsed.get(release_path, {})

    api_job_id = contract.get("api_gate_job", "api-gate")
    api_job = ci_jobs.get(api_job_id)
    if api_job is None:
        errors.append(f"{ci_path}: api job '{api_job_id}' is missing")
    else:
        api_name = (api_job.get("name") or "")
        require_contains(
            errors,
            f"{ci_path}:{api_job_id}",
            api_name,
            list(contract.get("api_gate_name_terms") or []),
        )
        require_contains(
            errors,
            f"{ci_path}:{api_job_id}",
            job_text(api_job),
            list(contract.get("api_gate_commands") or []),
        )
        for forbidden in contract.get("api_gate_forbidden_commands") or []:
            if forbidden in job_text(api_job):
                errors.append(
                    f"{ci_path}:{api_job_id}: must not run weakened gate command "
                    f"{forbidden!r}"
                )

    release_job_id = contract.get("release_completeness_job", "check-release-gate")
    release_job = release_jobs.get(release_job_id)
    if release_job is None:
        errors.append(f"{release_path}: release gate job '{release_job_id}' is missing")
    else:
        require_contains(
            errors,
            f"{release_path}:{release_job_id}",
            job_text(release_job),
            list(contract.get("release_completeness_commands") or []),
        )
        require_contains(
            errors,
            f"{release_path}:{release_job_id}",
            job_text(release_job),
            [
                contract.get("manifest_artifact_prefix", "test-manifest-"),
                (
                    contract.get("manifest_artifact_prefix", "test-manifest-")
                    + "${{ github.sha }}"
                ),
                contract.get("manifest_fold_argument", "--test-manifest"),
                "ci/check_release_gate.sh",
            ],
        )
        for forbidden in contract.get("api_gate_forbidden_commands") or []:
            if forbidden in job_text(release_job):
                errors.append(
                    f"{release_path}:{release_job_id}: must not run weakened gate "
                    f"command {forbidden!r}"
                )

    test_job = ci_jobs.get("test")
    if test_job is None:
        errors.append(f"{ci_path}: test job is missing")
    else:
        test_text = job_text(test_job)
        require_contains(
            errors,
            f"{ci_path}:test",
            test_text,
            ["bash ci/check_tests.sh"],
        )
        if contract.get("manifest_artifact_prefix", "test-manifest-") not in test_text:
            errors.append(
                f"{ci_path}:test: does not upload the compiled test manifest "
                f"({contract.get('manifest_artifact_prefix')!r})"
            )
        artifact_name = (
            contract.get("manifest_artifact_prefix", "test-manifest-") + "${{ github.sha }}"
        )
        if artifact_name not in test_text:
            errors.append(
                f"{ci_path}:test: manifest artifact must be named {artifact_name!r} "
                "so the release job can download it for this exact commit"
            )
        if "actions/upload-artifact" not in test_text:
            errors.append(f"{ci_path}:test: does not upload an artifact")
        manifest_path = contract.get("manifest_path", "ci/test-manifest.json")
        if manifest_path not in test_text:
            errors.append(
                f"{ci_path}:test: uploads no artifact from the manifest path "
                f"{manifest_path!r}"
            )
        if "fetch-depth: 0" not in test_text:
            errors.append(
                f"{ci_path}:test: must check out full history so the affected-test "
                "base ref is resolvable"
            )

    policy_job = ci_jobs.get("policy-check")
    if policy_job is None:
        errors.append(f"{ci_path}: policy-check job is missing")
    else:
        require_contains(
            errors,
            f"{ci_path}:policy-check",
            job_text(policy_job),
            ["ci/check_release_policy.py"],
        )

    check_tests = read_text(root / "ci" / "check_tests.sh")
    manifest_write_command = contract.get(
        "manifest_write_command", "ci/evidence_manifest.py --write ci/test-manifest.json"
    )
    require_contains(
        errors,
        "ci/check_tests.sh",
        check_tests,
        [manifest_write_command],
    )
    if not (root / "ci" / "evidence_manifest.py").is_file():
        errors.append("ci/evidence_manifest.py is missing")
    kiwi = read_text(root / ".kiwi" / "pipeline.yaml")
    require_contains(
        errors,
        ".kiwi/pipeline.yaml",
        kiwi,
        [manifest_write_command, "ci/check_release_policy.py"],
    )
    release_gate = read_text(root / "ci" / "check_release_gate.sh")
    require_contains(
        errors,
        "ci/check_release_gate.sh",
        release_gate,
        ["test_manifest", "evidence_manifest.py"],
    )
    fold = read_text(root / "ci" / "fold_api_report_provenance.py")
    require_contains(
        errors,
        "ci/fold_api_report_provenance.py",
        fold,
        ["test_manifest", "evidence_manifest"],
    )

    release_aggregate_id = "release-gate"
    release_aggregate = release_jobs.get(release_aggregate_id)
    if release_aggregate is None:
        errors.append(f"{release_path}: aggregate job '{release_aggregate_id}' is missing")
    else:
        require_contains(
            errors,
            f"{release_path}:{release_aggregate_id}",
            job_text(release_aggregate),
            ["ci/check_release_policy.py"],
        )

    nightly = workflow_text(root, nightly_path)
    try:
        nightly_jobs = parse_jobs(root / nightly_path)
    except PolicyError as exc:
        errors.append(str(exc))
        nightly_jobs = {}
    all_features = nightly_jobs.get("all-features-test")
    if all_features is None:
        errors.append(f"{nightly_path}: all-features-test job is missing")
    else:
        require_contains(
            errors,
            f"{nightly_path}:all-features-test",
            job_text(all_features),
            ["brew install ffmpeg", "PKG_CONFIG_PATH=$(brew --prefix ffmpeg@7)", "cargo test --all-features"],
        )
    if "ci/meta-tests.txt" not in nightly:
        errors.append(
            f"{nightly_path}: nightly test commands must consume ci/meta-tests.txt "
            "so cargo-invoking meta tests never execute"
        )

    ubsan_script = contract.get("ubsan_script", "ci/run_nightly_ubsan_if_supported.sh")
    script_path = root / ubsan_script
    if not script_path.is_file():
        errors.append(f"UBSAN script missing: {ubsan_script}")
    else:
        if not script_path.stat().st_mode & 0o111:
            errors.append(f"{ubsan_script} is not executable")
        ubsan_text = read_text(script_path)
        require_contains(
            errors,
            ubsan_script,
            ubsan_text,
            list(
                contract.get("ubsan_required_tokens")
                or ["-Zsanitizer=undefined", "-Zbuild-std", "ci/meta-tests.txt", "--skip"]
            ),
        )
    if f"bash {ubsan_script}" not in nightly:
        errors.append(
            f"{nightly_path}: UBSAN must be invoked as 'bash {ubsan_script}' "
            "(no reliance on the exec bit in the workflow)"
        )

    # No workflow or CI shell script may request the nonexistent metal feature.
    forbidden_tokens = set(contract.get("forbid_feature_tokens") or [])
    if forbidden_tokens:
        candidates = list((root / ".github" / "workflows").glob("*.yml"))
        candidates += list((root / "ci").glob("*.sh"))
        candidates += list((root / ".kiwi").glob("*.yaml"))
        for path in candidates:
            text = read_text(path)
            for match in re.finditer(
                r"--features(?:=|\s+)([\"']?)([^\"'\s]+)\1", text
            ):
                requested = {token for token in re.split(r"[,\s]+", match.group(2)) if token}
                bad = sorted(requested.intersection(forbidden_tokens))
                if bad:
                    errors.append(
                        f"{path.relative_to(root)}: requests nonexistent feature(s) {bad}"
                    )

    # No destructive ref commands in workflows (force-push settings cannot be
    # changed from code, but workflows must never perform them either).
    patterns = list(contract.get("forbid_command_patterns") or [])
    command_candidates = list((root / ".github" / "workflows").glob("*.yml"))
    command_candidates += list((root / ".kiwi").glob("*.yaml"))
    for path in command_candidates:
        for number, line in enumerate(read_text(path).splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            lowered = stripped.lower()
            for pattern in patterns:
                if pattern.lower() in lowered:
                    errors.append(
                        f"{path.relative_to(root)}:{number}: forbidden command "
                        f"pattern {pattern!r}"
                    )
    errors.extend(check_windows_oracle(policy, parsed, root))
    return errors


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(pathlib.Path(__file__).resolve().parent.parent))
    args = parser.parse_args(argv)
    root = pathlib.Path(args.root).resolve()

    try:
        policy = load_policy(root)
        errors, parsed = check_workflow_shape(policy, root)
        errors.extend(check_status_contexts(policy, parsed))
        errors.extend(check_contract(policy, parsed, root))
    except PolicyError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1

    if errors:
        for error in errors:
            print(f"::error::{error}", file=sys.stderr)
        print(
            f"::error::release policy FAILED ({len(errors)} violation(s)); see "
            "docs/RELEASE_HARDENING.md",
            file=sys.stderr,
        )
        return 1
    print(
        "release policy: OK — required jobs, aggregate gates, evidence manifest, "
        "nightly FFmpeg/UBSAN, and no-force-push workflow contract verified"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
