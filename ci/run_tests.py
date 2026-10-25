#!/usr/bin/env python3
"""Run ONLY adversarial tests, optionally only those affected by the change.

Sanctioned entry point for all agents and CI. Happy-path tests never run here.

Modes:
    ci/run_tests.py --module msi          # adversarial tests whose name has "msi"
    ci/run_tests.py --affected            # adversarial tests for changed code only
    ci/run_tests.py --all-targets --affected --coverage
                                          # central gate: affected + 100% changed-line coverage

The runner serializes through a lock so concurrent sessions cannot duplicate
compute.
"""

from __future__ import annotations

import argparse
import fcntl
import glob
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "ci"))

from affected import affected_prefixes, changed_rs_files, name_matches  # noqa: E402
from test_classification import gather  # noqa: E402


def adversarial_names() -> set[str]:
    adversarial, _, _, _, _ = gather()
    return set(adversarial)


def load_expectations() -> dict[str, list[str]]:
    path = ROOT / "ci" / "expectations.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def llvm_tool(name: str) -> str | None:
    override = os.environ.get(f"{name.upper().replace('-', '_')}")
    if override and pathlib.Path(override).is_file():
        return override
    # Prefer the LLVM tools shipped with the active Rust toolchain: their
    # raw-profile format is guaranteed to match the instrumented binaries.
    sysroot = subprocess.run(
        ["rustc", "--print", "sysroot"], capture_output=True, text=True
    ).stdout.strip()
    version = subprocess.run(
        ["rustc", "-vV"], capture_output=True, text=True
    ).stdout
    host = next(
        (line.split(":", 1)[1].strip() for line in version.splitlines()
         if line.startswith("host:")),
        None,
    )
    candidates = []
    if sysroot and host:
        candidates.append(f"{sysroot}/lib/rustlib/{host}/bin/{name}")
    candidates.extend([
        f"/opt/homebrew/opt/llvm@21/bin/{name}",
        f"/opt/homebrew/opt/llvm/bin/{name}",
        f"/usr/local/opt/llvm/bin/{name}",
    ])
    for candidate in candidates:
        if pathlib.Path(candidate).is_file():
            return candidate
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = pathlib.Path(directory) / name
        if candidate.is_file():
            return str(candidate)
    return None


def build_target(args: list[str], env: dict[str, str] | None = None) -> pathlib.Path | None:
    command = ["cargo", "test", *args, "--no-run", "--message-format=json"]
    print(f":: building: {' '.join(command)}")
    result = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, env=env
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        return None
    executable: pathlib.Path | None = None
    for line in result.stdout.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("reason") == "compiler-artifact" and record.get("executable"):
            executable = pathlib.Path(record["executable"])
    return executable


def list_tests(binary: pathlib.Path, env: dict[str, str] | None = None) -> list[str]:
    result = subprocess.run(
        [str(binary), "--list"], capture_output=True, text=True, env=env
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        return []
    return [
        line[: -len(": test")].strip()
        for line in result.stdout.splitlines()
        if line.endswith(": test")
    ]


def select(
    names: list[str],
    adversarial: set[str],
    prefixes: set[str] | None,
    module: str | None,
) -> list[str]:
    selected = []
    for name in names:
        if name.rsplit("::", 1)[-1] not in adversarial:
            continue
        if prefixes is not None and not name_matches(name, prefixes):
            continue
        if module is not None and module not in name:
            continue
        selected.append(name)
    return selected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", action="store_true")
    parser.add_argument("--bins", action="store_true")
    parser.add_argument("--test", action="append", default=[])
    parser.add_argument("--all-targets", action="store_true")
    parser.add_argument("--tests-only", action="store_true",
                        help="integration test files only (no lib)")
    parser.add_argument("--module", default=None)
    parser.add_argument("--affected", action="store_true")
    parser.add_argument("--base", default=None)
    parser.add_argument("--coverage", action="store_true")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()

    lock_path = pathlib.Path("/tmp/casa1-test-runner.lock")
    lock_file = open(lock_path, "w")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print(":: another test run is active; waiting for the lock")
        fcntl.flock(lock_file, fcntl.LOCK_EX)

    prefixes: set[str] | None = None
    changed_targets: set[str] = set()
    base = args.base
    if args.affected:
        files = changed_rs_files(base)
        if not files:
            print(":: no affected Rust files — nothing to test (no cold code)")
            return 0
        prefixes, changed_targets = affected_prefixes(files)
        print(f":: affected: {len(files)} file(s)")
        for path in files:
            print(f"::   {path.relative_to(ROOT)}")

    targets: list[tuple[list[str], str]] = []
    if (args.all_targets or args.lib) and not args.tests_only:
        targets.append((["--lib"], "lib"))
    if args.all_targets or args.tests_only:
        for path in sorted((ROOT / "tests").glob("*.rs")):
            targets.append((["--test", path.stem], path.stem))
    for name in args.test:
        targets.append((["--test", name], name))
    if args.bins:
        targets.append((["--bins"], "bins"))
    if not targets:
        parser.error("pass --lib, --test <name>, or --all-targets")

    coverage_dir: pathlib.Path | None = None
    coverage_env: dict[str, str] | None = None
    profraw_dirs: list[pathlib.Path] = []
    binaries: list[pathlib.Path] = []
    if args.coverage:
        coverage_dir = pathlib.Path(tempfile.mkdtemp(prefix="casa1-cov-"))
        coverage_env = os.environ.copy()
        existing = coverage_env.get("RUSTFLAGS", "")
        coverage_env["RUSTFLAGS"] = (existing + " -Cinstrument-coverage").strip()
        print(f":: coverage instrumentation enabled ({coverage_dir})")

    adversarial = adversarial_names()
    expectations = load_expectations()
    failures: list[tuple[str, str, str]] = []
    total_run = 0

    for target_args, label in targets:
        env = coverage_env
        binary = build_target(target_args, env=env)
        if binary is None:
            return 1
        compiled = list_tests(binary, env=env)
        if args.affected:
            if label in changed_targets:
                target_prefixes = None  # whole changed test target
            else:
                target_prefixes = prefixes
            selected = select(compiled, adversarial, target_prefixes, args.module)
        else:
            selected = select(compiled, adversarial, None, args.module)
        print(f":: {label}: {len(selected)} adversarial tests selected "
              f"(of {len(compiled)} compiled)")
        if args.list:
            for name in selected:
                print(name)
            continue
        binaries.append(binary)
        if args.coverage and coverage_dir is not None:
            profile_dir = coverage_dir / f"{label}-profiles"
            profile_dir.mkdir(parents=True, exist_ok=True)
            profraw_dirs.append(profile_dir)
        for name in selected:
            short = name.rsplit("::", 1)[-1]
            if short not in adversarial:
                print(f":: {name}: no pinned expectation (skipped)")
                continue
            total_run += 1
            run_env = coverage_env
            if args.coverage and coverage_dir is not None:
                run_env = dict(os.environ)
                run_env["LLVM_PROFILE_FILE"] = str(
                    coverage_dir / f"{label}-profiles" / "%p-%m.profraw"
                )
            result = subprocess.run(
                [str(binary), "--exact", name, "--nocapture"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=600,
                env=run_env,
            )
            if result.returncode != 0:
                expected = expectations.get(short, [])
                expectation_text = (
                    "\n:: expected: " + " | ".join(expected) if expected else ""
                )
                failures.append(
                    (label, name, (result.stdout + result.stderr)[-4000:] + expectation_text)
                )

    if args.list:
        return 0

    print(f":: ran {total_run} adversarial tests across {len(targets)} target(s)")
    if failures:
        for label, name, output in failures:
            print(f":: FAILED [{label}] {name}")
            print(output)
        print(f":: {len(failures)} failure(s)")
        return 1

    if args.coverage and coverage_dir is not None:
        profdata = llvm_tool("llvm-profdata")
        llvm_cov = llvm_tool("llvm-cov")
        if not profdata or not llvm_cov:
            print(":: coverage: llvm-profdata/llvm-cov not found")
            return 1
        profraws = [
            item
            for directory in profraw_dirs
            for item in glob.glob(str(directory / "*.profraw"))
        ]
        if not profraws:
            print(":: coverage: no profile data recorded (no tests ran?)")
            return 0
        merged = coverage_dir / "merged.profdata"
        merge = subprocess.run(
            [profdata, "merge", "-sparse", *profraws, "-o", str(merged)],
            capture_output=True,
            text=True,
        )
        if merge.returncode != 0:
            sys.stderr.write(merge.stderr)
            return 1
        lcov = coverage_dir / "lcov.info"
        export = subprocess.run(
            [
                llvm_cov,
                "export",
                "-format=lcov",
                f"-instr-profile={merged}",
                *[str(binary) for binary in binaries],
            ],
            capture_output=True,
            text=True,
        )
        if export.returncode != 0:
            sys.stderr.write(export.stderr)
            return 1
        lcov.write_text(export.stdout, encoding="utf-8")
        gate = subprocess.run(
            [
                sys.executable,
                str(ROOT / "ci" / "coverage_gate.py"),
                "--lcov",
                str(lcov),
                *(["--base", base] if base else []),
            ],
            cwd=ROOT,
        )
        keep = os.environ.get("CASA1_KEEP_COVERAGE") == "1"
        if not keep:
            shutil.rmtree(coverage_dir, ignore_errors=True)
        else:
            print(f":: coverage artifacts kept in {coverage_dir}")
        if gate.returncode != 0:
            return gate.returncode

    print(":: all selected adversarial tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
