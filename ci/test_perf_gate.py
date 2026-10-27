#!/usr/bin/env python3
"""Adversarial self-tests for the performance gate.

Each case feeds synthetic Criterion estimates/KPI values into
``ci/check_perf.py`` and pins the exact exit code and diagnostic message.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

GATE = Path(__file__).resolve().parent / "check_perf.py"
FILTER = "gate/kpi"
SCHEMA = 1


def estimates(median: float, low: float, high: float) -> dict:
    return {
        "median": {
            "point_estimate": median,
            "confidence_interval": {
                "confidence_level": 0.95,
                "lower_bound": low,
                "upper_bound": high,
            },
        }
    }


def timing_entry(median: float, low: float, high: float) -> dict:
    return {
        "kind": "timing",
        "unit": "ns",
        "direction": "lower",
        "threshold": {"rel": 0.15, "abs": 0.0},
        "baseline": {"median": median, "ci_low": low, "ci_high": high},
        "source": "self-test",
    }


def kpi_entry(value: float, available: bool = True) -> dict:
    if not available:
        return {
            "kind": "kpi",
            "available": False,
            "reason": "self-test unavailable reason",
            "source": "self-test",
        }
    return {
        "kind": "kpi",
        "unit": "ratio",
        "direction": "lower",
        "threshold": {"rel": 0.0, "abs": 0.01},
        "baseline": {"value": value},
        "available": True,
        "source": "self-test",
    }


def baseline(entries: dict) -> dict:
    return {
        "schema": SCHEMA,
        "generated_at": "self-test",
        "filter": FILTER,
        "platform": {"os": "test", "arch": "test"},
        "native_baseline": {"available": False, "reason": "self-test"},
        "entries": entries,
    }


def run_case(
    name: str,
    baseline_entries: dict,
    estimate_docs: dict[str, dict],
    kpi_metrics: dict[str, dict],
    thresholds: dict | None = None,
    report: bool = False,
) -> tuple[int, str, dict | None]:
    with tempfile.TemporaryDirectory(prefix=f"casa1-perf-{name}-") as directory:
        root = Path(directory)
        estimate_root = root / "criterion"
        for benchmark, document in estimate_docs.items():
            path = estimate_root / benchmark / "new" / "estimates.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(document), encoding="utf-8")
        baseline_path = root / "baseline.json"
        baseline_path.write_text(json.dumps(baseline(baseline_entries)), encoding="utf-8")
        kpi_path = root / "kpi.json"
        kpi_path.write_text(
            json.dumps({"schema": 1, "metrics": kpi_metrics}), encoding="utf-8"
        )
        command = [
            sys.executable,
            str(GATE),
            "--estimates-dir",
            str(estimate_root),
            "--kpi-file",
            str(kpi_path),
            "--baseline",
            str(baseline_path),
            "--filter",
            FILTER,
            "--no-run",
        ]
        if thresholds is not None:
            threshold_path = root / "thresholds.json"
            threshold_path.write_text(json.dumps(thresholds), encoding="utf-8")
            command.extend(["--thresholds", str(threshold_path)])
        report_path = root / "report.json"
        if report:
            command.extend(["--report-json", str(report_path)])
        completed = subprocess.run(command, capture_output=True, text=True)
        report_doc = None
        if report and report_path.is_file():
            report_doc = json.loads(report_path.read_text(encoding="utf-8"))
        return completed.returncode, completed.stdout + completed.stderr, report_doc


CASES: list[tuple[str, int, str]] = []


def check(name: str, expected_code: int, expected_text: str) -> None:
    CASES.append((name, expected_code, expected_text))


def main() -> int:
    benchmark = "gate/kpi/synthetic"

    code, output, _ = run_case(
        "pass",
        {benchmark: timing_entry(1000.0, 950.0, 1050.0)},
        {benchmark: estimates(1000.0, 980.0, 1020.0)},
        {},
    )
    assert code == 0, (code, output)
    assert f"PASS {benchmark}" in output, output
    assert "RESULT PASS benchmarks=1" in output, output
    check("pass", code, "PASS gate/kpi/synthetic")

    code, output, _ = run_case(
        "regression",
        {benchmark: timing_entry(1000.0, 950.0, 1050.0)},
        {benchmark: estimates(1300.0, 1260.0, 1340.0)},
        {},
    )
    assert code == 2, (code, output)
    assert f"REGRESSION {benchmark}" in output, output
    assert "RESULT FAIL regressions=1 missing=0 mismatches=0" in output, output
    check("regression", code, "REGRESSION gate/kpi/synthetic")

    code, output, _ = run_case(
        "threshold-edge",
        {benchmark: timing_entry(1000.0, 950.0, 1050.0)},
        {benchmark: estimates(1150.0, 1100.0, 1200.0)},
        {},
    )
    assert code == 0, (code, output)
    assert f"THRESHOLD_EDGE {benchmark}" in output, output
    assert "threshold edge" in output, output
    check("threshold_edge", code, "THRESHOLD_EDGE gate/kpi/synthetic")

    code, output, _ = run_case(
        "ci-overlap",
        {benchmark: timing_entry(1000.0, 900.0, 1100.0)},
        {benchmark: estimates(1300.0, 1050.0, 1500.0)},
        {},
    )
    assert code == 0, (code, output)
    assert f"CI_OVERLAP {benchmark}" in output, output
    assert "confidence intervals overlap" in output, output
    check("ci_overlap", code, "CI_OVERLAP gate/kpi/synthetic")

    code, output, _ = run_case(
        "missing-benchmark",
        {benchmark: timing_entry(1000.0, 950.0, 1050.0)},
        {},
        {},
    )
    assert code == 3, (code, output)
    assert f"MISSING_BENCHMARK {benchmark}" in output, output
    assert "RESULT FAIL regressions=0 missing=1 mismatches=0" in output, output
    check("missing_benchmark", code, "MISSING_BENCHMARK gate/kpi/synthetic")

    metric = "kpi/synthetic_metric"
    code, output, _ = run_case(
        "kpi-regression",
        {metric: kpi_entry(0.10)},
        {},
        {"synthetic_metric": {"available": True, "value": 0.20, "unit": "ratio", "direction": "lower"}},
    )
    assert code == 2, (code, output)
    assert f"REGRESSION {metric}" in output, output
    check("kpi-regression", code, f"REGRESSION {metric}")

    code, output, _ = run_case(
        "kpi-unavailable",
        {"kpi/synthetic_unavailable": kpi_entry(0.0, available=False)},
        {},
        {},
    )
    assert code == 0, (code, output)
    assert "UNAVAILABLE kpi/synthetic_unavailable: self-test unavailable reason" in output, output
    check("kpi-unavailable", code, "UNAVAILABLE kpi/synthetic_unavailable")

    latency = "kpi/frame_latency_p50_us"
    absolute = dict(kpi_entry(1000.0))
    absolute["absolute_max"] = 2000.0
    code, output, _ = run_case(
        "absolute-target",
        {latency: absolute},
        {},
        {"frame_latency_p50_us": {"available": True, "value": 2500.0, "unit": "us", "direction": "lower"}},
    )
    assert code == 2, (code, output)
    assert f"TARGET_EXCEEDED {latency}" in output, output
    check("absolute-target", code, f"TARGET_EXCEEDED {latency}")

    pending = "kpi/synthetic_metric"
    code, output, _ = run_case(
        "kpi-baseline-pending",
        {pending: kpi_entry(0.0, available=False)},
        {},
        {
            "synthetic_metric": {
                "available": True,
                "value": 0.10,
                "unit": "ratio",
                "direction": "lower",
            }
        },
    )
    assert code == 0, (code, output)
    assert f"BASELINE_PENDING {pending}" in output, output
    assert "run --update to gate this metric" in output, output
    check("kpi-baseline-pending", code, f"BASELINE_PENDING {pending}")

    code, output, _ = run_case(
        "threshold-override",
        {benchmark: timing_entry(1000.0, 950.0, 1050.0)},
        {benchmark: estimates(1300.0, 1260.0, 1340.0)},
        {},
        thresholds={"timing": {benchmark: {"rel": 10.0, "abs": 0.0}}},
    )
    assert code == 0, (code, output)
    assert f"PASS {benchmark}" in output, output
    check("threshold-override", code, f"PASS {benchmark}")

    code, output, report = run_case(
        "report-json",
        {benchmark: timing_entry(1000.0, 950.0, 1050.0)},
        {benchmark: estimates(1000.0, 980.0, 1020.0)},
        {},
        report=True,
    )
    assert code == 0, (code, output)
    assert report is not None, output
    assert report["result"] == "pass", report
    assert report["entries"][0]["status"] == "PASS", report
    check("report-json", code, "report.json result=pass")

    print("SELFTEST PASS cases=11")
    for name, code, text in CASES:
        print(f"SELFTEST {name} exit={code} message={text}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
