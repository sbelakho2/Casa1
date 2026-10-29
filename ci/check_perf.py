#!/usr/bin/env python3
"""Casa1 performance KPI gate.

Runs a defined Criterion subset, reads the machine-readable Criterion
estimates, reads the benchmark-emitted KPI document, and compares both against
``ci/perf-baseline.json``.  A regression beyond the per-entry allowed delta
(and, for timing entries, outside the baseline confidence interval) fails the
gate.

Exit codes:
  0  pass (including explicitly unavailable KPIs)
  2  performance regression
  3  a baseline benchmark produced no estimates/KPI
  4  baseline/config mismatch (stale or unknown benchmark)
  5  the benchmark run itself failed
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

SCHEMA = 1
DEFAULT_FILTER = "gate/kpi"
DEFAULT_BASELINE = Path(__file__).resolve().parent / "perf-baseline.json"
DEFAULT_NATIVE = Path(__file__).resolve().parent / "perf-native-baseline.json"
DEFAULT_NATIVE_REPORT = Path("target") / "casa1-perf-native.json"
DEFAULT_CRITERION_DIR = Path("target") / "criterion"
EPSILON = 1e-9

EXIT_PASS = 0
EXIT_REGRESSION = 2
EXIT_MISSING = 3
EXIT_MISMATCH = 4
EXIT_RUN_FAILED = 5

# Machine-readable report entries accumulated by ``evaluate`` and written by
# ``--report-json``. Each entry records the exact status and diagnostic.
REPORT_ENTRIES: list[dict[str, Any]] = []
DISPATCH_REPORT: dict[str, Any] = {}
NATIVE_RELATIVE_ENTRIES: list[dict[str, Any]] = []


def report_entry(entry_id: str, status: str, detail: str, **extra: Any) -> None:
    REPORT_ENTRIES.append(
        {"id": entry_id, "status": status, "detail": detail, **extra}
    )

# Per-benchmark gates.  ``rel`` is the minimum relative increase that counts as
# a regression; ``abs`` is the floor in the benchmark's unit, so sub-noise
# differences on very fast benchmarks do not fail the gate.  ``absolute_max``
# encodes a documented end-user target (median/p99 latency).
TIMING_GATES: dict[str, dict[str, Any]] = {
    "gate/kpi/cpu_dispatch_nop_1024": {"rel": 0.50, "abs": 400.0},
    "gate/kpi/gfx_upload_allocate_64k": {"rel": 0.50, "abs": 20.0},
    "gate/kpi/gfx_command_batch_128": {"rel": 0.50, "abs": 8000.0},
    "gate/kpi/pe_parse_minimal": {"rel": 0.50, "abs": 500.0},
    "gate/kpi/frame_present_64x64": {"rel": 0.20, "abs": 200.0},
    "gate/kpi/thunk_resolve_256": {"rel": 0.50, "abs": 2000.0},
    "gate/kpi/shader_cache_hit": {"rel": 0.50, "abs": 2000.0},
}

KPI_GATES: dict[str, dict[str, Any]] = {
    "dispatcher_exits_per_1000_instructions": {"rel": 0.15, "abs": 0.5},
    "legacy_dispatch_mips": {
        "rel": 0.50,
        "abs": 10.0,
        "direction": "higher",
        "absolute_min": 50.0,
    },
    "native_chaining_rate": {"rel": 0.02, "abs": 0.01, "direction": "higher"},
    "indirect_ic_hit_rate": {"rel": 0.02, "abs": 0.01, "direction": "higher"},
    "generic_helper_rate": {"rel": 0.0, "abs": 0.0},
    "high_address_software_syncs_per_1000_instructions": {"rel": 0.0, "abs": 0.01},
    "high_address_guest_page_faults_per_access": {"rel": 0.0, "abs": 0.001},
    "thunk_generic_dispatch_rate": {"rel": 0.0, "abs": 0.0},
    "persistent_aot_hit_rate": {"rel": 0.02, "abs": 0.01, "direction": "higher"},
    "tier2_compile_hit_rate": {"rel": 0.02, "abs": 0.01, "direction": "higher"},
    "iat_patched": {"rel": 0.0, "abs": 0.0, "direction": "higher"},
    "iat_dispatch_bypasses": {"rel": 0.50, "abs": 1.0, "direction": "higher"},
    "iat_repatched": {"rel": 0.0, "abs": 0.0},
    "iat_invalidated": {"rel": 0.0, "abs": 0.0},
    "inline_api_registered_targets": {"rel": 0.0, "abs": 0.0, "direction": "higher"},
    "inline_api_call_total": {"rel": 0.0, "abs": 0.0, "direction": "higher"},
    "frame_latency_p50_us": {
        "rel": 0.10,
        "abs": 100.0,
        "absolute_max": 2000.0,
    },
    "frame_latency_p95_us": {"rel": 0.10, "abs": 200.0},
    "frame_latency_p99_us": {
        "rel": 0.10,
        "abs": 200.0,
        "absolute_max": 5000.0,
    },
    "frame_latency_p999_us": {"rel": 1.00, "abs": 500.0},
    "frame_latency_1pct_low_fps": {"rel": 0.90, "abs": 50000.0, "direction": "higher"},
    "frame_latency_0p1pct_low_fps": {
        "rel": 0.90,
        "abs": 20000.0,
        "direction": "higher",
    },
    "frame_interval_p50_us": {"rel": 0.15, "abs": 100.0},
    "frame_interval_p95_us": {"rel": 0.15, "abs": 200.0},
    "frame_interval_p99_us": {"rel": 0.15, "abs": 200.0},
    "frame_interval_p999_us": {"rel": 1.00, "abs": 500.0},
    "pso_compile_us": {"rel": 10.0, "abs": 100000.0},
    "pso_cache_hit_us": {"rel": 0.25, "abs": 10.0},
    "encoder_switches_per_1000_draws": {"rel": 0.0, "abs": 0.0},
    "shader_compile_stall_rate_cold": {"rel": 0.10, "abs": 0.05},
    "shader_compile_stall_rate_warm": {"rel": 0.0, "abs": 0.0},
    "gfx_staged_upload_copy_rate": {"rel": 0.0, "abs": 0.0},
    "gfx_barriers_required_per_1000_considered": {"rel": 0.0, "abs": 0.0},
    "gpu_idle_gap_us": {"rel": 0.20, "abs": 100.0},
    "gpu_frame_time_p50_us": {"rel": 0.10, "abs": 100.0, "absolute_max": 2000.0},
    "gpu_frame_time_p95_us": {"rel": 0.10, "abs": 200.0},
    "gpu_frame_time_p99_us": {"rel": 0.10, "abs": 200.0, "absolute_max": 5000.0},
    "gpu_frame_time_p999_us": {"rel": 1.00, "abs": 500.0},
    "gpu_frame_time_1pct_low_fps": {
        "rel": 0.90,
        "abs": 50000.0,
        "direction": "higher",
    },
    "gpu_frame_time_0p1pct_low_fps": {
        "rel": 0.90,
        "abs": 20000.0,
        "direction": "higher",
    },
    "gpu_time_p50_us": {"rel": 0.20, "abs": 100.0},
    "gpu_time_p99_us": {"rel": 0.20, "abs": 200.0},
    "cpu_submit_p50_us": {"rel": 0.20, "abs": 100.0},
    "cpu_submit_p99_us": {"rel": 0.20, "abs": 200.0},
    "input_to_present_p50_us": {"rel": 0.10, "abs": 100.0, "absolute_max": 2000.0},
    "input_to_present_p99_us": {"rel": 0.10, "abs": 200.0, "absolute_max": 5000.0},
    "input_to_gpu_completion_p50_us": {"rel": 0.15, "abs": 100.0},
    "input_to_gpu_completion_p99_us": {"rel": 0.15, "abs": 200.0},
    "host_cpu_time_p50_us": {"rel": 0.20, "abs": 100.0},
    "shader_compile_stall_rate_measured": {"rel": 0.10, "abs": 0.05},
    "guest_instructions_per_sec": {
        "rel": 0.50,
        "abs": 1000000.0,
        "direction": "higher",
    },
    "owner_barrier_ratio": {"rel": 0.10, "abs": 0.0},
    "time_per_1000_guest_instructions_ns": {"rel": 0.15, "abs": 0.0},
    "residency_churn_per_1000_frames": {"rel": 0.20, "abs": 1.0},
    "gpu_heap_faults_per_1000_frames": {"rel": 0.20, "abs": 1.0},
}

NATIVE_REASON = (
    "no native ARM64-equivalent reference binary/benchmark is checked in; "
    "supply ci/perf-native-baseline.json to enable native-relative ratios"
)


def gate_for(entry_id: str, kind: str) -> dict[str, Any]:
    if kind == "timing":
        return dict(TIMING_GATES.get(entry_id, {"rel": 0.20, "abs": 100.0}))
    metric = entry_id[len("kpi/") :] if entry_id.startswith("kpi/") else entry_id
    return dict(KPI_GATES.get(metric, {"rel": 0.20, "abs": 0.0}))


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def normalize_estimate_id(raw: str, filter_text: str) -> str:
    """Map Criterion's sanitized group directory back to the gate id."""
    criterion_prefix = filter_text.replace("/", "_")
    if raw == criterion_prefix:
        return filter_text
    if raw.startswith(criterion_prefix + "/"):
        return filter_text + "/" + raw[len(criterion_prefix) + 1 :]
    return raw


def criterion_estimates(
    root: Path, filter_text: str
) -> dict[str, dict[str, float]]:
    """Return {benchmark_id: {median, ci_low, ci_high}} from Criterion JSON."""
    estimates: dict[str, dict[str, float]] = {}
    if not root.exists():
        return estimates
    for path in root.rglob("new/estimates.json"):
        raw_id = path.parent.parent.relative_to(root).as_posix()
        benchmark_id = normalize_estimate_id(raw_id, filter_text)
        try:
            document = read_json(path)
            median = document["median"]
            value = float(median["point_estimate"])
            interval = median.get("confidence_interval") or {}
            low = float(interval.get("lower_bound", value))
            high = float(interval.get("upper_bound", value))
        except (KeyError, TypeError, ValueError) as error:
            raise SystemExit(f"invalid Criterion estimates in {path}: {error}")
        estimates[benchmark_id] = {
            "median": value,
            "ci_low": low,
            "ci_high": high,
        }
    return estimates


def kpi_values(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    document = read_json(path)
    metrics = document.get("metrics")
    if not isinstance(metrics, dict):
        raise SystemExit(f"invalid KPI document in {path}: missing metrics object")
    return metrics


def native_baseline(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"available": False, "reason": NATIVE_REASON}
    try:
        document = read_json(path)
    except (OSError, json.JSONDecodeError) as error:
        return {"available": False, "reason": f"unreadable native baseline: {error}"}
    document.setdefault("available", True)
    return document


def dispatch_report(path: Path) -> dict[str, Any]:
    """Return the runner's owner-barrier dispatch block from the KPI document."""
    if not path.exists():
        return {
            "available": False,
            "reason": (
                f"KPI document {path} is absent; run with CASA1_DISPATCH_STATS set "
                "to capture owner-barrier statistics"
            ),
        }
    try:
        document = read_json(path)
    except (OSError, json.JSONDecodeError) as error:
        return {
            "available": False,
            "reason": f"KPI document {path} is unreadable: {error}",
        }
    dispatch = document.get("dispatch")
    if not isinstance(dispatch, dict):
        return {
            "available": False,
            "reason": (
                f"KPI document {path} has no dispatch section; set "
                "CASA1_DISPATCH_STATS to a dispatch statistics file"
            ),
        }
    if not isinstance(dispatch.get("available"), bool):
        return {
            "available": False,
            "reason": "dispatch section is malformed: `available` must be a boolean",
        }
    return dispatch


def print_dispatch(dispatch: dict[str, Any]) -> None:
    if not dispatch.get("available"):
        print(f"DISPATCH unavailable: {dispatch.get('reason', 'dispatch statistics are unavailable')}")
        return
    ratio = dispatch.get("owner_barrier_ratio")
    time_per_1000 = dispatch.get("time_per_1000_guest_instructions_ns")
    reasons = dispatch.get("barrier_reasons") or {}
    reason_text = ",".join(f"{name}:{count}" for name, count in sorted(reasons.items())) or "none"
    ratio_text = f"{float(ratio):.6f}" if isinstance(ratio, (int, float)) else "unavailable"
    time_text = (
        f"{float(time_per_1000):.3f} ns"
        if isinstance(time_per_1000, (int, float))
        else "unavailable"
    )
    print(
        f"DISPATCH owner_barrier_ratio={ratio_text} "
        f"parallel={dispatch.get('parallel_dispatched')} "
        f"barrier={dispatch.get('barrier_calls')} barrier_reasons=[{reason_text}] "
        f"time_per_1000_guest_instructions={time_text}"
    )


def _side(side: Any) -> tuple[bool, int, str]:
    if not isinstance(side, dict):
        return False, 0, "side is missing from the native reference report"
    if not isinstance(side.get("available"), bool):
        return False, 0, "side is malformed: `available` must be a boolean"
    if not side["available"]:
        reason = side.get("reason")
        return (
            False,
            0,
            reason if isinstance(reason, str) else "side is unavailable without a reason",
        )
    wall_ns = side.get("wall_ns")
    if not isinstance(wall_ns, int) or isinstance(wall_ns, bool) or wall_ns < 0:
        return False, 0, "side is malformed: `wall_ns` must be a non-negative integer"
    return True, wall_ns, ""


def _cpu_ns(side: Any) -> int | None:
    if not isinstance(side, dict) or not side.get("available"):
        return None
    value = side.get("cpu_ns")
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return None
    return value


def native_relative_entries(path: Path) -> list[dict[str, Any]]:
    """Compute per-workload ``casa1_time / native_time`` without fabricating sides."""
    if not path.exists():
        return [
            {
                "status": "UNAVAILABLE",
                "reason": (
                    f"native reference report {path} is absent; run "
                    "`cargo run --bin perf_native` (or pass --native-report)"
                ),
            }
        ]
    try:
        document = read_json(path)
    except (OSError, json.JSONDecodeError) as error:
        return [
            {
                "status": "UNAVAILABLE",
                "reason": f"native reference report {path} is malformed: {error}",
            }
        ]
    workloads = document.get("workloads")
    if not isinstance(workloads, dict) or not workloads:
        return [
            {
                "status": "UNAVAILABLE",
                "reason": f"native reference report {path} has no workloads object",
            }
        ]
    entries: list[dict[str, Any]] = []
    for workload in sorted(workloads):
        measured = workloads[workload]
        if not isinstance(measured, dict):
            entries.append(
                {
                    "workload": workload,
                    "status": "UNAVAILABLE",
                    "reason": "workload entry is not an object; ratio refused",
                }
            )
            continue
        casa1_ok, casa1_wall, casa1_reason = _side(measured.get("casa1"))
        native_ok, native_wall, native_reason = _side(measured.get("native"))
        if not casa1_ok:
            entries.append(
                {
                    "workload": workload,
                    "status": "UNAVAILABLE",
                    "reason": f"Casa1 guest workload is unavailable: {casa1_reason}; ratio refused",
                    "casa1": measured.get("casa1"),
                    "native": measured.get("native"),
                }
            )
            continue
        if not native_ok:
            entries.append(
                {
                    "workload": workload,
                    "status": "UNAVAILABLE",
                    "reason": f"native reference workload is unavailable: {native_reason}; ratio refused",
                    "casa1": measured.get("casa1"),
                    "native": measured.get("native"),
                }
            )
            continue
        if casa1_wall == 0:
            entries.append(
                {
                    "workload": workload,
                    "status": "UNAVAILABLE",
                    "reason": "Casa1 guest workload measured zero wall time; ratio refused",
                    "casa1": measured.get("casa1"),
                    "native": measured.get("native"),
                }
            )
            continue
        if native_wall == 0:
            entries.append(
                {
                    "workload": workload,
                    "status": "UNAVAILABLE",
                    "reason": "native reference measured zero wall time; ratio refused",
                    "casa1": measured.get("casa1"),
                    "native": measured.get("native"),
                }
            )
            continue
        casa1_cpu = _cpu_ns(measured.get("casa1"))
        native_cpu = _cpu_ns(measured.get("native"))
        ratio_cpu = None
        if casa1_cpu is not None and native_cpu is not None and casa1_cpu > 0 and native_cpu > 0:
            ratio_cpu = casa1_cpu / native_cpu
        entries.append(
            {
                "workload": workload,
                "status": "RATIO",
                "ratio": casa1_wall / native_wall,
                "ratio_cpu": ratio_cpu,
                "casa1_wall_ns": casa1_wall,
                "native_wall_ns": native_wall,
                "casa1_cpu_ns": casa1_cpu,
                "native_cpu_ns": native_cpu,
                "casa1_allocations": (measured.get("casa1") or {}).get("allocations"),
                "native_allocations": (measured.get("native") or {}).get("allocations"),
            }
        )
    return entries


def print_native_relative(entries: list[dict[str, Any]]) -> None:
    for entry in entries:
        if entry.get("status") == "RATIO":
            cpu = entry.get("ratio_cpu")
            cpu_text = f"{float(cpu):.6f}" if isinstance(cpu, (int, float)) else "unavailable"
            print(
                f"NATIVE_RATIO {entry['workload']}: ratio={float(entry['ratio']):.6f} "
                f"casa1_wall_ns={entry['casa1_wall_ns']} native_wall_ns={entry['native_wall_ns']} "
                f"casa1_cpu_ns={entry['casa1_cpu_ns']} native_cpu_ns={entry['native_cpu_ns']} "
                f"casa1_allocations={entry['casa1_allocations']} "
                f"native_allocations={entry['native_allocations']} ratio_cpu={cpu_text}"
            )
        else:
            workload = entry.get("workload")
            prefix = f"NATIVE_UNAVAILABLE {workload}" if workload else "NATIVE_UNAVAILABLE"
            print(f"{prefix}: {entry.get('reason', 'ratio unavailable')}")


def parse_metric_lines(text: str) -> dict[str, dict[str, Any]]:
    """Parse the diagnostic lines already emitted by the JIT benchmarks.

    ``TIER2_HOT_LOOP``, ``IAT_METRICS`` and ``INLINE_API_STATS`` predate the
    KPI document.  Keeping a parser for them makes those existing signals part
    of the checked baseline instead of log-only trivia.
    """

    def fields(line: str) -> dict[str, str]:
        values: dict[str, str] = {}
        for part in line.split():
            if "=" in part:
                key, value = part.split("=", 1)
                values[key] = value
        return values

    def metric(value: str, unit: str, direction: str, source: str) -> dict[str, Any]:
        return {
            "available": True,
            "value": float(value),
            "unit": unit,
            "direction": direction,
            "source": source,
        }

    metrics: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("TIER2_HOT_LOOP "):
            values = fields(line)
            if "hit_rate" in values:
                metrics["tier2_compile_hit_rate"] = metric(
                    values["hit_rate"],
                    "compiled/(compiled+fallback)",
                    "higher",
                    "TIER2_HOT_LOOP benchmark line",
                )
        elif line.startswith("IAT_METRICS "):
            values = fields(line)
            for source, key, unit, direction in (
                ("patched", "iat_patched", "slots", "higher"),
                ("bypasses", "iat_dispatch_bypasses", "dispatches", "higher"),
                ("repatched", "iat_repatched", "slots", "lower"),
                ("invalidated", "iat_invalidated", "slots", "lower"),
            ):
                if source in values:
                    metrics[key] = metric(
                        values[source], unit, direction, "IAT_METRICS benchmark line"
                    )
        elif line.startswith("INLINE_API_STATS "):
            values = fields(line)
            if "registered_targets" in values:
                metrics["inline_api_registered_targets"] = metric(
                    values["registered_targets"],
                    "targets",
                    "higher",
                    "INLINE_API_STATS benchmark line",
                )
            if "inline_metric_total" in values:
                metrics["inline_api_call_total"] = metric(
                    values["inline_metric_total"],
                    "calls",
                    "higher",
                    "INLINE_API_STATS benchmark line",
                )
    return metrics


def run_benchmarks(filter_text: str, kpi_path: Path) -> tuple[int, str]:
    criterion_gate_dir = DEFAULT_CRITERION_DIR / filter_text.replace("/", "_")
    shutil.rmtree(criterion_gate_dir, ignore_errors=True)
    environment = dict(os.environ)
    environment["CASA1_PERF_KPI_OUT"] = str(kpi_path)
    command = [
        "cargo",
        "bench",
        "--bench",
        "perf_benchmarks",
        "--",
        "--quick",
        filter_text,
    ]
    print(f"RUN {' '.join(command)}")
    completed = subprocess.run(
        command,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    print(completed.stdout)
    if completed.returncode != 0:
        print(f"RUN_FAILED cargo bench exited {completed.returncode}")
        return EXIT_RUN_FAILED, completed.stdout
    return EXIT_PASS, completed.stdout


def build_baseline(
    estimates: dict[str, dict[str, float]],
    kpis: dict[str, dict[str, Any]],
    filter_text: str,
    native: dict[str, Any],
) -> dict[str, Any]:
    entries: dict[str, Any] = {}
    for benchmark_id, observed in sorted(estimates.items()):
        gate = gate_for(benchmark_id, "timing")
        entries[benchmark_id] = {
            "kind": "timing",
            "unit": "ns",
            "direction": gate.get("direction", "lower"),
            "threshold": {key: gate[key] for key in ("rel", "abs") if key in gate},
            "baseline": observed,
            "source": "criterion",
        }
        for key in ("absolute_max", "absolute_min"):
            if key in gate:
                entries[benchmark_id][key] = gate[key]
    for metric, observed in sorted(kpis.items()):
        entry_id = f"kpi/{metric}"
        if observed.get("available"):
            gate = gate_for(entry_id, "kpi")
            entries[entry_id] = {
                "kind": "kpi",
                "unit": observed.get("unit", ""),
                "direction": observed.get("direction", gate.get("direction", "lower")),
                "threshold": {key: gate[key] for key in ("rel", "abs") if key in gate},
                "baseline": {"value": float(observed["value"])},
                "source": observed.get("source", "benchmark KPI"),
                "available": True,
            }
            for key in ("absolute_max", "absolute_min"):
                if key in gate:
                    entries[entry_id][key] = gate[key]
        else:
            entries[entry_id] = {
                "kind": "kpi",
                "available": False,
                "reason": observed.get("reason", "metric reported unavailable"),
                "source": "benchmark KPI",
            }
    return {
        "schema": SCHEMA,
        "generated_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(),
        "filter": filter_text,
        "platform": {"os": sys.platform, "arch": platform.machine()},
        "native_baseline": native,
        "entries": entries,
    }


def allowed_delta(entry: dict[str, Any], baseline: float) -> float:
    threshold = entry.get("threshold") or {}
    relative = float(threshold.get("rel", 0.0) or 0.0)
    absolute = float(threshold.get("abs", 0.0) or 0.0)
    return max(absolute, relative * abs(baseline))


def compare(entry_id: str, entry: dict[str, Any], observed: dict[str, Any]) -> tuple[str, str]:
    """Return (status, detail). status is PASS/REGRESSION/THRESHOLD_EDGE/CI_OVERLAP/TARGET_EXCEEDED."""
    stored = entry["baseline"]
    baseline = float(stored["median"] if "median" in stored else stored["value"])
    median = float(observed["median"])
    direction = entry.get("direction", "lower")
    allowed = allowed_delta(entry, baseline)
    delta = median - baseline if direction == "lower" else baseline - median
    regressed = delta > allowed + EPSILON
    at_edge = abs(delta - allowed) <= EPSILON

    absolute_max = entry.get("absolute_max")
    if absolute_max is not None and direction == "lower" and median > float(absolute_max):
        return (
            "TARGET_EXCEEDED",
            f"median={median:.6g} exceeds documented target {float(absolute_max):.6g}",
        )
    absolute_min = entry.get("absolute_min")
    if absolute_min is not None and direction == "higher" and median < float(absolute_min):
        return (
            "TARGET_EXCEEDED",
            f"median={median:.6g} is below the legacy absolute floor {float(absolute_min):.6g}",
        )

    if not regressed:
        suffix = "threshold edge" if at_edge else "within threshold"
        return (
            "THRESHOLD_EDGE" if at_edge else "PASS",
            f"median={median:.6g} baseline={baseline:.6g} delta={delta:.6g} allowed={allowed:.6g} ({suffix})",
        )

    ci_low = observed.get("ci_low")
    ci_high = observed.get("ci_high")
    base_low = entry["baseline"].get("ci_low")
    base_high = entry["baseline"].get("ci_high")
    if ci_low is not None and ci_high is not None and base_low is not None and base_high is not None:
        if direction == "lower":
            separated = float(ci_low) > float(base_high)
        else:
            separated = float(ci_high) < float(base_low)
        if not separated:
            return (
                "CI_OVERLAP",
                f"median={median:.6g} baseline={baseline:.6g} delta={delta:.6g} allowed={allowed:.6g} "
                f"new_ci=[{float(ci_low):.6g},{float(ci_high):.6g}] "
                f"baseline_ci=[{float(base_low):.6g},{float(base_high):.6g}] (confidence intervals overlap)",
            )
    return (
        "REGRESSION",
        f"median={median:.6g} baseline={baseline:.6g} delta={delta:.6g} allowed={allowed:.6g}",
    )


def evaluate(
    baseline: dict[str, Any],
    estimates: dict[str, dict[str, float]],
    kpis: dict[str, dict[str, Any]],
    estimates_root: Path,
    kpi_path: Path,
) -> int:
    entries = baseline.get("entries")
    if not isinstance(entries, dict) or not entries:
        print("BASELINE_MISMATCH entries: baseline has no entries")
        return EXIT_MISMATCH

    regressions = 0
    missing = 0
    mismatches = 0
    failures: list[str] = []
    checked = 0

    # Detect estimates/KPIs that are not gated by the checked-in baseline.
    for benchmark_id in sorted(estimates):
        if benchmark_id not in entries:
            detail = "Criterion estimate is not in the baseline; run --update"
            print(f"BASELINE_MISMATCH {benchmark_id}: {detail}")
            report_entry(benchmark_id, "BASELINE_MISMATCH", detail)
            mismatches += 1
    for metric in sorted(kpis):
        entry_id = f"kpi/{metric}"
        if entry_id not in entries:
            detail = "KPI is not in the baseline; run --update"
            print(f"BASELINE_MISMATCH {entry_id}: {detail}")
            report_entry(entry_id, "BASELINE_MISMATCH", detail)
            mismatches += 1

    for entry_id, entry in sorted(entries.items()):
        kind = entry.get("kind", "timing")
        if kind == "timing":
            if entry_id not in estimates:
                detail = (
                    "no Criterion estimates under "
                    f"{estimates_root / entry_id / 'new' / 'estimates.json'}"
                )
                print(f"MISSING_BENCHMARK {entry_id}: {detail}")
                report_entry(entry_id, "MISSING_BENCHMARK", detail)
                missing += 1
                continue
            status, detail = compare(entry_id, entry, estimates[entry_id])
            checked += 1
            report_entry(entry_id, status, detail, kind="timing")
            if status == "REGRESSION":
                print(f"REGRESSION {entry_id}: {detail}")
                failures.append(entry_id)
                regressions += 1
            elif status == "TARGET_EXCEEDED":
                print(f"TARGET_EXCEEDED {entry_id}: {detail}")
                failures.append(entry_id)
                regressions += 1
            else:
                print(f"{status} {entry_id}: {detail}")
        else:
            metric = entry_id[len("kpi/") :] if entry_id.startswith("kpi/") else entry_id
            if not entry.get("available", True):
                observed = kpis.get(metric)
                if observed is not None and observed.get("available"):
                    detail = (
                        "real samples present but the baseline entry is unavailable; "
                        "run --update to gate this metric"
                    )
                    print(f"BASELINE_PENDING {entry_id}: {detail}")
                    report_entry(entry_id, "BASELINE_PENDING", detail, kind="kpi")
                else:
                    reason = entry.get("reason", "metric recorded unavailable")
                    print(f"UNAVAILABLE {entry_id}: {reason}")
                    report_entry(entry_id, "UNAVAILABLE", reason, kind="kpi")
                continue
            if metric not in kpis:
                detail = (
                    f"KPI document {kpi_path} has no entry "
                    "(emitted by the gate/kpi benchmark)"
                )
                print(f"MISSING_BENCHMARK {entry_id}: {detail}")
                report_entry(entry_id, "MISSING_BENCHMARK", detail, kind="kpi")
                missing += 1
                continue
            observed = kpis[metric]
            if not observed.get("available"):
                reason = observed.get("reason", "metric reported unavailable")
                detail = (
                    "baseline requires this KPI but the run reported it unavailable: "
                    f"{reason}"
                )
                print(f"UNAVAILABLE {entry_id}: {detail}")
                report_entry(
                    entry_id,
                    "UNAVAILABLE",
                    detail,
                    kind="kpi",
                    baseline_available=True,
                )
                missing += 1
                continue
            value = float(observed["value"])
            status, detail = compare(
                entry_id,
                entry,
                {"median": value, "ci_low": None, "ci_high": None},
            )
            checked += 1
            report_entry(
                entry_id,
                status,
                detail,
                kind="kpi",
                value=value,
                unit=observed.get("unit", ""),
            )
            if status in ("REGRESSION", "TARGET_EXCEEDED"):
                print(f"{status} {entry_id}: {detail}")
                failures.append(entry_id)
                regressions += 1
            else:
                print(f"{status} {entry_id}: {detail}")

    native = baseline.get("native_baseline") or {}
    if native.get("available"):
        print(f"NATIVE_BASELINE available: {native.get('source', 'checked-in reference')}")
        native_metrics = native.get("metrics") or {}
        warn_ratio = float(native.get("ratio_warn", 1.10))
        limit_ratio = float(native.get("ratio_limit", 1.20))
        for entry_id, entry in sorted(entries.items()):
            if entry.get("kind") != "timing" or entry_id not in estimates:
                continue
            native_value = native_metrics.get(entry_id)
            if not isinstance(native_value, (int, float)) or native_value <= 0:
                print(f"NATIVE_UNAVAILABLE {entry_id}: no native reference value")
                continue
            ratio = float(estimates[entry_id]["median"]) / float(native_value)
            if ratio > limit_ratio + EPSILON:
                print(
                    f"TARGET_EXCEEDED native/{entry_id}: ratio={ratio:.4f} > "
                    f"{limit_ratio:.4f} (native={native_value:.6g})"
                )
                regressions += 1
            elif ratio > warn_ratio + EPSILON:
                print(
                    f"WARN native/{entry_id}: ratio={ratio:.4f} exceeds soft target "
                    f"{warn_ratio:.4f} (limit {limit_ratio:.4f})"
                )
            else:
                print(f"NATIVE_RATIO {entry_id}: {ratio:.4f} <= {warn_ratio:.4f}")
    else:
        print(f"NATIVE_BASELINE unavailable: {native.get('reason', NATIVE_REASON)}")

    if missing:
        print(f"RESULT FAIL regressions={regressions} missing={missing} mismatches={mismatches}")
        return EXIT_MISSING if not mismatches else EXIT_MISMATCH
    if mismatches:
        print(f"RESULT FAIL regressions={regressions} missing={missing} mismatches={mismatches}")
        return EXIT_MISMATCH
    if regressions:
        print(f"RESULT FAIL regressions={regressions} missing=0 mismatches=0")
        return EXIT_REGRESSION
    print(f"RESULT PASS benchmarks={checked}")
    return EXIT_PASS


def apply_threshold_overrides(path: Path) -> dict[str, Any]:
    """Merge a JSON threshold document over the built-in gate table.

    The document may contain ``timing`` and ``kpi`` objects keyed by gate id
    (``gate/kpi/...`` for timing, metric name for KPI). Values are partial
    threshold objects (``rel``, ``abs``, ``direction``, ``absolute_max``).
    The same document is applied to already-loaded baseline entries so a gate
    run can use a stricter/looser budget without regenerating the baseline.
    """
    document = read_json(path)
    for group, target in (("timing", TIMING_GATES), ("kpi", KPI_GATES)):
        overrides = document.get(group) or {}
        if not isinstance(overrides, dict):
            raise SystemExit(f"invalid threshold override in {path}: {group} must be an object")
        for key, value in overrides.items():
            if not isinstance(value, dict):
                raise SystemExit(
                    f"invalid threshold override in {path}: {group}.{key} must be an object"
                )
            target.setdefault(key, {}).update(value)
    return document


def apply_thresholds_to_baseline(baseline: dict[str, Any], document: dict[str, Any]) -> None:
    entries = baseline.get("entries")
    if not isinstance(entries, dict):
        return
    timing = document.get("timing") or {}
    kpi = document.get("kpi") or {}
    for entry_id, entry in entries.items():
        if not isinstance(entry, dict):
            continue
        kind = entry.get("kind", "timing")
        metric = entry_id[len("kpi/") :] if entry_id.startswith("kpi/") else entry_id
        override = timing.get(entry_id) if kind == "timing" else kpi.get(metric)
        if not isinstance(override, dict):
            continue
        threshold = dict(entry.get("threshold") or {})
        for key in ("rel", "abs"):
            if key in override:
                threshold[key] = override[key]
        entry["threshold"] = threshold
        for key in ("direction", "absolute_max", "absolute_min"):
            if key in override:
                entry[key] = override[key]


def write_report(path: Path, exit_code: int, baseline_path: Path) -> None:
    global DISPATCH_REPORT, NATIVE_RELATIVE_ENTRIES
    status = {
        EXIT_PASS: "pass",
        EXIT_REGRESSION: "regression",
        EXIT_MISSING: "missing",
        EXIT_MISMATCH: "mismatch",
        EXIT_RUN_FAILED: "run_failed",
    }.get(exit_code, "error")
    write_json(
        path,
        {
            "schema": 1,
            "generated_at": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).isoformat(),
            "baseline": str(baseline_path),
            "result": status,
            "exit_code": exit_code,
            "dispatch": DISPATCH_REPORT,
            "native_relative": NATIVE_RELATIVE_ENTRIES,
            "entries": REPORT_ENTRIES,
        },
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--update",
        action="store_true",
        help="run benchmarks and regenerate ci/perf-baseline.json from this clean run",
    )
    parser.add_argument("--filter", default=DEFAULT_FILTER, help="Criterion filter (default: gate/kpi)")
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--native-baseline", type=Path, default=DEFAULT_NATIVE)
    parser.add_argument(
        "--estimates-dir",
        type=Path,
        default=None,
        help="read synthetic/recorded Criterion estimates instead of running cargo bench",
    )
    parser.add_argument(
        "--kpi-file",
        type=Path,
        default=None,
        help="read a recorded CASA1_PERF_KPI document instead of running cargo bench",
    )
    parser.add_argument("--no-run", action="store_true", help="never invoke cargo bench")
    parser.add_argument(
        "--native-report",
        type=Path,
        default=DEFAULT_NATIVE_REPORT,
        help=(
            "native-relative report written by `cargo run --bin perf_native` "
            f"(default: {DEFAULT_NATIVE_REPORT})"
        ),
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=3,
        help="repeat the Criterion subset N times and keep the fastest median per benchmark (default: 3)",
    )
    parser.add_argument(
        "--thresholds",
        type=Path,
        default=None,
        help="JSON file overriding timing/kpi thresholds (configurable budget)",
    )
    parser.add_argument(
        "--report-json",
        type=Path,
        default=None,
        help="write a machine-readable gate report with per-entry status",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    global DISPATCH_REPORT, NATIVE_RELATIVE_ENTRIES
    args = parse_args(argv)
    threshold_document = (
        apply_threshold_overrides(args.thresholds)
        if args.thresholds is not None
        else None
    )
    native = native_baseline(args.native_baseline)

    if args.estimates_dir is not None or args.no_run:
        estimates_root = args.estimates_dir or DEFAULT_CRITERION_DIR
        estimates = criterion_estimates(estimates_root, args.filter)
        estimates = {
            key: value
            for key, value in estimates.items()
            if key == args.filter or key.startswith(args.filter.rstrip("/") + "/")
        }
        kpi_path = args.kpi_file or Path("target/casa1-perf-kpi.json")
        kpis = kpi_values(kpi_path)
    else:
        estimates_root = DEFAULT_CRITERION_DIR
        fastest: dict[str, dict[str, float]] = {}
        kpis: dict[str, dict[str, Any]] = {}
        kpi_path = Path("target/casa1-perf-kpi.json")
        for run in range(max(1, args.runs)):
            temporary = tempfile.NamedTemporaryFile(
                prefix="casa1-perf-kpi-", suffix=".json", delete=False
            )
            temporary.close()
            run_kpi_path = Path(temporary.name)
            try:
                print(f"RUN {run + 1}/{max(1, args.runs)}")
                result, output = run_benchmarks(args.filter, run_kpi_path)
                if result != EXIT_PASS:
                    return result
                run_estimates = criterion_estimates(estimates_root, args.filter)
                run_estimates = {
                    key: value
                    for key, value in run_estimates.items()
                    if key == args.filter or key.startswith(args.filter.rstrip("/") + "/")
                }
                if not kpis:
                    kpis = kpi_values(run_kpi_path)
                    for key, value in parse_metric_lines(output).items():
                        kpis.setdefault(key, value)
                    kpi_path = run_kpi_path.with_name("casa1-perf-kpi.json")
                    if run_kpi_path.exists():
                        shutil.copyfile(run_kpi_path, Path("target/casa1-perf-kpi.json"))
                    kpi_path = Path("target/casa1-perf-kpi.json")
                for key, value in run_estimates.items():
                    previous = fastest.get(key)
                    if previous is None or value["median"] < previous["median"]:
                        fastest[key] = value
            finally:
                run_kpi_path.unlink(missing_ok=True)
        estimates = fastest

    DISPATCH_REPORT = dispatch_report(kpi_path)
    NATIVE_RELATIVE_ENTRIES = native_relative_entries(args.native_report)
    print_dispatch(DISPATCH_REPORT)
    print_native_relative(NATIVE_RELATIVE_ENTRIES)

    if args.update:
        if not estimates and not kpis:
            print("BASELINE_MISMATCH: no estimates or KPI values were produced")
            return EXIT_MISMATCH
        baseline = build_baseline(estimates, kpis, args.filter, native)
        write_json(args.baseline, baseline)
        available = sum(1 for entry in baseline["entries"].values() if entry.get("available", True))
        unavailable = len(baseline["entries"]) - available
        print(
            f"UPDATED {args.baseline} entries={len(baseline['entries'])} "
            f"available={available} unavailable={unavailable}"
        )
        for entry_id, entry in sorted(baseline["entries"].items()):
            if entry.get("available", True):
                value = entry["baseline"].get("median", entry["baseline"].get("value"))
                print(f"BASELINE {entry_id} = {value} {entry.get('unit', '')}".rstrip())
            else:
                print(f"BASELINE {entry_id} UNAVAILABLE: {entry.get('reason', '')}")
        return EXIT_PASS

    if not args.baseline.exists():
        print(
            f"BASELINE_MISMATCH {args.baseline}: baseline does not exist; run "
            f"{Path(__file__).name} --update"
        )
        return EXIT_MISMATCH
    baseline = read_json(args.baseline)
    if threshold_document is not None:
        apply_thresholds_to_baseline(baseline, threshold_document)
    if int(baseline.get("schema", 0)) != SCHEMA:
        detail = f"schema {baseline.get('schema')} != {SCHEMA}"
        print(f"BASELINE_MISMATCH {args.baseline}: {detail}")
        report_entry(str(args.baseline), "BASELINE_MISMATCH", detail)
        exit_code = EXIT_MISMATCH
    else:
        exit_code = evaluate(baseline, estimates, kpis, estimates_root, kpi_path)
    if args.report_json is not None:
        write_report(args.report_json, exit_code, args.baseline)
    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
