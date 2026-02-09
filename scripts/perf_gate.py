#!/usr/bin/env python3
"""Criterion regression gate for hot-path benchmarks.

Reads Criterion change estimates from `target/criterion/**/change/estimates.json`
and fails when a benchmark regresses beyond a configured threshold.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BenchGate:
    name: str
    max_regression: float


DEFAULT_BENCHES = [
    # Stable legacy benchmark retained for cross-commit comparisons.
    BenchGate("collector/collect_medium_window", 0.10),
    # Newer throughput-focused benchmarks (may be absent on older baselines).
    BenchGate("buffer/ingest_mixed_events/16384", 0.10),
    BenchGate("collector/collect_window_reuse/512", 0.10),
    BenchGate("pipeline_parse_aggregate_collect_1024", 0.10),
]


def load_change(criterion_root: Path, bench_name: str) -> tuple[float, float, float]:
    candidates = [
        criterion_root / bench_name / "change" / "estimates.json",
        criterion_root / bench_name.replace("/", "_") / "change" / "estimates.json",
    ]

    path = next((candidate for candidate in candidates if candidate.exists()), None)
    if path is None:
        raise FileNotFoundError(
            f"missing change estimates for '{bench_name}': tried {candidates}"
        )

    payload = json.loads(path.read_text(encoding="utf-8"))
    mean = payload.get("mean", {})
    ci = mean.get("confidence_interval", {})

    point = float(mean.get("point_estimate"))
    lower = float(ci.get("lower_bound"))
    upper = float(ci.get("upper_bound"))
    return point, lower, upper


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fail on benchmark regressions.")
    parser.add_argument(
        "--criterion-root",
        default="target/criterion",
        help="Criterion output directory (default: target/criterion)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    criterion_root = Path(args.criterion_root)

    failures: list[str] = []
    evaluated = 0
    print("Benchmark regression gate:")

    for gate in DEFAULT_BENCHES:
        try:
            point, lower, upper = load_change(criterion_root, gate.name)
        except FileNotFoundError:
            print(f"  SKIP {gate.name}: no baseline comparison available")
            continue

        evaluated += 1
        point_pct = point * 100.0
        lower_pct = lower * 100.0
        upper_pct = upper * 100.0
        threshold_pct = gate.max_regression * 100.0

        # Require both a point-estimate regression beyond threshold and
        # a positive lower confidence bound to reduce flaky failures.
        regressed = point > gate.max_regression and lower > 0.0
        status = "FAIL" if regressed else "PASS"
        print(
            f"  {status} {gate.name}: "
            f"{point_pct:+.2f}% (95% CI {lower_pct:+.2f}%..{upper_pct:+.2f}%), "
            f"limit +{threshold_pct:.2f}%"
        )

        if regressed:
            failures.append(
                f"{gate.name}: regression {point_pct:+.2f}% exceeds +{threshold_pct:.2f}%"
            )

    if evaluated == 0:
        print("\nPerformance gate failed: no comparable benchmarks were found.")
        return 1

    if failures:
        print("\nPerformance gate failed:")
        for item in failures:
            print(f"  - {item}")
        return 1

    print("\nPerformance gate passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
