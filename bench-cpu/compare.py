#!/usr/bin/env python3
"""Compare CPU overhead benchmark results.

Takes 3 result JSON files, computes the median, and optionally compares to a
baseline. Outputs a human-readable summary and a JSON report. Always exits 0 —
this is a reporter, not a gate. Codex decides what to do with the numbers.

Usage:
    python3 compare.py run1.json run2.json run3.json [--baseline baseline.json] [--output report.json]
"""

import argparse
import json
import sys
from statistics import median


def load_result(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(description="Compare CPU overhead benchmark results")
    parser.add_argument("results", nargs="+", help="Result JSON files (ideally 3)")
    parser.add_argument("--baseline", help="Baseline result JSON to compare against")
    parser.add_argument("--output", help="Write JSON report to this file")
    args = parser.parse_args()

    # Load all results and compute median.
    results = [load_result(p) for p in args.results]
    cpu_values = [r["observoor_cpu_seconds"] for r in results]
    wall_values = [r["wall_clock_seconds"] for r in results]

    median_cpu = median(cpu_values)
    median_wall = median(wall_values)

    report = {
        "runs": len(results),
        "cpu_values": cpu_values,
        "median_cpu_seconds": round(median_cpu, 6),
        "median_wall_seconds": round(median_wall, 3),
        "git_commit": results[0].get("git_commit", "unknown"),
        "iterations": results[0].get("iterations", 0),
        "threads": results[0].get("threads", 0),
    }

    print(f"Benchmark results ({len(results)} runs):")
    print(f"  CPU seconds:  {cpu_values}")
    print(f"  Median CPU:   {median_cpu:.6f}s")
    print(f"  Median wall:  {median_wall:.3f}s")
    print(f"  Commit:       {report['git_commit']}")

    # Compare to baseline if provided.
    if args.baseline:
        baseline = load_result(args.baseline)
        baseline_cpu = baseline["median_cpu_seconds"]
        delta = median_cpu - baseline_cpu
        delta_pct = (delta / baseline_cpu) * 100 if baseline_cpu > 0 else 0

        report["baseline_cpu_seconds"] = baseline_cpu
        report["baseline_commit"] = baseline.get("git_commit", "unknown")
        report["delta_seconds"] = round(delta, 6)
        report["delta_percent"] = round(delta_pct, 2)

        direction = "faster" if delta < 0 else "slower"
        print(f"\n  Baseline:     {baseline_cpu:.6f}s ({baseline.get('git_commit', '?')})")
        print(f"  Delta:        {delta:+.6f}s ({delta_pct:+.2f}%) — {direction}")

    # Write report.
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
        print(f"\nReport written to {args.output}")

    # Always print JSON to stdout for machine consumption.
    print(f"\n{json.dumps(report)}")


if __name__ == "__main__":
    main()
