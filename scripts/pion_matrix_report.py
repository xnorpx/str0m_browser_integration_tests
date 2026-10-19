#!/usr/bin/env python3
"""Merge the per-job Pion <-> str0m interop results into one cross-platform matrix.

Each CI job writes target/pion-interop/results.json (see pion/report.go). This script
finds all of them below a directory and writes:

  * a summary per OS/crypto column plus every case that failed somewhere
    (to --summary-file, e.g. $GITHUB_STEP_SUMMARY, and <output-dir>/pion-summary.md)
  * the full case x platform matrix to <output-dir>/pion-matrix.md
"""
import argparse
import json
import sys
from pathlib import Path

ICONS = {"pass": "✅", "fail": "❌", "skip": "⏭️", "xfail": "⚠️"}


def load_reports(root: Path) -> list[dict]:
    reports = []
    for path in sorted(root.rglob("results.json")):
        try:
            reports.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as e:
            print(f"skipping {path}: {e}", file=sys.stderr)
    reports.sort(key=lambda r: (r.get("os", ""), r.get("crypto", "")))
    return reports


def cell(result: dict | None) -> str:
    if result is None:
        return ""
    status = result.get("status", "")
    if status == "pass" and not result.get("expect", {}).get("connect", True):
        return "🚫"
    icon = ICONS.get(status, "❓")
    negotiated = result.get("pion_dtls_negotiated")
    if status == "pass" and negotiated:
        return f"{icon} {negotiated}"
    return icon


def matrix_table(names: list[str], columns: list[str], by_column: list[dict]) -> list[str]:
    lines = ["| Case | " + " | ".join(columns) + " |", "|---|" + "---|" * len(columns)]
    for name in names:
        cells = [cell(results.get(name)) for results in by_column]
        lines.append(f"| `{name}` | " + " | ".join(cells) + " |")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("results_dir", help="directory containing results.json files (searched recursively)")
    parser.add_argument("--output-dir", default="analysis")
    parser.add_argument("--summary-file", default=None, help="append the summary here (e.g. $GITHUB_STEP_SUMMARY)")
    args = parser.parse_args()

    reports = load_reports(Path(args.results_dir))
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    if not reports:
        print("No Pion results found")
        return 0

    columns = [f"{r.get('os', '?')} · {r.get('crypto', '?')}" for r in reports]
    by_column = [{res["name"]: res for res in r.get("results", [])} for r in reports]
    names: list[str] = []
    for r in reports:
        for res in r.get("results", []):
            if res["name"] not in names:
                names.append(res["name"])

    summary = ["## Pion ↔ str0m interop · all platforms", ""]
    summary += ["| Platform | ✅ Pass | ❌ Fail | ⚠️ Known issue | ⏭️ Skip | 🚫 Rejected as expected | Total |",
                "|---|---|---|---|---|---|---|"]
    for column, r in zip(columns, reports):
        results = r.get("results", [])
        count = lambda status: sum(1 for x in results if x.get("status") == status)
        rejected = sum(1 for x in results if x.get("status") == "pass" and not x.get("expect", {}).get("connect", True))
        summary.append(f"| {column} | {count('pass')} | {count('fail')} | {count('xfail')} | {count('skip')} | {rejected} | {len(results)} |")
    summary.append("")

    failing = [n for n in names if any(res.get(n, {}).get("status") == "fail" for res in by_column)]
    if failing:
        summary += ["### Cases failing on at least one platform", ""]
        summary += matrix_table(failing, columns, by_column)
        summary.append("")
    else:
        summary += ["No unexpected failures on any platform.", ""]
    summary.append("Full case × platform matrix: `pion-matrix.md` in the `rtt-analysis` artifact.")

    matrix = ["## Pion ↔ str0m interop matrix", "",
              "✅ pass (negotiated DTLS) · 🚫 rejected as expected · ❌ fail · ⚠️ known upstream issue · ⏭️ skipped", ""]
    matrix += matrix_table(names, columns, by_column)

    summary_md = "\n".join(summary) + "\n"
    (out / "pion-summary.md").write_text(summary_md, encoding="utf-8")
    (out / "pion-matrix.md").write_text("\n".join(matrix) + "\n", encoding="utf-8")
    print(summary_md)
    if args.summary_file:
        with open(args.summary_file, "a", encoding="utf-8") as f:
            f.write(summary_md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
