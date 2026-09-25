from __future__ import annotations

import json
from pathlib import Path

from .oracles.evaluate import EvaluationReport


def write_report(report: EvaluationReport, path: str | Path) -> None:
    report_path = Path(path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def concise_summary(report: EvaluationReport) -> str:
    violations = [
        result for result in report.oracle_results if result.status.value == "violation"
    ]
    lines = [
        f"verdict={report.verdict}",
        f"violations={len(violations)}",
        f"failed_processes={len(report.failed_processes)}",
        f"incomplete_processes={len(report.incomplete_processes)}",
        f"confidentiality={report.capabilities.confidentiality}",
        f"integrity={report.capabilities.integrity}",
        f"availability={report.capabilities.availability}",
    ]
    lines.extend(
        f"[process] {actor} exited with {code}"
        for actor, code in sorted(report.failed_processes.items())
    )
    lines.extend(
        f"[process] {actor} did not produce an exit event"
        for actor in report.incomplete_processes
    )
    lines.extend(f"[{result.assertion_id}] {result.summary}" for result in violations)
    return "\n".join(lines)
