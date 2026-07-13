"""JSON, CSV, and Markdown replay report exports."""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any, Dict, Mapping

from .serialization import pretty_json


def rules_csv(report: Mapping[str, Any]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(
        [
            "rule_id",
            "engine",
            "owner",
            "decision",
            "state",
            "precision",
            "recall",
            "false_positive_rate",
            "alerts",
            "p95_latency_ms",
            "diagnostics",
            "techniques",
        ]
    )
    for item in report["rules"]:
        writer.writerow(
            [
                item["rule"]["id"],
                item["rule"]["engine"],
                item["rule"]["owner"],
                item["lifecycle"]["decision"],
                item["lifecycle"]["resulting_state"],
                item["metrics"]["precision"],
                item["metrics"]["recall"],
                item["metrics"]["false_positive_rate"],
                item["metrics"]["alert_count"],
                item["metrics"]["latency_ms"]["p95"],
                "|".join(item["diagnostics"]),
                "|".join(
                    technique["id"]
                    for technique in item["rule"]["threat"]["techniques"]
                ),
            ]
        )
    return output.getvalue()


def markdown_report(report: Mapping[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Detection replay report",
        "",
        f"- Assessment date: `{report['as_of']}`",
        f"- Functional SHA-256: `{report['functional_sha256']}`",
        f"- Rules: `{summary['rule_count']}`",
        f"- Replay cases: `{summary['replay_case_count']}`",
        f"- Unit-test pass rate: `{summary['unit_test_pass_rate']:.1%}`",
        f"- Decisions: `{summary['promote_count']} promote / {summary['hold_count']} hold / {summary['reject_count']} reject`",
        "",
        "## Rule quality",
        "",
        "| Rule | Engine | Decision | Precision | Recall | FPR | Alerts | Diagnostics |",
        "|---|---|---|---:|---:|---:|---:|---|",
    ]
    for item in report["rules"]:
        precision = (
            "n/a"
            if item["metrics"]["precision"] is None
            else f"{item['metrics']['precision']:.3f}"
        )
        recall = (
            "n/a"
            if item["metrics"]["recall"] is None
            else f"{item['metrics']['recall']:.3f}"
        )
        diagnostics = ", ".join(item["diagnostics"]) or "healthy"
        lines.append(
            f"| `{item['rule']['id']}` | {item['rule']['engine']} | {item['lifecycle']['decision']} | "
            f"{precision} | {recall} | {item['metrics']['false_positive_rate']:.3f} | "
            f"{item['metrics']['alert_count']} | {diagnostics} |"
        )
    lines.extend(
        [
            "",
            "## Diagnostics",
            "",
            f"- Silent: `{', '.join(report['diagnostics']['silent_rules']) or 'none'}`",
            f"- Noisy: `{', '.join(report['diagnostics']['noisy_rules']) or 'none'}`",
            f"- Redundant pairs: `{len(report['diagnostics']['redundant_pairs'])}`",
            f"- Expired: `{', '.join(report['diagnostics']['expired_rules']) or 'none'}`",
            "",
            "Promotion is simulated. This report does not deploy a rule to a SIEM or runtime sensor.",
            "",
        ]
    )
    return "\n".join(lines)


def write_report_bundle(report: Mapping[str, Any], output_dir: Path) -> Dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": output_dir / "replay-report.json",
        "csv": output_dir / "rule-metrics.csv",
        "markdown": output_dir / "replay-report.md",
        "audit": output_dir / "audit-chain.json",
    }
    paths["json"].write_text(pretty_json(report), encoding="utf-8")
    paths["csv"].write_text(rules_csv(report), encoding="utf-8")
    paths["markdown"].write_text(markdown_report(report), encoding="utf-8")
    paths["audit"].write_text(pretty_json(report["audit"]), encoding="utf-8")
    return {name: str(path) for name, path in paths.items()}
