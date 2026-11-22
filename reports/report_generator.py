"""Generate JSON, CSV, and HTML assessment reports."""

import csv
import json
import logging
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from attacks.base_attack import AttackResult
from core.scorer import ScoreCard
from reports.html_template import render_html_report

logger = logging.getLogger("redteam.reports")
_REPORT_NAME = re.compile(
    r"^(?:redteam_report_\d{8}_\d{6}\.(?:json|html)|"
    r"redteam_findings_\d{8}_\d{6}\.csv)$"
)


class ReportGenerator:
    def __init__(self, config: dict[str, Any]):
        reporting = config.get("reporting", {})
        self.output_dir = Path(reporting.get("output_dir", "./reports/output"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.formats = reporting.get("formats", ["html", "json"])
        self.include_raw = reporting.get("include_raw_responses", True)
        retention = reporting.get("retention", {})
        if not isinstance(retention, dict):
            raise ValueError("reporting.retention must be a mapping")
        self.retention_enabled = retention.get("enabled", False)
        self.retention_days = retention.get("days", 30)
        if not isinstance(self.retention_enabled, bool):
            raise ValueError("reporting.retention.enabled must be a boolean")
        if isinstance(self.retention_days, bool) or not isinstance(self.retention_days, int) or self.retention_days < 1:
            raise ValueError("reporting.retention.days must be a positive integer")

    def generate_all_reports(
        self,
        results: list[AttackResult],
        scorecard: ScoreCard,
        target_info: dict[str, Any],
    ) -> dict[str, str]:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        paths = {}

        if "json" in self.formats:
            paths["json"] = self._generate_json(
                results, scorecard, target_info, timestamp
            )
        if "csv" in self.formats:
            paths["csv"] = self._generate_csv(results, timestamp)
        if "html" in self.formats:
            paths["html"] = self._generate_html(
                results, scorecard, target_info, timestamp
            )

        if self.retention_enabled:
            self._apply_retention()
        return paths

    def _apply_retention(self) -> None:
        cutoff = time.time() - self.retention_days * 86400
        for path in self.output_dir.iterdir():
            if not _REPORT_NAME.fullmatch(path.name) or path.is_symlink() or not path.is_file():
                continue
            if path.stat().st_mtime < cutoff:
                path.unlink()
                logger.info("Removed expired report: %s", path)

    def _generate_json(
        self,
        results: list[AttackResult],
        scorecard: ScoreCard,
        target_info: dict[str, Any],
        timestamp: str,
    ) -> str:
        filepath = self.output_dir / f"redteam_report_{timestamp}.json"
        report = {
            "meta": {
                "tool": "AI Red Team Framework v2.0",
                "timestamp": timestamp,
                "target": target_info,
            },
            "scorecard": {
                "overall_grade": scorecard.overall_grade,
                "risk_score": scorecard.overall_risk_score,
                "total_tests": scorecard.total_tests,
                "successful_attacks": scorecard.successful_attacks,
                "failed_attacks": scorecard.failed_attacks,
                "severity": {
                    "critical": scorecard.critical_findings,
                    "high": scorecard.high_findings,
                    "medium": scorecard.medium_findings,
                    "low": scorecard.low_findings,
                },
                "owasp_coverage": scorecard.owasp_coverage,
                "executive_summary": scorecard.executive_summary,
                "top_risks": scorecard.top_risks,
            },
            "category_scores": {
                category: {
                    "grade": score.grade,
                    "risk_score": score.risk_score,
                    "total_tests": score.total_tests,
                    "successful_attacks": score.successful_attacks,
                    "attack_success_rate": score.attack_success_rate,
                    "top_findings": score.top_findings,
                }
                for category, score in scorecard.category_scores.items()
            },
            "findings": [result.to_dict() for result in results],
        }
        filepath.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        return str(filepath)

    def _generate_csv(self, results: list[AttackResult], timestamp: str) -> str:
        filepath = self.output_dir / f"redteam_findings_{timestamp}.csv"
        with filepath.open("w", newline="", encoding="utf-8") as output_file:
            writer = csv.writer(output_file)
            writer.writerow(
                [
                    "ID",
                    "Attack Name",
                    "OWASP Category",
                    "Severity",
                    "Success",
                    "Confidence",
                    "CWE",
                    "Description",
                    "Prompt",
                    "Response (truncated)",
                    "Remediation",
                    "Judge Reasoning",
                    "Latency(s)",
                    "Timestamp",
                ]
            )
            for result in results:
                writer.writerow(
                    [
                        result.id,
                        result.attack_name,
                        result.owasp_category.value,
                        result.severity.value,
                        result.success,
                        f"{result.confidence:.2f}",
                        result.cwe_id,
                        result.description,
                        result.prompt[:200],
                        result.response[:200],
                        result.remediation[:200],
                        result.judge_reasoning[:200],
                        f"{result.latency:.2f}",
                        result.timestamp,
                    ]
                )
        return str(filepath)

    def _generate_html(
        self,
        results: list[AttackResult],
        scorecard: ScoreCard,
        target_info: dict[str, Any],
        timestamp: str,
    ) -> str:
        filepath = self.output_dir / f"redteam_report_{timestamp}.html"
        document = render_html_report(results, scorecard, target_info, timestamp)
        filepath.write_text(document, encoding="utf-8")
        return str(filepath)
