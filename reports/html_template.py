
"""Safe HTML rendering for assessment reports."""

from html import escape
from typing import Any

from attacks.base_attack import AttackResult
from core.scorer import ScoreCard


_GRADE_COLORS = {
    "A": "#28a745",
    "A-": "#5cb85c",
    "B": "#7bc043",
    "C": "#ffc107",
    "D": "#fd7e14",
    "F": "#dc3545",
    "N/A": "#6c757d",
}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _safe(value: Any) -> str:
    return escape(str(value if value is not None else ""), quote=True)


def render_html_report(
    results: list[AttackResult],
    scorecard: ScoreCard,
    target_info: dict[str, Any],
    timestamp: str,
) -> str:
    """Render a self-contained HTML report with all dynamic text escaped."""
    grade = scorecard.overall_grade
    grade_color = _GRADE_COLORS.get(grade, _GRADE_COLORS["N/A"])

    coverage_rows = []
    for category, status in scorecard.owasp_coverage.items():
        if "FAIL" in status:
            row_class, icon = "danger", "❌"
        elif "WARN" in status:
            row_class, icon = "warning", "⚠️"
        elif "PASS" in status:
            row_class, icon = "success", "✅"
        else:
            row_class, icon = "secondary", "⬜"

        category_score = scorecard.category_scores.get(category)
        coverage_rows.append(
            f'<tr class="row-{row_class}">'
            f"<td>{icon} {_safe(category)}</td>"
            f"<td>{_safe(status)}</td>"
            f"<td>{category_score.total_tests if category_score else 0}</td>"
            f"<td>{category_score.successful_attacks if category_score else 0}</td>"
            f"<td>{_safe(str(category_score.attack_success_rate) + '%' if category_score else 'N/A')}</td>"
            f"<td>{_safe(category_score.grade if category_score else 'N/A')}</td>"
            "</tr>"
        )

    sorted_results = sorted(
        results,
        key=lambda result: (
            0 if result.success else 1,
            _SEVERITY_ORDER.get(result.severity.value, len(_SEVERITY_ORDER)),
        ),
    )
    finding_rows = []
    for result in sorted_results:
        severity = result.severity.value
        severity_class = severity if severity in _SEVERITY_ORDER else "info"
        status_text = "⚠️ VULN" if result.success else "✅ PASS"
        description = result.description[:500]
        prompt = result.prompt[:250]
        finding_rows.append(
            f'<tr class="row-{"danger" if result.success else "success"}">'
            f"<td>{_safe(result.id)}</td>"
            f"<td>{_safe(result.attack_name[:40])}</td>"
            f"<td>{_safe(result.owasp_category.value[:50])}</td>"
            f"<td>{status_text}</td>"
            f'<td><span class="severity-badge sev-{severity_class}">'
            f"{_safe(severity.upper())}</span></td>"
            f"<td>{result.confidence:.0%}</td>"
            f'<td class="desc-cell" title="{_safe(description)}">{_safe(description)}</td>'
            f'<td class="prompt-cell" title="{_safe(prompt)}">{_safe(prompt)}</td>'
            "</tr>"
        )

    risk_items = "".join(
        f"<li>{_safe(risk)}</li>" for risk in scorecard.top_risks[:5]
    )
    remediation_items = "".join(
        '<div class="remediation-box"><strong>'
        f"{_safe(category)}:</strong><br>"
        f"{_safe(category_score.top_findings[0] if category_score.top_findings else 'No specific findings')}"
        "</div>"
        for category, category_score in scorecard.category_scores.items()
        if category_score.grade in ("F", "D", "C")
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AI Red Team Report - {_safe(timestamp)}</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font: 16px/1.5 system-ui, sans-serif;
      background: #0d1117; color: #c9d1d9; }}
    .container {{ max-width: 1400px; margin: auto; padding: 20px; }}
    .header {{ display: flex; justify-content: space-between; align-items: center;
      gap: 1rem; padding: 2rem; margin-bottom: 1.5rem; border-radius: 12px;
      background: linear-gradient(135deg, #1a1a2e, #16213e, #0f3460); }}
    .header h1 {{ color: #fff; }}
    .header p {{ color: #8b949e; margin: .25rem 0; }}
    .grade-circle {{ flex: 0 0 120px; height: 120px; border: 5px solid {grade_color};
      border-radius: 50%; display: grid; place-items: center; color: {grade_color};
      font-size: 2.5rem; font-weight: bold; }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit,
      minmax(150px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
    .stat-card, .section {{ background: #161b22; border: 1px solid #30363d;
      border-radius: 10px; padding: 1rem; margin-bottom: 1rem; }}
    .stat-card {{ text-align: center; }}
    .number {{ font-size: 2rem; font-weight: bold; }}
    .label {{ color: #8b949e; }}
    .stat-critical {{ color: #f85149; }} .stat-high {{ color: #f0883e; }}
    .stat-medium {{ color: #d29922; }} .stat-success {{ color: #3fb950; }}
    .section h2 {{ color: #fff; margin-top: 0; }}
    .table-wrap {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
    th, td {{ text-align: left; vertical-align: top; padding: .65rem;
      border-bottom: 1px solid #30363d; }}
    th {{ background: #21262d; }}
    .row-danger {{ background: rgba(248, 81, 73, .1); }}
    .row-warning {{ background: rgba(210, 153, 34, .1); }}
    .severity-badge {{ display: inline-block; padding: .15rem .5rem;
      border-radius: 12px; font-size: .7rem; font-weight: bold; }}
    .sev-critical {{ background: #f85149; color: #fff; }}
    .sev-high {{ background: #f0883e; color: #fff; }}
    .sev-medium {{ background: #d29922; color: #000; }}
    .sev-low {{ background: #3fb950; color: #000; }}
    .sev-info {{ background: #8b949e; color: #000; }}
    .prompt-cell, .desc-cell {{ max-width: 260px; overflow-wrap: anywhere; }}
    .executive-summary {{ white-space: pre-line; }}
    .risk-list {{ padding-left: 1.25rem; }}
    .remediation-box {{ background: #0d1117; border-left: 4px solid #3fb950;
      padding: .8rem; margin: .6rem 0; }}
    @media print {{ body {{ background: #fff; color: #000; }}
      .section, .stat-card {{ border: 1px solid #ddd; }} }}
  </style>
</head>
<body>
<main class="container">
  <header class="header">
    <div>
      <h1>AI Red Team Assessment Report</h1>
      <p>Target: {_safe(target_info.get('model', 'Unknown'))}
         ({_safe(target_info.get('provider', ''))})</p>
      <p>Date: {_safe(timestamp)} |
         Duration: {_safe(f'{target_info.get("duration_seconds", 0):.0f}')}s</p>
      <p>Risk Score: {_safe(scorecard.overall_risk_score)}/100</p>
    </div>
    <div class="grade-circle">{_safe(grade)}</div>
  </header>
  <section class="stats-grid">
    <div class="stat-card"><div class="number">{scorecard.total_tests}</div><div class="label">Total Tests</div></div>
    <div class="stat-card"><div class="number stat-critical">{scorecard.successful_attacks}</div><div class="label">Successful Attacks</div></div>
    <div class="stat-card"><div class="number stat-success">{scorecard.failed_attacks}</div><div class="label">Blocked</div></div>
    <div class="stat-card"><div class="number stat-critical">{scorecard.critical_findings}</div><div class="label">Critical</div></div>
    <div class="stat-card"><div class="number stat-high">{scorecard.high_findings}</div><div class="label">High</div></div>
    <div class="stat-card"><div class="number stat-medium">{scorecard.medium_findings}</div><div class="label">Medium</div></div>
  </section>
  <section class="section"><h2>Executive Summary</h2>
    <div class="executive-summary">{_safe(scorecard.executive_summary)}</div></section>
  <section class="section"><h2>Top Risks</h2>
    <ol class="risk-list">{risk_items}</ol></section>
  <section class="section"><h2>OWASP LLM Coverage</h2>
    <div class="table-wrap"><table><thead><tr>
      <th>Category</th><th>Status</th><th>Tests</th><th>Findings</th><th>Rate</th><th>Grade</th>
    </tr></thead><tbody>{''.join(coverage_rows)}</tbody></table></div></section>
  <section class="section"><h2>Detailed Findings ({len(results)} tests)</h2>
    <div class="table-wrap"><table><thead><tr>
      <th>ID</th><th>Attack</th><th>Category</th><th>Status</th>
      <th>Severity</th><th>Confidence</th><th>Description</th><th>Prompt</th>
    </tr></thead><tbody>{''.join(finding_rows)}</tbody></table></div></section>
  <section class="section"><h2>Remediation Guidance</h2>
    {remediation_items or '<p>No category-specific remediation guidance.</p>'}</section>
  <footer class="section">
    <p>Generated by AI Red Team Framework | {_safe(timestamp)}</p>
    <p>This report may contain sensitive security findings; handle accordingly.</p>
  </footer>
</main>
</body>
</html>"""
