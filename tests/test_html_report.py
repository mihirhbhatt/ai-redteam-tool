from pathlib import Path

from attacks.base_attack import AttackResult, OWASPCategory, Severity
from core.scorer import Scorer
from reports.report_generator import ReportGenerator


def test_html_report_escapes_dynamic_content(tmp_path: Path) -> None:
    result = AttackResult(
        attack_name='<script>alert("attack")</script>',
        owasp_category=OWASPCategory.LLM01_PROMPT_INJECTION,
        prompt='<img src=x onerror="prompt(1)">',
        response="Response is not rendered in the HTML report.",
        success=True,
        severity=Severity.HIGH,
        confidence=0.9,
        description='<svg onload="alert(1)">',
        remediation="<script>fix()</script>",
    )
    scorecard = Scorer().calculate_score([result])
    output_dir = tmp_path / "output"
    generator = ReportGenerator(
        {"reporting": {"output_dir": str(output_dir), "formats": ["html"]}}
    )

    report_path = Path(
        generator._generate_html(
            [result],
            scorecard,
            {"model": '<iframe src="x">', "provider": "local", "duration_seconds": 1},
            "20261105",
        )
    )

    html = report_path.read_text(encoding="utf-8")
    assert "&lt;script&gt;" in html
    assert "&lt;img" in html
    assert "&lt;svg" in html
    assert "&lt;iframe" in html
    assert "<script>" not in html
    assert "<img" not in html
    assert "<svg" not in html
    assert "<iframe" not in html
    assert "Response is not rendered" not in html
