"""Local, read-only viewer for generated assessment JSON reports."""

import argparse
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse
import webbrowser


DEFAULT_REPORT_DIR = Path("reports/output")
REPORT_PATTERN = "redteam_report_*.json"


def _text(value: Any) -> str:
    """Convert report values to safe display text."""
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    return escape(str(value))


def render_dashboard(
    report_dir: str | Path = DEFAULT_REPORT_DIR,
    selected_report: str | None = None,
) -> str:
    """Render a dashboard for local report files without exposing raw prompts."""
    directory = Path(report_dir)
    report_paths = sorted(directory.glob(REPORT_PATTERN), key=lambda path: path.name, reverse=True)
    requested_path = next(
        (path for path in report_paths if path.name == selected_report),
        None,
    ) if selected_report else None
    active_path = (
        requested_path
        if selected_report is not None
        else (report_paths[0] if report_paths else None)
    )

    report_links = "".join(
        '<li><a href="/?{}">{}</a></li>'.format(
            urlencode({"report": path.name}),
            _text(path.name),
        )
        for path in report_paths
    ) or "<li>No JSON reports found.</li>"

    message = ""
    if selected_report and requested_path is None:
        message = '<p class="notice">That report is unavailable.</p>'
    if active_path is None:
        content = '<p class="muted">Generate a JSON assessment report to view it here.</p>'
    else:
        try:
            report = json.loads(active_path.read_text(encoding="utf-8"))
            if not isinstance(report, dict):
                raise ValueError("Report root must be a JSON object.")
            content = _render_report(report)
        except (OSError, json.JSONDecodeError, ValueError) as error:
            content = (
                f'<p class="notice">Unable to load {_text(active_path.name)}: '
                f"{_text(error)}</p>"
            )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Local Assessment Dashboard</title>
  <style>
    :root {{ color-scheme: dark; font: 16px/1.5 system-ui, sans-serif; }}
    body {{ margin: 0; background: #0d1117; color: #e6edf3; }}
    main {{ max-width: 1100px; margin: auto; padding: 2rem 1rem; }}
    section, .metric {{ background: #161b22; border: 1px solid #30363d;
      border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }}
    .metrics {{ display: grid; grid-template-columns: repeat(auto-fit,
      minmax(150px, 1fr)); gap: .75rem; }}
    .metric strong {{ display: block; font-size: 1.5rem; }}
    a {{ color: #79c0ff; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ text-align: left; vertical-align: top; padding: .6rem;
      border-bottom: 1px solid #30363d; }}
    .table-wrap {{ overflow-x: auto; }}
    .muted {{ color: #8b949e; }}
    .notice {{ color: #ffcc66; }}
    .safe-note {{ border-left: 4px solid #d29922; padding-left: .75rem; }}
  </style>
</head>
<body>
<main>
  <h1>Local Assessment Dashboard</h1>
  <p class="safe-note">Read-only local report viewer. Reports may contain sensitive
  findings. Prompts and raw model responses are not displayed.</p>
  {message}
  <section><h2>Assessment reports</h2><ul>{report_links}</ul></section>
  {content}
</main>
</body>
</html>"""


def _render_report(report: dict[str, Any]) -> str:
    scorecard = report.get("scorecard")
    if not isinstance(scorecard, dict):
        scorecard = {}
    meta = report.get("meta")
    if not isinstance(meta, dict):
        meta = {}
    target = meta.get("target")
    if not isinstance(target, dict):
        target = {}
    severity = scorecard.get("severity")
    if not isinstance(severity, dict):
        severity = {}
    findings = report.get("findings")
    if not isinstance(findings, list):
        findings = []

    rows = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        rows.append(
            "<tr>"
            f"<td>{_text(finding.get('id'))}</td>"
            f"<td>{_text(finding.get('attack_name'))}</td>"
            f"<td>{_text(finding.get('owasp_category'))}</td>"
            f"<td>{_text(finding.get('severity'))}</td>"
            f"<td>{'Yes' if finding.get('success') else 'No'}</td>"
            f"<td>{_text(finding.get('description'))}</td>"
            "</tr>"
        )
    findings_table = (
        "<div class=\"table-wrap\"><table><thead><tr>"
        "<th>ID</th><th>Test</th><th>Category</th><th>Severity</th>"
        "<th>Flagged</th><th>Description</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
        if rows
        else '<p class="muted">No findings in this report.</p>'
    )

    return f"""<section>
  <h2>Summary</h2>
  <p>Generated: {_text(meta.get('timestamp'))}</p>
  <p>Provider: {_text(target.get('provider'))} |
     Model: {_text(target.get('model'))}</p>
  <div class="metrics">
    <div class="metric">Grade<strong>{_text(scorecard.get('overall_grade', 'N/A'))}</strong></div>
    <div class="metric">Risk score<strong>{_text(scorecard.get('risk_score', 0))}</strong></div>
    <div class="metric">Tests<strong>{_text(scorecard.get('total_tests', len(findings)))}</strong></div>
    <div class="metric">Successful attacks<strong>{_text(scorecard.get('successful_attacks', 0))}</strong></div>
    <div class="metric">Critical findings<strong>{_text(severity.get('critical', 0))}</strong></div>
    <div class="metric">High findings<strong>{_text(severity.get('high', 0))}</strong></div>
  </div>
  <p>{_text(scorecard.get('executive_summary'))}</p>
</section>
<section><h2>Findings</h2>{findings_table}</section>"""


def _handler_for(report_dir: Path) -> type[BaseHTTPRequestHandler]:
    class DashboardHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path != "/":
                self.send_error(404)
                return

            query = parse_qs(parsed.query)
            selected = query.get("report", [None])[0]
            document = render_dashboard(report_dir, selected).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(document)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(document)

        def log_message(self, format: str, *args: Any) -> None:
            return

    return DashboardHandler


def serve_dashboard(
    report_dir: str | Path = DEFAULT_REPORT_DIR,
    port: int = 8765,
    *,
    open_browser: bool = False,
) -> None:
    """Serve the dashboard on loopback only; no remote bind option is exposed."""
    directory = Path(report_dir).resolve()
    server = HTTPServer(("127.0.0.1", port), _handler_for(directory))
    try:
        url = f"http://127.0.0.1:{server.server_port}/"
        print(f"Dashboard available at {url}")
        print("Press Ctrl+C in this window to stop the dashboard.")
        if open_browser and not webbrowser.open(url):
            print(f"Could not open a browser automatically. Open {url} manually.")
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="View local assessment JSON reports.")
    parser.add_argument(
        "--report-dir",
        default=str(DEFAULT_REPORT_DIR),
        help="Directory containing generated JSON reports",
    )
    parser.add_argument("--port", type=int, default=8765, help="Local dashboard port")
    args = parser.parse_args()
    serve_dashboard(args.report_dir, args.port)


if __name__ == "__main__":
    main()
