import json
import sys
import threading
from urllib.request import urlopen

import pytest

import dashboard.app as app
from dashboard.app import render_dashboard
import main


def test_dashboard_renders_summary_and_escapes_report_text(tmp_path) -> None:
    report = {
        "meta": {"timestamp": "2026-11-05", "target": {"provider": "local", "model": "test"}},
        "scorecard": {
            "overall_grade": "A",
            "risk_score": 0,
            "total_tests": 1,
            "successful_attacks": 0,
            "severity": {"critical": 0, "high": 0},
            "executive_summary": "Assessment complete.",
        },
        "findings": [
            {
                "id": "F1",
                "attack_name": "<script>alert(1)</script>",
                "owasp_category": "Testing",
                "severity": "low",
                "success": False,
                "description": "<img src=x onerror=alert(1)>",
                "prompt": "Do not show this prompt.",
                "response": "Do not show this response.",
            }
        ],
    }
    (tmp_path / "redteam_report_20261105.json").write_text(
        json.dumps(report),
        encoding="utf-8",
    )

    page = render_dashboard(tmp_path)

    assert "Assessment complete." in page
    assert "&lt;script&gt;" in page
    assert "&lt;img" in page
    assert "Do not show this prompt." not in page
    assert "Do not show this response." not in page


def test_dashboard_handles_missing_and_invalid_reports(tmp_path) -> None:
    assert "No JSON reports found." in render_dashboard(tmp_path)

    invalid_report = tmp_path / "redteam_report_invalid.json"
    invalid_report.write_text("{", encoding="utf-8")

    page = render_dashboard(tmp_path)

    assert "Unable to load" in page
    assert "redteam_report_invalid.json" in page


def test_report_selection_cannot_choose_arbitrary_files(tmp_path) -> None:
    (tmp_path / "redteam_report_valid.json").write_text("{}", encoding="utf-8")

    page = render_dashboard(tmp_path, "..\\secrets.json")

    assert "That report is unavailable." in page
    assert "Unable to load" not in page


def test_dashboard_cli_launches_with_custom_directory(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(app, "serve_dashboard", lambda path, port, **kwargs: seen.append((path, port, kwargs)))
    monkeypatch.setattr(sys, "argv", [
        "main.py", "--dashboard", "--report-dir", str(tmp_path), "--dashboard-port", "8766",
    ])
    assert main.main() == 0
    assert seen == [(str(tmp_path), 8766, {"open_browser": True})]


def test_dashboard_cli_reports_bind_failure(monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise OSError("address in use")
    monkeypatch.setattr(app, "serve_dashboard", fail)
    monkeypatch.setattr(sys, "argv", ["main.py", "--dashboard"])
    assert main.main() == 1
    assert "address in use" in capsys.readouterr().err


def test_dashboard_cli_rejects_assessment_flags(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["main.py", "--dashboard", "--quick"])
    with pytest.raises(SystemExit) as exc:
        main.main()
    assert exc.value.code == 2


def test_http_viewer_is_loopback_read_only_and_not_cached(tmp_path):
    (tmp_path / "redteam_report_sample.json").write_text(
        json.dumps({"meta": {"timestamp": "example"}, "findings": []}),
        encoding="utf-8",
    )
    server = app.HTTPServer(("127.0.0.1", 0), app._handler_for(tmp_path))
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        with urlopen(f"http://127.0.0.1:{server.server_port}/?report=redteam_report_sample.json", timeout=5) as response:
            page = response.read().decode("utf-8")
            assert response.headers["Cache-Control"] == "no-store"
            assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
            assert "example" in page
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_dashboard_browser_launch_occurs_after_bind(tmp_path, monkeypatch, capsys):
    seen = []
    class Server:
        server_port = 8765

        def __init__(self, address, handler):
            seen.append(address)

        def serve_forever(self):
            seen.append("serving")

        def server_close(self):
            seen.append("closed")

    monkeypatch.setattr(app, "HTTPServer", Server)
    monkeypatch.setattr(app.webbrowser, "open", lambda url: seen.append(url) or False)
    app.serve_dashboard(tmp_path, 8765, open_browser=True)
    assert seen == [("127.0.0.1", 8765), "http://127.0.0.1:8765/", "serving", "closed"]
    assert "Open http://127.0.0.1:8765/ manually" in capsys.readouterr().out
