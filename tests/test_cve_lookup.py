from types import SimpleNamespace
import sys

import pytest
import requests

import main
from core import cve_lookup


def _record(identifier, published, metrics=None):
    return {"cve": {
        "id": identifier,
        "published": published,
        "descriptions": [{"lang": "en", "value": "Test description"}],
        "metrics": metrics or {},
        "references": [{"url": "https://example.test/advisory"}],
    }}


def test_id_lookup_and_cvss_format(monkeypatch):
    seen = []
    def get(url, **kwargs):
        seen.append((url, kwargs))
        record = _record("CVE-2021-44228", "2021-12-10", {
            "cvssMetricV31": [{"type": "Primary", "cvssData": {
                "version": "3.1", "baseScore": 10.0, "baseSeverity": "CRITICAL",
            }}]
        })
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"totalResults": 1, "vulnerabilities": [record]},
        )
    monkeypatch.setattr(cve_lookup.requests, "get", get)
    monkeypatch.setenv("NVD_API_KEY", "example-key")
    records, total = cve_lookup.lookup_cves("cve-2021-44228")
    text = cve_lookup.format_cve(records[0])
    assert total == 1
    assert seen[0][1]["params"] == {"cveId": "CVE-2021-44228"}
    assert seen[0][1]["headers"] == {"apiKey": "example-key"}
    assert "10.0 (CRITICAL), CVSS 3.1" in text
    assert "https://example.test/advisory" in text


def test_keyword_finds_latest_page(monkeypatch):
    calls = []
    def fake_request(params):
        calls.append(params.copy())
        if len(calls) == 1:
            return {"totalResults": 20, "vulnerabilities": [_record("CVE-2026-1000", "2026-01-01")]}
        return {"totalResults": 20, "vulnerabilities": [
            _record("CVE-2026-1111", "2026-11-01"),
            _record("CVE-2026-2222", "2026-11-02"),
        ]}
    monkeypatch.setattr(cve_lookup, "_request", fake_request)
    records, total = cve_lookup.lookup_cves("ollama", days=90, limit=2)
    assert total == 20
    assert calls[1]["startIndex"] == 18
    assert calls[1]["resultsPerPage"] == 2
    assert records[0]["id"] == "CVE-2026-2222"


def test_no_results_and_missing_metrics(monkeypatch):
    monkeypatch.setattr(cve_lookup, "_request", lambda params: {
        "totalResults": 0, "vulnerabilities": []
    })
    assert cve_lookup.lookup_cves("nothing") == ([], 0)
    assert "CVSS: Not available" in cve_lookup.format_cve(_record("CVE-2026-1234", "2026-01-01")["cve"])


@pytest.mark.parametrize("query,days,limit", [
    ("", 30, 10), ("CVE-bad", 30, 10), ("x", 121, 10), ("x", 30, 0)
])
def test_invalid_input_rejected(query, days, limit):
    with pytest.raises(ValueError):
        cve_lookup.lookup_cves(query, days=days, limit=limit)


def test_network_error_is_explicit(monkeypatch):
    def get(*args, **kwargs):
        raise requests.Timeout("timed out")
    monkeypatch.setattr(cve_lookup.requests, "get", get)
    with pytest.raises(cve_lookup.CveLookupError, match="NVD request failed"):
        cve_lookup.lookup_cves("CVE-2021-44228")


def test_cli_does_not_load_target_config(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(cve_lookup, "lookup_cves", lambda *args, **kwargs: (
        [_record("CVE-2026-1234", "2026-01-01")["cve"]], 1
    ))
    monkeypatch.setattr(sys, "argv", [
        "main.py", "--config", str(tmp_path / "missing.yaml"), "--cve", "CVE-2026-1234"
    ])
    assert main.main() == 0
    assert "CVE-2026-1234" in capsys.readouterr().out


def test_cli_reports_lookup_failure(monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise cve_lookup.CveLookupError("network unavailable")
    monkeypatch.setattr(cve_lookup, "lookup_cves", fail)
    monkeypatch.setattr(sys, "argv", ["main.py", "--cve", "ollama"])
    assert main.main() == 1
    assert "network unavailable" in capsys.readouterr().err
