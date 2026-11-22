import os
import time
from pathlib import Path

import pytest

from core.scorer import Scorer
from reports.report_generator import ReportGenerator


def _old(path: Path) -> None:
    timestamp = time.time() - 31 * 86400
    os.utime(path, (timestamp, timestamp))


def test_retention_deletes_only_expired_matching_report_files(tmp_path: Path):
    old = tmp_path / "redteam_report_20200101_010101.json"
    fresh = tmp_path / "redteam_report_20200101_010102.html"
    other = tmp_path / "notes.json"
    folder = tmp_path / "redteam_report_20200101_010103.html"
    old.write_text("old")
    fresh.write_text("fresh")
    other.write_text("other")
    folder.mkdir()
    _old(old)
    _old(other)
    generator = ReportGenerator({"reporting": {
        "output_dir": str(tmp_path), "formats": ["json"],
        "retention": {"enabled": True, "days": 30},
    }})
    result = generator.generate_all_reports([], Scorer().calculate_score([]), {})
    assert not old.exists()
    assert fresh.exists() and other.exists() and folder.exists()
    assert Path(result["json"]).exists()


def test_retention_off_by_default(tmp_path: Path):
    report = tmp_path / "redteam_report_20200101_010101.json"
    report.write_text("old")
    _old(report)
    generator = ReportGenerator({"reporting": {"output_dir": str(tmp_path), "formats": []}})
    generator.generate_all_reports([], Scorer().calculate_score([]), {})
    assert report.exists()


def test_retention_does_not_run_on_report_generation_failure(tmp_path: Path, monkeypatch):
    old = tmp_path / "redteam_report_20200101_010101.json"
    old.write_text("old")
    _old(old)
    generator = ReportGenerator({"reporting": {
        "output_dir": str(tmp_path), "formats": ["json"],
        "retention": {"enabled": True, "days": 30},
    }})
    def fail(*args):
        raise OSError("write failed")
    monkeypatch.setattr(generator, "_generate_json", fail)
    with pytest.raises(OSError, match="write failed"):
        generator.generate_all_reports([], Scorer().calculate_score([]), {})
    assert old.exists()


@pytest.mark.parametrize("retention", [
    {"enabled": "yes", "days": 30},
    {"enabled": True, "days": 0},
    {"enabled": True, "days": True},
    "invalid",
])
def test_invalid_retention_is_rejected(tmp_path: Path, retention):
    with pytest.raises(ValueError):
        ReportGenerator({"reporting": {"output_dir": str(tmp_path), "retention": retention}})
