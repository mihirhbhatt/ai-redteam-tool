from pathlib import Path
from types import SimpleNamespace
import sys

import pytest
import yaml

import core.engine
from core.provider_catalog import load_provider_catalog
import main


def _catalog(tmp_path: Path, entry: object) -> Path:
    path = tmp_path / "providers.yaml"
    path.write_text(
        yaml.safe_dump({"providers": {"example": entry}}), encoding="utf-8"
    )
    return path


def _config(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump({"target": {
            "provider": "ollama", "model": "old",
            "base_url": "http://localhost:11434", "api_key_env": "OLD_KEY",
        }}),
        encoding="utf-8",
    )
    return path


def test_catalog_loads_profiles() -> None:
    profiles = load_provider_catalog("config/providers.yaml")
    assert profiles["deepseek"].base_url == "https://api.deepseek.com"
    assert profiles["openrouter"].api_key_env == "OPENROUTER_API_KEY"


@pytest.mark.parametrize("entry", [
    {"base_url": "http://example.test", "api_key_env": "KEY"},
    {"base_url": "https://user:secret@example.test", "api_key_env": "KEY"},
    {"base_url": "https://example.test?key=secret", "api_key_env": "KEY"},
    {"base_url": "https://example.test:abc", "api_key_env": "KEY"},
    {"base_url": "https://example.test", "api_key_env": "not valid"},
    {"base_url": "https://example.test", "api_key_env": "KEY", "api_key": "secret"},
])
def test_catalog_rejects_invalid_entries(tmp_path: Path, entry: object) -> None:
    with pytest.raises(ValueError):
        load_provider_catalog(_catalog(tmp_path, entry))


def test_list_providers_needs_no_target_config(tmp_path, monkeypatch, capsys):
    catalog = _catalog(tmp_path, {
        "base_url": "https://example.test/v1", "api_key_env": "EXAMPLE_KEY"
    })
    monkeypatch.setattr(sys, "argv", [
        "main.py", "--provider-catalog", str(catalog), "--list-providers",
        "--config", str(tmp_path / "missing.yaml"),
    ])
    assert main.main() == 0
    assert "example: https://example.test/v1" in capsys.readouterr().out


def test_selected_profile_reaches_health_check_without_old_credentials(
    tmp_path, monkeypatch
):
    catalog = _catalog(tmp_path, {
        "base_url": "https://example.test/v1", "api_key_env": "EXAMPLE_KEY"
    })
    seen = []

    class FakeAdapter:
        def __init__(self, config):
            seen.append(config.copy())

        def health_check(self):
            return True

    monkeypatch.setitem(core.engine.ADAPTER_REGISTRY, "openai", FakeAdapter)
    monkeypatch.setattr(sys, "argv", [
        "main.py", "--config", str(_config(tmp_path)),
        "--provider-catalog", str(catalog), "--provider-profile", "example",
        "--model", "vendor/model", "--check-target",
    ])
    assert main.main() == 0
    assert seen == [{
        "provider": "openai", "base_url": "https://example.test/v1",
        "api_key_env": "EXAMPLE_KEY", "model": "vendor/model",
    }]


def test_selected_profile_reaches_assessment(tmp_path, monkeypatch):
    catalog = _catalog(tmp_path, {
        "base_url": "https://example.test/v1", "api_key_env": "EXAMPLE_KEY"
    })
    seen = []

    class FakeEngine:
        def __init__(self, path):
            with open(path, encoding="utf-8") as file:
                seen.append(yaml.safe_load(file)["target"])

        def run_assessment(self, categories):
            return {"scorecard": SimpleNamespace(critical_findings=0, high_findings=0)}

    monkeypatch.setattr(core.engine, "RedTeamEngine", FakeEngine)
    monkeypatch.setattr(sys, "argv", [
        "main.py", "--config", str(_config(tmp_path)),
        "--provider-catalog", str(catalog), "--provider-profile", "example",
        "--model", "vendor/model", "--no-judge",
    ])
    with pytest.raises(SystemExit) as exc:
        main.main()
    assert exc.value.code == 0
    assert seen[0]["base_url"] == "https://example.test/v1"
    assert seen[0]["api_key_env"] == "EXAMPLE_KEY"
    assert seen[0]["model"] == "vendor/model"


@pytest.mark.parametrize("options, error", [
    (["--provider-profile", "missing", "--model", "x"], "Unknown provider profile"),
    (["--provider-profile", "example"], "--model is required"),
    (["--provider-profile", "example", "--model", "x", "--base-url", "https://elsewhere.test"], "cannot be combined"),
])
def test_cli_rejects_invalid_profile_options(tmp_path, monkeypatch, capsys, options, error):
    catalog = _catalog(tmp_path, {
        "base_url": "https://example.test/v1", "api_key_env": "EXAMPLE_KEY"
    })
    monkeypatch.setattr(sys, "argv", [
        "main.py", "--provider-catalog", str(catalog), *options,
    ])
    with pytest.raises(SystemExit) as exc:
        main.main()
    assert exc.value.code == 2
    assert error in capsys.readouterr().err
