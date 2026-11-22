from pathlib import Path
from types import SimpleNamespace
import builtins
import sys

import pytest
import yaml

import core.engine
from core.interactive_setup import configure_interactively
import main


def _config(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({
        "target": {
            "provider": "openai", "model": "remote", "base_url": "https://old.test/v1",
            "api_key_env": "OPENAI_API_KEY",
        },
        "judge": {"enabled": True, "provider": "openai", "model": "judge"},
    }), encoding="utf-8")
    return path


def _inputs(monkeypatch, *values):
    iterator = iter(values)
    monkeypatch.setattr(builtins, "input", lambda prompt: next(iterator))


def test_local_assessment_disables_cloud_judge(tmp_path, monkeypatch):
    path = _config(tmp_path)
    seen = []

    class Engine:
        def __init__(self, path):
            with open(path, encoding="utf-8") as file:
                seen.append(yaml.safe_load(file))

        def run_assessment(self, categories):
            return {"scorecard": SimpleNamespace(critical_findings=0, high_findings=0)}

    monkeypatch.setattr(core.engine, "RedTeamEngine", Engine)
    monkeypatch.setattr(sys, "argv", ["main.py", "--config", str(path), "--interactive"])
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    _inputs(monkeypatch, "1", "llama3.2", "1")

    with pytest.raises(SystemExit) as exc:
        main.main()
    assert exc.value.code == 0
    assert seen[0]["target"] == {
        "provider": "ollama", "model": "llama3.2",
        "base_url": "http://localhost:11434", "api_key_env": None,
    }
    assert seen[0]["judge"]["enabled"] is False
    assert yaml.safe_load(path.read_text(encoding="utf-8"))["judge"]["enabled"] is True


def test_local_health_check_does_not_create_judge(tmp_path, monkeypatch):
    seen = []

    class Adapter:
        def __init__(self, config):
            seen.append(config.copy())

        def health_check(self):
            return True

    monkeypatch.setitem(core.engine.ADAPTER_REGISTRY, "ollama", Adapter)
    monkeypatch.setattr(sys, "argv", [
        "main.py", "--config", str(_config(tmp_path)), "--interactive", "--check-target",
    ])
    _inputs(monkeypatch, "1", "my-model")
    assert main.main() == 0
    assert seen[0]["provider"] == "ollama"
    assert seen[0]["model"] == "my-model"


def test_api_selection_uses_profile_and_can_disable_judge(tmp_path, monkeypatch):
    seen = []

    class Engine:
        def __init__(self, path):
            with open(path, encoding="utf-8") as file:
                seen.append(yaml.safe_load(file))

        def run_assessment(self, categories):
            return {"scorecard": SimpleNamespace(critical_findings=0, high_findings=0)}

    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-value")
    monkeypatch.setattr(core.engine, "RedTeamEngine", Engine)
    monkeypatch.setattr(sys, "argv", ["main.py", "--config", str(_config(tmp_path)), "--interactive"])
    _inputs(monkeypatch, "2", "deepseek", "deepseek-flash", "1")
    with pytest.raises(SystemExit) as exc:
        main.main()
    assert exc.value.code == 0
    assert seen[0]["target"]["base_url"] == "https://api.deepseek.com"
    assert seen[0]["target"]["api_key_env"] == "DEEPSEEK_API_KEY"
    assert seen[0]["judge"]["enabled"] is False
    assert "test-value" not in repr(seen)


def test_api_missing_key_fails_before_network(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(sys, "argv", [
        "main.py", "--config", str(_config(tmp_path)), "--interactive", "--check-target",
    ])
    _inputs(monkeypatch, "2", "anthropic", "model")
    assert main.main() == 1
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err


def test_hosted_target_uses_independent_local_judge(tmp_path, monkeypatch):
    seen = []

    class Engine:
        def __init__(self, path):
            with open(path, encoding="utf-8") as file:
                seen.append(yaml.safe_load(file))

        def run_assessment(self, categories):
            return {"scorecard": SimpleNamespace(critical_findings=0, high_findings=0)}

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-value")
    monkeypatch.setattr(core.engine, "RedTeamEngine", Engine)
    monkeypatch.setattr(sys, "argv", ["main.py", "--config", str(_config(tmp_path)), "--interactive"])
    _inputs(monkeypatch, "2", "anthropic", "model", "2", "local-judge")
    with pytest.raises(SystemExit) as exc:
        main.main()
    assert exc.value.code == 0
    assert seen[0]["target"]["provider"] == "anthropic"
    assert seen[0]["judge"]["enabled"] is True
    assert seen[0]["judge"]["provider"] == "ollama"
    assert seen[0]["judge"]["model"] == "local-judge"
    assert seen[0]["judge"]["base_url"] == "http://localhost:11434"
    assert seen[0]["judge"]["api_key_env"] is None


def test_local_health_check_reports_connection_error(tmp_path, monkeypatch, capsys):
    from requests.exceptions import ConnectionError

    class Adapter:
        def __init__(self, config):
            pass

        def health_check(self):
            raise ConnectionError("Ollama is unavailable")

    monkeypatch.setitem(core.engine.ADAPTER_REGISTRY, "ollama", Adapter)
    monkeypatch.setattr(sys, "argv", [
        "main.py", "--config", str(_config(tmp_path)), "--interactive", "--check-target",
    ])
    _inputs(monkeypatch, "1", "model")
    assert main.main() == 1
    assert "Ollama is unavailable" in capsys.readouterr().err


def test_local_target_hosted_judge_is_independent_and_wired(monkeypatch):
    seen = []

    class Adapter:
        def __init__(self, config):
            seen.append(config.copy())

    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-value")
    monkeypatch.setitem(core.engine.ADAPTER_REGISTRY, "openai", Adapter)
    _inputs(monkeypatch, "1", "target-model", "3", "y", "deepseek", "judge-model")
    config = {
        "target": {"provider": "openai", "base_url": "https://old.test"},
        "judge": {"enabled": False, "temperature": 0.1},
    }
    configure_interactively(config, "config/providers.yaml")
    engine = core.engine.RedTeamEngine.__new__(core.engine.RedTeamEngine)
    engine.config = config
    judge = engine._create_judge()

    assert config["target"]["provider"] == "ollama"
    assert config["target"]["model"] == "target-model"
    assert judge is not None
    assert seen == [{
        "enabled": True, "temperature": 0.1, "provider": "openai",
        "model": "judge-model", "base_url": "https://api.deepseek.com",
        "api_key_env": "DEEPSEEK_API_KEY",
    }]
    assert "test-value" not in repr(config)


def test_declining_hosted_judge_returns_to_rule_based_selection(monkeypatch):
    config = {"target": {}, "judge": {"enabled": True}}
    _inputs(monkeypatch, "1", "target-model", "3", "n", "1")
    configure_interactively(config, "config/providers.yaml")
    assert config["judge"]["enabled"] is False


def test_missing_hosted_judge_key_fails_before_network(monkeypatch):
    config = {"target": {}, "judge": {"enabled": False}}
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    _inputs(monkeypatch, "1", "target-model", "3", "y", "deepseek", "judge-model")
    with pytest.raises(ValueError, match="DEEPSEEK_API_KEY"):
        configure_interactively(config, "config/providers.yaml")
    assert config["judge"]["enabled"] is False


def test_no_judge_flag_skips_judge_selection(monkeypatch):
    config = {"target": {}, "judge": {"enabled": True}}
    _inputs(monkeypatch, "1", "target-model")
    configure_interactively(config, "config/providers.yaml", no_judge=True)
    assert config["judge"]["enabled"] is False


def test_interactive_conflicting_flags_fail(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["main.py", "--interactive", "--model", "model"])
    with pytest.raises(SystemExit) as exc:
        main.main()
    assert exc.value.code == 2


def test_cancel_interactive_setup(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["main.py", "--config", str(_config(tmp_path)), "--interactive"])
    def cancel(prompt):
        raise EOFError
    monkeypatch.setattr(builtins, "input", cancel)
    assert main.main() == 1
    assert "cancelled" in capsys.readouterr().err
