from types import SimpleNamespace
from pathlib import Path
import sys

import pytest
import yaml

import core.engine
import main
from adapters.openai_adapter import AnthropicAdapter, OllamaAdapter, OpenAIAdapter


def _write_config(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump({
            "target": {
                "provider": "openai",
                "model": "old-model",
                "api_key_env": "OLD_KEY",
                "base_url": "https://old.example/v1",
            }
        }),
        encoding="utf-8",
    )
    return path


def test_cli_check_switches_provider_and_clears_old_connection_settings(
    tmp_path, monkeypatch, capsys
):
    config_path = _write_config(tmp_path)
    seen = []

    class FakeAdapter:
        def __init__(self, config):
            seen.append(config.copy())

        def health_check(self):
            return True

    monkeypatch.setitem(core.engine.ADAPTER_REGISTRY, "ollama", FakeAdapter)
    monkeypatch.setattr(sys, "argv", [
        "main.py", "--config", str(config_path), "--provider", "ollama",
        "--model", "local-model", "--check-target",
    ])

    assert main.main() == 0
    assert seen[0]["model"] == "local-model"
    assert seen[0]["base_url"] is None
    assert seen[0]["api_key_env"] is None
    assert "health check passed" in capsys.readouterr().out
    assert yaml.safe_load(config_path.read_text())["target"]["provider"] == "openai"


def test_cli_requires_model_when_switching_provider(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", [
        "main.py", "--config", str(_write_config(tmp_path)), "--provider",
        "ollama", "--check-target",
    ])
    with pytest.raises(SystemExit) as exc:
        main.main()
    assert exc.value.code == 2
    assert "--model is required" in capsys.readouterr().err


def test_cli_check_reports_empty_response(tmp_path, monkeypatch, capsys):
    class FakeAdapter:
        def __init__(self, config):
            pass

        def health_check(self):
            return False

    monkeypatch.setitem(core.engine.ADAPTER_REGISTRY, "openai", FakeAdapter)
    monkeypatch.setattr(sys, "argv", [
        "main.py", "--config", str(_write_config(tmp_path)), "--check-target",
    ])
    assert main.main() == 1
    assert "empty health-check response" in capsys.readouterr().err


def test_cli_passes_overrides_to_assessment_and_cleans_temp_config(
    tmp_path, monkeypatch
):
    seen = {}

    class FakeEngine:
        def __init__(self, path):
            seen["path"] = path
            with open(path, encoding="utf-8") as file:
                seen["config"] = yaml.safe_load(file)

        def run_assessment(self, categories):
            seen["categories"] = categories
            return {"scorecard": SimpleNamespace(
                critical_findings=0, high_findings=0
            )}

    monkeypatch.setattr(core.engine, "RedTeamEngine", FakeEngine)
    monkeypatch.setattr(sys, "argv", [
        "main.py", "--config", str(_write_config(tmp_path)),
        "--provider", "ollama", "--model", "local-model",
        "--base-url", "http://localhost:12345", "--no-judge",
    ])
    with pytest.raises(SystemExit) as exc:
        main.main()
    assert exc.value.code == 0
    assert seen["config"]["target"]["model"] == "local-model"
    assert seen["config"]["target"]["base_url"] == "http://localhost:12345"
    assert seen["config"]["judge"]["enabled"] is False
    assert not Path(seen["path"]).exists()


def test_ollama_null_url_and_options(monkeypatch):
    import requests
    seen = {}

    def post(url, **kwargs):
        seen.update(url=url, **kwargs)
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"message": {"content": "OK"}},
        )

    monkeypatch.setattr(requests, "post", post)
    adapter = OllamaAdapter({
        "base_url": None, "model": "local-model", "timeout": 12,
        "max_tokens": 44, "temperature": 0.3,
    })
    result = adapter.query("hello")
    assert result.response == "OK"
    assert seen["url"] == "http://localhost:11434/api/chat"
    assert seen["timeout"] == 12
    assert seen["json"]["options"] == {"temperature": 0.3, "num_predict": 44}


def test_openai_key_and_request_model(monkeypatch):
    monkeypatch.setenv("MODEL_TEST_KEY", "test-only")
    calls = []

    class Client:
        def __init__(self, **kwargs):
            assert kwargs["api_key"] == "test-only"
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

        def create(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(
                choices=[SimpleNamespace(
                    message=SimpleNamespace(content="OK"), finish_reason="stop"
                )],
                usage=None,
            )

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=Client))
    adapter = OpenAIAdapter({"api_key_env": "MODEL_TEST_KEY", "model": "default"})
    result = adapter.query("hello", model="override")
    assert result.model == "override"
    assert calls[0]["model"] == "override"


def test_anthropic_reads_text_blocks_and_generation_options(monkeypatch):
    monkeypatch.setenv("MODEL_TEST_KEY", "test-only")
    calls = []

    class Client:
        def __init__(self, **kwargs):
            assert kwargs == {"api_key": "test-only", "timeout": 8}
            self.messages = SimpleNamespace(create=self.create)

        def create(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(content=[
                SimpleNamespace(type="text", text="one"),
                SimpleNamespace(type="other"),
                SimpleNamespace(type="text", text="two"),
            ])

    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(Anthropic=Client))
    adapter = AnthropicAdapter({
        "api_key_env": "MODEL_TEST_KEY", "model": "default", "timeout": 8,
    })
    result = adapter.query("hello", model="override", max_tokens=50, temperature=0.1)
    assert result.response == "onetwo"
    assert result.model == "override"
    assert calls[0]["max_tokens"] == 50
    assert calls[0]["temperature"] == 0.1


def test_cloud_adapter_requires_key(monkeypatch):
    monkeypatch.delenv("MODEL_TEST_MISSING_KEY", raising=False)
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=object))
    with pytest.raises(ValueError, match="MODEL_TEST_MISSING_KEY"):
        OpenAIAdapter({"api_key_env": "MODEL_TEST_MISSING_KEY"})
