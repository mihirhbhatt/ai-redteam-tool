from unittest.mock import Mock

import pytest

import core.engine as engine_module
from attacks.base_attack import AttackResult, BaseAttack, OWASPCategory, Severity
from core.engine import RedTeamEngine
from core.scorer import Scorer
from core.target import TargetResponse


class OfflineAttack(BaseAttack):
    name = "Offline test attack"
    description = "Uses only mocked responses."
    owasp_category = OWASPCategory.LLM01_PROMPT_INJECTION
    cwe_id = "CWE-TEST"

    def generate_test_cases(self) -> list[dict[str, object]]:
        return [
            {"prompt": "safe local test one"},
            {"prompt": "safe local test two"},
        ]

    def _rule_evaluate(
        self, test_case: dict[str, object], response: str
    ) -> AttackResult:
        return AttackResult(
            attack_name=self.name,
            owasp_category=self.owasp_category,
            prompt=str(test_case["prompt"]),
            response=response,
            success=False,
            severity=Severity.LOW,
        )


class RecordingReportGenerator:
    def __init__(self) -> None:
        self.call: tuple[list[AttackResult], object, dict[str, object]] | None = None

    def generate_all_reports(
        self,
        results: list[AttackResult],
        scorecard: object,
        target_info: dict[str, object],
    ) -> dict[str, str]:
        self.call = (results, scorecard, target_info)
        return {"json": "mock-report.json"}


def _engine_with_mocked_target() -> RedTeamEngine:
    engine = RedTeamEngine.__new__(RedTeamEngine)
    engine.config = {
        "target": {
            "provider": "mock",
            "model": "offline-test-model",
            "system_prompt": "Test-only system prompt",
        },
        "attacks": {
            "enabled_categories": ["offline"],
            "max_tests_per_category": 1,
            "delay_between_requests": 0,
        },
    }
    engine.target_adapter = Mock()
    engine.target_adapter.query.return_value = TargetResponse(
        prompt="health check",
        response="OK",
        model="mock",
        latency=0,
    )
    engine.target_adapter.query_with_system.return_value = TargetResponse(
        prompt="safe local test one",
        response="Mocked response",
        model="mock",
        latency=0,
    )
    engine.judge = None
    engine.scorer = Scorer()
    engine.report_generator = RecordingReportGenerator()
    engine.all_results = []
    engine.start_time = None
    return engine


def test_run_assessment_uses_selected_registry_and_builds_reports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(engine_module, "ATTACK_REGISTRY", {"offline": OfflineAttack})
    engine = _engine_with_mocked_target()
    monkeypatch.setattr(engine, "_print_banner", lambda: None)
    monkeypatch.setattr(engine, "_print_final_summary", lambda *_: None)

    result = engine.run_assessment(categories=["offline", "unknown"])

    assert result["reports"] == {"json": "mock-report.json"}
    assert len(result["results"]) == 1
    assert result["results"][0].prompt == "safe local test one"
    assert result["scorecard"].total_tests == 1
    engine.target_adapter.query.assert_called_once()
    engine.target_adapter.query_with_system.assert_called_once_with(
        "Test-only system prompt", "safe local test one"
    )
    assert engine.report_generator.call is not None
    report_results, scorecard, target_info = engine.report_generator.call
    assert report_results == result["results"]
    assert scorecard is result["scorecard"]
    assert target_info["provider"] == "mock"
    assert target_info["model"] == "offline-test-model"


def test_run_assessment_stops_when_target_health_check_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(engine_module, "ATTACK_REGISTRY", {"offline": OfflineAttack})
    engine = _engine_with_mocked_target()
    engine.target_adapter.query.return_value = TargetResponse(
        prompt="health check",
        response=" ",
        model="mock",
        latency=0,
    )
    monkeypatch.setattr(engine, "_print_banner", lambda: None)

    with pytest.raises(ConnectionError, match="health check failed"):
        engine.run_assessment(categories=["offline"])

    engine.target_adapter.query_with_system.assert_not_called()
    assert engine.report_generator.call is None