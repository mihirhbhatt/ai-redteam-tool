
from unittest.mock import Mock

import pytest

from attacks.base_attack import (
    AttackResult,
    BaseAttack,
    OWASPCategory,
    Severity,
)
from core.target import TargetResponse


class ExampleAttack(BaseAttack):
    name = "Example offline attack"

    def generate_test_cases(self) -> list[dict[str, object]]:
        return [
            {"prompt": "safe test prompt one", "metadata": {"case": 1}},
            {"prompt": "safe test prompt two", "metadata": {"case": 2}},
        ]

    def _rule_evaluate(
        self, test_case: dict[str, object], response: str
    ) -> AttackResult:
        return AttackResult(
            attack_name=self.name,
            owasp_category=OWASPCategory.LLM01_PROMPT_INJECTION,
            prompt=str(test_case["prompt"]),
            response=response,
            success=False,
            severity=Severity.LOW,
        )


def test_attack_result_serializes_enums_and_truncates_response() -> None:
    result = AttackResult(
        attack_name="Offline test",
        owasp_category=OWASPCategory.LLM02_SENSITIVE_INFO,
        severity=Severity.MEDIUM,
        response="x" * 1200,
    )

    serialized = result.to_dict()

    assert serialized["owasp_category"] == OWASPCategory.LLM02_SENSITIVE_INFO.value
    assert serialized["severity"] == "medium"
    assert len(serialized["response"]) == 1000
    assert "metadata" not in serialized


def test_attack_run_honors_limit_and_merges_case_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = Mock()
    target.query_with_system.return_value = TargetResponse(
        prompt="safe test prompt one",
        response="Model response",
        model="mock",
        latency=0.01,
    )
    attack = ExampleAttack(
        target_adapter=target,
        config={"system_prompt": "Local test system", "delay_between_requests": 0},
    )
    monkeypatch.setattr("attacks.base_attack.time.sleep", Mock())

    results = attack.run(max_tests=1)

    assert len(results) == 1
    assert results[0].prompt == "safe test prompt one"
    assert results[0].response == "Model response"
    assert results[0].metadata == {"case": 1}
    assert results[0].latency >= 0
    target.query_with_system.assert_called_once_with(
        "Local test system", "safe test prompt one"
    )
    assert attack.results == results


def test_attack_run_records_target_errors_without_aborting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = Mock()
    target.query_with_system.side_effect = RuntimeError("offline target failure")
    attack = ExampleAttack(
        target_adapter=target,
        config={"delay_between_requests": 0},
    )
    monkeypatch.setattr("attacks.base_attack.time.sleep", Mock())

    results = attack.run(max_tests=1)

    assert len(results) == 1
    assert not results[0].success
    assert results[0].severity is Severity.INFO
    assert results[0].response == "ERROR: offline target failure"
    assert results[0].prompt == "safe test prompt one"


def test_attack_uses_judge_result_when_judge_is_configured() -> None:
    judge = Mock()
    judge.evaluate.return_value = {
        "success": True,
        "severity": "high",
        "confidence": 0.9,
        "reasoning": "Mocked evaluation",
    }
    attack = ExampleAttack(
        target_adapter=Mock(),
        judge=judge,
        config={"system_prompt": "Configured system prompt"},
    )
    test_case = {
        "prompt": "safe test prompt",
        "system_prompt": "Case-specific system prompt",
        "metadata": {"case": "judge"},
    }

    result = attack.evaluate_response(test_case, "Mocked response")

    assert result.success
    assert result.severity is Severity.HIGH
    assert result.confidence == 0.9
    assert result.judge_reasoning == "Mocked evaluation"
    assert result.system_prompt_used == "Case-specific system prompt"
    judge.evaluate.assert_called_once_with(
        category=attack.owasp_category,
        prompt="safe test prompt",
        response="Mocked response",
        system_prompt="Case-specific system prompt",
        metadata={"case": "judge"},
    )
