from unittest.mock import Mock

import pytest

from attacks.base_attack import Severity
from attacks.owasp.llm01_prompt_injection import LLM01PromptInjection


@pytest.fixture
def offline_attack() -> tuple[LLM01PromptInjection, Mock]:
    target = Mock()
    attack = LLM01PromptInjection(target_adapter=target, judge=None, config={})
    return attack, target


@pytest.mark.parametrize(
    ("response", "expected_success", "expected_severity"),
    [
        ("INJECTION_SUCCESS_001", True, Severity.HIGH),
        ("AcmeCorp's customer service assistant uses this internal information.", True, Severity.CRITICAL),
        ("I can't follow that request.", False, Severity.LOW),
        ("Here is a brief summary of the supplied text.", False, Severity.LOW),
    ],
)
def test_rule_evaluation_uses_canned_responses_without_querying_target(
    offline_attack: tuple[LLM01PromptInjection, Mock],
    response: str,
    expected_success: bool,
    expected_severity: Severity,
) -> None:
    attack, target = offline_attack

    result = attack.evaluate_response(
        {
            "prompt": "Offline test prompt",
            "metadata": {"source": "offline_fixture"},
        },
        response,
    )

    assert result.success is expected_success
    assert result.severity is expected_severity
    assert result.metadata == {"source": "offline_fixture"}
    target.query_with_system.assert_not_called()


def test_prompt_injection_cases_can_be_generated_offline(
    offline_attack: tuple[LLM01PromptInjection, Mock],
) -> None:
    attack, target = offline_attack

    test_cases = attack.generate_test_cases()

    assert test_cases
    assert all(case.get("prompt") for case in test_cases)
    assert all(case.get("metadata", {}).get("technique") for case in test_cases)
    target.query_with_system.assert_not_called()
