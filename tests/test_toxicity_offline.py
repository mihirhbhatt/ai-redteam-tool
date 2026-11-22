import pytest

from attacks.base_attack import OWASPCategory, Severity
from attacks.toxicity import ToxicityElicitation


def test_safe_evaluation_prompts_do_not_contain_toxic_payloads() -> None:
    cases = ToxicityElicitation().generate_test_cases()

    assert len(cases) == 3
    assert all(case["prompt"] for case in cases)
    assert all(case["metadata"]["scenario"] for case in cases)


def test_configured_marker_is_flagged_locally() -> None:
    evaluator = ToxicityElicitation(
        markers={"insulting_language": ["test_marker"]}
    )

    result = evaluator.evaluate_response(
        "Respond respectfully.",
        "This includes TEST_MARKER as a policy-test fixture.",
    )

    assert result.success
    assert result.severity is Severity.MEDIUM
    assert result.owasp_category is OWASPCategory.TOXICITY
    assert result.metadata["matched_categories"] == ["insulting_language"]
    assert result.metadata["matched_markers"] == ["test_marker"]


def test_marker_matching_observes_word_boundaries() -> None:
    evaluator = ToxicityElicitation(markers={"category": ["mean"]})

    result = evaluator.evaluate_response("Prompt", "The meaning is clear.")

    assert not result.success
    assert result.severity is Severity.LOW


def test_evaluation_requires_a_configured_marker_lexicon() -> None:
    with pytest.raises(ValueError, match="configure at least one"):
        ToxicityElicitation().evaluate_response("Prompt", "Response.")


@pytest.mark.parametrize(
    ("prompt", "response"),
    [
        ("Prompt", ""),
        (None, "Response."),
    ],
)
def test_evaluation_rejects_invalid_text(prompt: str, response: str) -> None:
    evaluator = ToxicityElicitation(markers={"category": ["marker"]})

    with pytest.raises(ValueError):
        evaluator.evaluate_response(prompt, response)
