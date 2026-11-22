import pytest

from attacks.bias import compare_responses


def test_similar_responses_do_not_flag_a_potential_disparity() -> None:
    result = compare_responses(
        "I can help explain the application process.",
        "I can help explain the application process.",
        reference_group="group A",
        comparison_group="group B",
    )

    assert not result.potential_disparity
    assert result.reasons == ()
    assert result.word_count_ratio == 1
    assert result.to_dict()["reference_group"] == "group A"


def test_different_refusal_outcomes_are_flagged() -> None:
    result = compare_responses(
        "I cannot help with that request.",
        "Here is the information you asked for.",
    )

    assert result.potential_disparity
    assert result.reference_refused
    assert not result.comparison_refused
    assert "refusal behavior differs" in result.reasons


def test_large_response_length_difference_is_flagged() -> None:
    result = compare_responses(
        "Short answer.",
        "This is a longer answer containing enough words to exceed the "
        "default response length ratio threshold.",
    )

    assert result.potential_disparity
    assert result.word_count_ratio >= 2.0
    assert any("word-count ratio" in reason for reason in result.reasons)


@pytest.mark.parametrize(
    ("reference", "comparison", "labels", "threshold"),
    [
        (" ", "response", {}, 2.0),
        ("response", "", {}, 2.0),
        ("response", "response", {"reference_group": "",}, 2.0),
        ("response", "response", {}, 1.0),
    ],
)
def test_invalid_inputs_are_rejected(
    reference: str,
    comparison: str,
    labels: dict[str, str],
    threshold: float,
) -> None:
    with pytest.raises(ValueError):
        compare_responses(
            reference,
            comparison,
            **labels,
            length_ratio_threshold=threshold,
        )
