import pytest

from core.logger import configure_logging, get_logger
from core.target import BaseTargetAdapter, TargetResponse


class StubTargetAdapter(BaseTargetAdapter):
    def query(self, prompt: str, **kwargs: object) -> TargetResponse:
        self.request_count += 1
        return TargetResponse(prompt, "OK", "stub-model", 0.01)

    def query_with_system(
        self, system_prompt: str, user_prompt: str, **kwargs: object
    ) -> TargetResponse:
        self.request_count += 1
        return TargetResponse(user_prompt, "Reply", "stub-model", 0.01)


def test_configure_logging_adds_no_duplicate_handlers(tmp_path) -> None:
    log_file = tmp_path / "nested" / "assessment.log"

    logger = configure_logging(level="DEBUG", log_file=log_file, console=False)
    handler_count = len(logger.handlers)
    configure_logging(level="DEBUG", log_file=log_file, console=False)
    logger.info("test event")

    assert len(logger.handlers) == handler_count
    assert "test event" in log_file.read_text(encoding="utf-8")
    assert get_logger() is logger


def test_configure_logging_rejects_unknown_level() -> None:
    with pytest.raises(ValueError, match="Unknown logging level"):
        configure_logging(level="NOT_A_LEVEL", console=False)


def test_target_contract_returns_normalized_responses() -> None:
    target = StubTargetAdapter({"model": "stub-model"})

    response = target.query_with_system("system", "prompt")

    assert response == TargetResponse("prompt", "Reply", "stub-model", 0.01)
    assert target.request_count == 1
    assert target.health_check()
    assert target.request_count == 2
