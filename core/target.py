
"""Shared target adapter contracts and response data types.

This module defines interfaces only; it does not create clients or send
requests. Concrete adapters are responsible for any explicitly invoked I/O.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TargetResponse:
    """Normalized response returned by a target adapter."""

    prompt: str
    response: str
    model: str
    latency: float
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseTargetAdapter(ABC):
    """Abstract interface implemented by target-specific adapters."""

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.request_count = 0

    @abstractmethod
    def query(self, prompt: str, **kwargs: Any) -> TargetResponse:
        """Send a prompt using the adapter's default system instructions."""
        raise NotImplementedError

    @abstractmethod
    def query_with_system(
        self, system_prompt: str, user_prompt: str, **kwargs: Any
    ) -> TargetResponse:
        """Send a prompt with explicit system instructions."""
        raise NotImplementedError

    def health_check(self) -> bool:
        """Send one simple request and report whether a non-empty reply arrived."""
        response = self.query("Say 'OK'")
        return bool(response.response.strip())
