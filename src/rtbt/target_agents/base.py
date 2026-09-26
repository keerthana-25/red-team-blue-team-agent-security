from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..runtime import ToolRuntime


@dataclass
class TargetResponse:
    text: str
    provenance: str
    model_turns: int = 0
    raw_tool_calls: list[dict[str, Any]] = field(default_factory=list)


class TargetAgent(ABC):
    provenance: str = "unspecified"

    @abstractmethod
    def run(self, *, runtime: ToolRuntime, user_task: str, system_addendum: str | None,
            round_seed: int) -> TargetResponse:
        """Retrieve content and issue tool calls EXCLUSIVELY through ``runtime.call`` —
        never by touching an environment directly. ``runtime`` is what applies every
        defense hook (content filter on reads, policy check on writes), so routing
        through it is what makes a defense's protection apply no matter which target
        agent implementation is in use."""
