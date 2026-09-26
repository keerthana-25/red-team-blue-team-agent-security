"""ToolRuntime is the one door between a target agent (simulated or real) and the
sandboxed environment. Every read passes through the content-filter hook before the
agent sees it; every write passes through the tool-validator hook before the
environment executes it. Neither the simulated nor the real target agent ever calls
the environment directly, so a defense cannot be accidentally bypassed by one target
implementation and not another.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .defenses import Defense
from .environments.base import Environment
from .schemas import WITHHELD_MESSAGE, ToolCallRecord, ToolError
from .util import utc_now_iso


@dataclass
class ToolRuntime:
    environment: Environment
    defense: Defense
    emit: Callable[[dict[str, Any]], None] | None = None  # optional live-stream hook
    # Audit-record context. Defaults keep every existing direct ToolRuntime(...) call (tests
    # included) working unchanged; harness.py fills in the real values for a real campaign.
    experiment_id: str = "standalone"
    campaign_id: str = ""
    scenario_id: str = ""
    round_number: int = 0
    phase: str = ""
    calls: list[ToolCallRecord] = field(default_factory=list)
    content_blocked_this_round: bool = False
    _step: int = 0

    def specs_for_agent(self) -> list[dict[str, Any]]:
        return [s.as_function_schema() for s in self.environment.specs()]

    def call(self, tool: str, arguments: dict[str, Any]) -> str:
        self._step += 1
        spec = self.environment.spec(tool)
        kind = spec.kind if spec else "unknown"
        record = ToolCallRecord(
            step=self._step, tool=tool, arguments=dict(arguments), kind=kind, timestamp=utc_now_iso(),
            experiment_id=self.experiment_id, campaign_id=self.campaign_id, scenario_id=self.scenario_id,
            round_number=self.round_number, phase=self.phase,
        )

        if kind == "write":
            decision = self.defense.authorize_tool(tool, kind, arguments)
            record.defense_decision = decision.verdict
            record.defense_reason_code = decision.reason_code
            record.defense_latency_ms = decision.latency_ms
            if decision.verdict != "allow":
                record.executed = False
                record.error_code = f"defense_{decision.verdict}"
                self.calls.append(record)
                self._notify(record)
                return f"[Action not completed: {decision.detail}]"

        try:
            output = self.environment.call(tool, arguments)
        except ToolError as exc:
            record.executed = False
            record.error_code = exc.code
            record.output = exc.message
            self.calls.append(record)
            self._notify(record)
            return f"[Tool error: {exc.message}]"

        record.executed = True
        record.output = output
        seen = output

        if kind == "read" and spec is not None and spec.returns_untrusted_content:
            content_decision = self.defense.inspect_content(output)
            record.content_risk_score = content_decision.risk_score
            record.content_blocked = not content_decision.allowed
            record.defense_reason_code = record.defense_reason_code or content_decision.reason_code
            record.defense_latency_ms += content_decision.latency_ms
            if not content_decision.allowed:
                self.content_blocked_this_round = True
                seen = WITHHELD_MESSAGE

        record.output_seen_by_agent = seen
        self.calls.append(record)
        self._notify(record)
        return seen

    def _notify(self, record: ToolCallRecord) -> None:
        if self.emit is not None:
            self.emit({"type": "tool_call", **record.to_dict()})
