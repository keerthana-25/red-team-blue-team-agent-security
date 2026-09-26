"""Rule-based tool-call validation: the action-execution-boundary defense.

This engine only ever sees a proposed tool call and the scenario's PUBLISHED policy
(``scenario.policy``) — never the ground-truth ``allowed_actions`` used by the oracle,
and never the attacker's payload text. That separation is what makes 'unauthorized
tool call executed' a meaningful, non-circular measurement.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .environments.base import normalise_principal

DESTINATION_KEYS = ("to", "principal", "attendee", "attendees")


@dataclass(frozen=True)
class PolicyDecision:
    verdict: str  # allow | block | confirm
    reason_code: str
    detail: str

    @property
    def allowed(self) -> bool:
        return self.verdict == "allow"


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].casefold()


def _destinations(arguments: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key in DESTINATION_KEYS:
        value = arguments.get(key)
        if value is None:
            continue
        values = value if isinstance(value, list) else [value]
        out.extend(normalise_principal(v) for v in values if isinstance(v, str) and "@" in v)
    return out


class ToolPolicyEngine:
    """Evaluates one proposed call against ``scenario.policy``.

    Policy fields (all in the scenario's public policy block, never the private
    ground-truth ``allowed_actions``):
      - allowed_write_tools: list[str]            tools this task may use at all
      - approved_destinations: list[str]           exact addresses (case-insensitive)
      - trusted_domains: list[str]                 domains treated as pre-approved
      - confirm_write_tools: list[str] (optional)  tools that require CONFIRM instead of ALLOW
    """

    def __init__(self, policy: dict[str, Any]) -> None:
        self.allowed_write_tools = set(policy.get("allowed_write_tools", []))
        self.approved = {normalise_principal(a) for a in policy.get("approved_destinations", [])}
        self.trusted_domains = {d.casefold() for d in policy.get("trusted_domains", [])}
        self.confirm_tools = set(policy.get("confirm_write_tools", []))

    def evaluate(self, tool: str, kind: str, arguments: dict[str, Any]) -> PolicyDecision:
        if kind != "write":
            return PolicyDecision("allow", "READ_TOOL", "Read tools are not gated by the write policy.")

        if tool not in self.allowed_write_tools:
            return PolicyDecision(
                "block", "TOOL_NOT_AUTHORIZED",
                f"'{tool}' is not on the approved write-tool list for this task.",
            )

        destinations = _destinations(arguments)
        if destinations:
            unapproved = [d for d in destinations if d not in self.approved and _domain_of(d) not in self.trusted_domains]
            if unapproved:
                return PolicyDecision(
                    "block", "DESTINATION_NOT_APPROVED",
                    f"Destination(s) not pre-approved and outside trusted domains: {', '.join(unapproved)}.",
                )

        if tool in self.confirm_tools:
            return PolicyDecision("confirm", "CONFIRMATION_REQUIRED", f"'{tool}' requires explicit confirmation.")

        return PolicyDecision("allow", "OK", "Call matches the approved policy for this task.")
