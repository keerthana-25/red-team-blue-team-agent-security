"""Cost and token accounting.

The rule throughout this module is the same one that governs the rest of the platform: never
invent a number. A simulated or deterministic component never called a model, so its token counts
are None and its cost is exactly 0.0 (not "unavailable" — there is genuinely nothing to pay for).
A real local model may return token counts with no attached monetary price, so its cost is None
("unavailable") even when its tokens are known. A hosted model's cost is computed only from an
explicit, named PricingConfig the caller supplies; no vendor price is ever hard-coded here.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PricingConfig:
    """A named, explicit price list. Never embedded as a silent default — every cost computed
    against one records the source_id so a report says exactly which prices produced a number
    that will otherwise go stale the moment a vendor changes their rates."""
    source_id: str
    currency: str = "USD"
    price_per_1k_input_tokens: float = 0.0
    price_per_1k_output_tokens: float = 0.0

    def cost_for(self, input_tokens: int | None, output_tokens: int | None) -> float | None:
        if input_tokens is None and output_tokens is None:
            return None
        return ((input_tokens or 0) / 1000.0) * self.price_per_1k_input_tokens + \
               ((output_tokens or 0) / 1000.0) * self.price_per_1k_output_tokens


def _component_cost(stats: dict[str, Any], pricing: PricingConfig | None) -> tuple[int | None, int | None, float | None]:
    input_tokens = stats.get("input_tokens")
    output_tokens = stats.get("output_tokens")
    if input_tokens is None and output_tokens is None:
        return None, None, 0.0  # nothing was ever called: genuinely free, not "unavailable"
    if pricing is None:
        return input_tokens, output_tokens, None  # tokens known, but no price list to value them against
    return input_tokens, output_tokens, pricing.cost_for(input_tokens, output_tokens)


def compute_cost_accounting(
    attacker_stats: dict[str, Any], target_stats: dict[str, Any] | None, defense_stats: dict[str, Any],
    attacker_pricing: PricingConfig | None = None, target_pricing: PricingConfig | None = None,
) -> dict[str, Any]:
    """Assembled once per campaign from each component's own stats(). Classifier/defense cost is
    always 0.0/None here: no hosted classifier adapter has ever been connected to a real pricing
    plan, so there is nothing yet to compute (see docs/LIMITATIONS.md)."""
    a_in, a_out, a_cost = _component_cost(attacker_stats, attacker_pricing)
    t_in, t_out, t_cost = _component_cost(target_stats or {}, target_pricing)
    d_cost = 0.0  # no classifier pricing path exists yet

    costs = [c for c in (a_cost, t_cost, d_cost) if c is not None]
    total = sum(costs) if costs and None not in (a_cost, t_cost) else None
    currency = None
    if attacker_pricing or target_pricing:
        currency = (attacker_pricing or target_pricing).currency

    return {
        "attacker_input_tokens": a_in, "attacker_output_tokens": a_out,
        "target_input_tokens": t_in, "target_output_tokens": t_out,
        "classifier_input_tokens": None, "classifier_output_tokens": None,
        "estimated_attacker_cost": a_cost, "estimated_target_cost": t_cost, "estimated_defense_cost": d_cost,
        "total_estimated_cost": total, "currency": currency,
        "pricing_source": ";".join(p.source_id for p in (attacker_pricing, target_pricing) if p) or None,
    }
