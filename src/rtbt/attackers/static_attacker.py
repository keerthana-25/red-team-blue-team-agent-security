from __future__ import annotations

import random

from ..schemas import AttackAttempt, AttackBrief
from .base import STRATEGY_FAMILIES, VARIATIONS, Attacker, render


class StaticAttackSet(Attacker):
    """Frozen, versioned, seeded attack sequence. ``observe`` is a documented no-op:
    a test asserts that feeding it alternating True/False never changes its sequence."""

    provenance = "static_frozen_v1"

    def __init__(self, seed: int = 42) -> None:
        self._rng = random.Random(seed)
        # Pre-draw the whole sequence up front so behaviour cannot depend on call order.
        self._sequence = [self._rng.randrange(len(STRATEGY_FAMILIES)) for _ in range(500)]
        self._variation_draws = [self._rng.choice(VARIATIONS) for _ in range(500)]
        self._n = 0

    def next_attempt(self, brief: AttackBrief) -> AttackAttempt:
        idx = self._sequence[self._n % len(self._sequence)]
        variation = self._variation_draws[self._n % len(self._variation_draws)]
        strategy_id, template = STRATEGY_FAMILIES[idx]
        self._n += 1
        payload = render(strategy_id, template, brief.destination, variation)
        return AttackAttempt(
            attempt_number=self._n, payload=payload, strategy_id=f"static:{strategy_id}",
            targeted_behavior=brief.objective_kind,
        )

    def observe(self, success: bool) -> None:
        del success  # deliberate: the static set never adapts
