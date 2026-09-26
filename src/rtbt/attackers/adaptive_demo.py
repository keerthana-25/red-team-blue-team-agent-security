from __future__ import annotations

import random

from ..schemas import AttackAttempt, AttackBrief
from .base import STRATEGY_FAMILIES, VARIATIONS, Attacker, render


class AdaptiveDemoAttacker(Attacker):
    """A deterministic rule — advance to the next family on failure, keep exploiting
    the current family (with wording variation) on success. Used to validate that the
    harness's feedback wiring works end to end. This is a fixture, not a research
    attacker: it does not reason about the target, and its behavior is fully
    determined by the seed and the outcome sequence."""

    provenance = "deterministic_demo_v1"

    def __init__(self, seed: int = 42) -> None:
        self._rng = random.Random(seed)
        self._family_index = 0
        self._n = 0
        self._history: list[tuple[str, bool]] = []

    def next_attempt(self, brief: AttackBrief) -> AttackAttempt:
        self._n += 1
        strategy_id, template = STRATEGY_FAMILIES[self._family_index % len(STRATEGY_FAMILIES)]
        variation = self._rng.choice(VARIATIONS)
        payload = render(strategy_id, template, brief.destination, variation)
        return AttackAttempt(
            attempt_number=self._n, payload=payload, strategy_id=f"adaptive_demo:{strategy_id}",
            targeted_behavior=brief.objective_kind,
            parent_attempt=(self._n - 1 if self._history and self._history[-1][1] else None),
            metadata={"family_index": self._family_index},
        )

    def observe(self, success: bool) -> None:
        self._history.append((f"family_{self._family_index}", bool(success)))
        if not success:
            self._family_index = min(self._family_index + 1, len(STRATEGY_FAMILIES) - 1)
        # on success: keep exploiting the same family (index unchanged)

    def stats(self) -> dict[str, object]:
        attempts = len(self._history)
        successes = sum(1 for _, ok in self._history if ok)
        return {
            "provenance": self.provenance,
            "attempts": attempts,
            "successes": successes,
            "final_family_index": self._family_index,
            "input_tokens": None, "output_tokens": None,  # deterministic fixture: no model is ever called
        }
