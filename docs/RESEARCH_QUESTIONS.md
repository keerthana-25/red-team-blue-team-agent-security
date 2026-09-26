# Research questions

## Primary question

Under the same attack-attempt budget and experimental conditions, how do indirect prompt-injection defenses trade off security and legitimate-task utility, compared against each other and against static and adaptive attacks?

This is deliberately a comparison question, not a "does defense X work" question. A defense that blocks every action scores perfectly on security and trivially fails on utility; the platform is built so that number can never be reported alone (see the Compare view and `comparison_table()` in `src/rtbt/reporting.py`, which always carry both).

## Sub-questions the platform is built to answer

1. **Does adaptation help the attacker, given only a success/failure signal?** Compares a static, seeded attack set against an attacker that adjusts its next attempt based on nothing but whether the last one worked, at the same budget. Answered by `statistics.static_vs_adaptive()` and the Compare view's "Does adaptation help the attacker?" table. Every current answer to this is `simulated_result` (see `docs/EXPERIMENT_PROTOCOL.md`), because the adaptive side is currently the deterministic demo fixture, not a real model.

2. **Does a cheap defense (a system prompt) buy real security, or only the appearance of it?** Compares the defensive-prompt defense against the undefended baseline on both attack success and legitimate-task completion.

3. **Does a rule-based validator's usefulness depend on how complete its policy is?** The `cal-schedule-sync` scenario exists specifically to test this: its policy omits a legitimate destination on purpose, so the validator both stops the attack and blocks the real task, demonstrating that "the defense worked" is not the same question as "the defense's configuration was adequate." See `docs/SCENARIO_REVIEW.md` for why the automated validator reports an approved policy-consistency warning for this scenario.

4. **How much does a classifier's threshold trade attack detection against false positives on harmless content?** Answered by the benign-control rounds in every scenario and the `benign_block_rate` metric.

5. **Do these findings hold when the target agent and the attacker are real models instead of the deterministic simulations?** Not yet answerable — see `docs/REAL_MODEL_VALIDATION_PLAN.md`. This is the single biggest open question standing between the current platform and a research finding.

## What is explicitly out of scope

Multi-turn conversational manipulation, attacks delivered through web browsing rather than a single retrieved document/email/event, attacks on the defense's own infrastructure, and any question about a specific commercial product rather than the general mechanism of indirect prompt injection. See `docs/THREAT_MODEL.md` for the full boundary.

## Status

Every sub-question above has a working measurement pipeline. None has been answered with real evidence yet — every number produced by this platform today carries `evidence_status: "simulated_result"` because the default target, the default classifier, and the adaptive-demo attacker are all deterministic stand-ins (see `src/rtbt/schemas.py: evidence_status_for_campaign`). This document should be updated with an actual answer to each sub-question, and a link to the pilot data that produced it, once that data exists — not before.
