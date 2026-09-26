# Hypotheses

Each hypothesis below states what would count as support and what would count against it, and is written so a specific statistic in this platform's output either does or does not support it. None has been evaluated against real components yet — see the Status line on each.

## H1: Adaptation increases attack success at a matched budget

**Claim.** An attacker that adapts using only a boolean success/failure signal achieves higher cumulative attack success than a static, seeded attack set given the same number of attempts against the same defense.

**Support would look like:** `statistics.static_vs_adaptive()` reporting `direction: "adaptive_higher"` (the paired-bootstrap interval on the mean difference excludes zero and is positive) for a defense, ideally with the gap widening in the later attempts shown by the adaptation curve.

**Against would look like:** `direction: "static_higher"` or `"null_or_undetermined"` — and given only 3–5 seeds by default, `"null_or_undetermined"` should be read as "not enough data," not as evidence of no effect.

**Status:** untested_design_intention. The adaptive side currently uses the deterministic demo fixture, which is built to demonstrate that the comparison machinery works, not to make a genuine claim about learning. A real test needs the model-backed attacker run against a live model (`docs/REAL_MODEL_VALIDATION_PLAN.md`).

## H2: A rule-based validator with an adequate policy stops attacks at no utility cost

**Claim.** When a tool-call validator's policy correctly lists every legitimate destination and action the task needs, it drives attack success to near zero while leaving legitimate-task completion unchanged from baseline.

**Support:** the `doc-share-legit` scenario, where `tool_validator` achieves `campaign_average_asr = 0.0` and `legitimate_task_completion_rate = 1.0` (verified by `test_correct_policy_stops_the_attack_without_costing_utility` in `tests/test_harness.py`).

**Status:** implementation_limitation, not yet a research finding — this is demonstrated on one hand-written, unreviewed scenario with a simulated target. It shows the oracle and metrics correctly detect this pattern when it occurs; it does not yet show how often real policies are actually this complete.

## H3: An incomplete policy blocks the legitimate task along with the attack

**Claim.** A validator whose policy omits a legitimate destination pays a real utility cost — it does not just fail to stop the attack, it actively breaks the honest use case.

**Support:** the `cal-schedule-sync` scenario, where `tool_validator` achieves `campaign_average_asr = 0.0` (attack stopped) but `legitimate_task_completion_rate = 0.0` and `benign_block_rate = 1.0` (verified by `test_incomplete_policy_shows_a_real_security_versus_utility_cost`).

**Status:** implementation_limitation for the same reason as H2 — demonstrated by construction on one scenario, not yet measured across a reviewed suite of many.

## H4: A classifier's benign-block rate rises with its sensitivity to injection-shaped language

**Claim.** A classifier tuned to catch subtler injections will, without a corresponding improvement in specificity, block more harmless content that merely resembles an injection (the benign hard-negative variants).

**Support would look like:** the current demonstration classifier's `benign_block_rate` compared across scenarios with different injection styles, or the same scenario suite run against classifiers with different thresholds.

**Status:** untested_design_intention. The benign-block-rate metric and the hard-negative benign variants exist and are measured (`email-benign-hard-negatives`), but no experiment has yet varied classifier sensitivity to test this specific claim.

## What "testing" a hypothesis here requires

Per `docs/EXPERIMENT_PROTOCOL.md`: at least three seeds for any confidence interval, a reviewed (not merely unreviewed) scenario set, and every relevant campaign's `evidence_status` at `measured_result` before the result is presented as more than a demonstration. A hypothesis "supported" by simulated components is a statement about the simulation, not about real defenses.
