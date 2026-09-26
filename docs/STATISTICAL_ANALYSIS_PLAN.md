# Statistical analysis plan

This is what `src/rtbt/statistics.py` actually implements, written as a plan so it can be checked against, not just read as a description after the fact.

## Unit of analysis

A campaign — one seeded run of one scenario against one defense with one attacker at one target mode — is the unit of independent replication. Rounds inside a campaign are never treated as independent observations, because an adaptive attacker's later rounds depend on its earlier ones by design. This is enforced, not just stated: `aggregate()` takes one value per campaign, never one per round, and every test that checks this (`tests/test_harness.py: BudgetAndIndependenceTests`, `ReproducibilityTests`) operates at the campaign level.

## Interval method

The default is a percentile bootstrap (2,000 resamples, deterministically seeded) over the per-campaign values in a group. This is bounded by construction: a bootstrap resample of values already in `[0, 1]` can never produce a mean outside `[0, 1]`, unlike a normal approximation, which can and did — see the changelog entry for the bug this replaced. A normal approximation remains available (`aggregate(..., method="normal")`) but is not the default.

Below three independent campaigns, no between-campaign interval is reported at all — only the descriptive mean, plus a Wilson interval computed from that one campaign's own valid rounds, explicitly labeled as a within-campaign descriptive supplement, not a substitute, and explicitly noted as not meaningful for an adaptive attacker (see `metrics.py: compute_campaign_metrics`, the `campaign_average_asr_within_campaign_wilson_ci` field).

## Paired comparisons

Static-versus-adaptive is a paired comparison: for each (scenario, defense, seed), the difference is adaptive-attack-success minus static-attack-success at the same seed, and the interval is a paired bootstrap over those differences (`statistics.static_vs_adaptive`). A direction (`adaptive_higher` / `static_higher`) is only reported when the interval excludes zero; otherwise the result is `null_or_undetermined`, and with the default 3–5 seeds this usually means the data is too thin to conclude anything, not that there is no effect.

## Wording

Nothing in this platform's output claims a result is confirmed beyond what the interval shows (`tests/test_core.py` scans the whole delivered tree to guard against that specific wording creeping back in). The word used instead is "detectable difference under this analysis," and only when an interval actually excludes zero.

## Evidence status is separate from statistical validity

An interval can be computed correctly and still describe a simulated component. Every aggregated row carries an `evidence_status` (`measured_result` only if every contributing campaign used real components; `simulated_result` otherwise — see `statistics.group_evidence_status()`), independent of whether the interval itself is wide or narrow, present or absent.

## Planned but not yet needed

Permutation tests and mixed-effects/hierarchical models are reasonable next steps once there are enough real campaigns across enough scenarios for the current per-group approach to feel undersized — nothing here rules them out, and `statistics.py`'s `aggregate()`/`bootstrap_ci()` functions are the natural place to add a method rather than replace them. Not implemented because there is not yet real data to apply them to.
