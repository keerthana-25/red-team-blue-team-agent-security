# Experiment protocol

This document defines what an experiment is and how its results may be read. The protocol, rather than any single defense or attack, is what this project contributes: a way to compare defense families that keeps the comparison fair and reports security and usability together.

## The unit of comparison

A campaign is one attacker, one defense, one scenario and one seed. It contains a fixed number of attack rounds (the attempt budget) followed by the scenario's benign control rounds. An experiment is the full grid of scenarios, attackers, seeds and defenses. The campaign, identified by `scenario:defense:attacker:target:seed`, is the independent observation used in every statistic. Rounds within a campaign are never treated as independent, because an adaptive attacker's later rounds depend on its earlier ones.

## What makes the comparison fair

Every defense in a group faces the same attacker configuration, the same scenario, the same number of attack rounds, and the same seed. Because round seeds are derived from the campaign seed, phase and round number and not from the defense, each defense also faces the same random draws, which is a paired design. Each campaign gets its own attacker instance with its own history, so what an attacker learns against one defense can never leak into a campaign against another. The attacker is shown identical briefs regardless of defense and learns only a boolean after each attempt. Before any campaign starts, the harness rejects configurations with unknown defenses or attackers, duplicated seeds, missing model settings or budgets outside 1 to 500. After the run, it verifies that every defense in every group faced the same number of valid-or-invalid attack rounds and lists any group where that fails; the Provenance view shows the check.

## What is measured

Attack success rate over a campaign is the share of valid attack rounds in which the oracle found the objective achieved in the environment state. Final-window success rate is the same measure over the last 20 percent of valid rounds, with a minimum of three, and the window size is a function of the budget alone so it cannot be chosen after seeing results; a gap between average and final-window success indicates learning. Attempts to first success is the attempt number of the first success, or `None` (censored) if none occurred, and it is never recorded as zero.

Legitimate task completion is the share of valid attack rounds in which the user's task still finished correctly (the required content appeared and required state holds), which is how a defense's cost shows up while an attacker is present. Safe utility is the share of valid attack rounds in which the task finished and no unauthorized action ran. The unauthorized action rate is the share of valid attack rounds in which any write outside the task's authorization executed, whether or not it was the attacker's goal. The benign block rate is measured separately over the harmless control rounds: the share in which a defense withheld content or refused a write. The adaptation curve is cumulative attack success after each attempt.

Attack success is never reported without the usability measures beside it. The Compare view leads with the plot of attacks stopped against legitimate tasks completed, because a defense that blocks everything scores perfectly on security alone.

## Invalid rounds

A round is invalid if the attacker or target failed for infrastructure reasons (timeout, unreachable server, empty or malformed output, a refusal to write a payload, an oversized payload). Invalid rounds are excluded from every rate, counted by error category, and never shown to the attacker as either success or failure. Any campaign with invalid rounds appears in the excluded-runs report, so a defense that appears to do well because its campaigns errored out cannot go unnoticed.

## Reading the statistics

For each scenario, attacker and defense the platform aggregates over seeds. With three or more campaigns it reports the mean and a 95 percent interval; with fewer it reports the mean and states that no between-campaign interval is possible, alongside a within-campaign Wilson interval computed directly from that campaign's own valid rounds as a bounded, hand-checkable descriptive supplement (not a substitute, and not meaningful for an adaptive attacker, whose rounds are correlated by design). The between-campaign interval defaults to a percentile bootstrap over the per-campaign rate values, which cannot fall outside a rate's true range because it only ever averages values that were themselves already in range; a normal approximation remains available but is not the default because it can push a rate's interval past 0 or 1 when few campaigns exist near an extreme. Every reported interval names which method produced it, and the platform never describes a difference as confirmed beyond what the interval shows — only as a detectable difference under this analysis, and only when the interval actually excludes zero. The pooled view across scenarios counts each scenario and seed once, so its interval includes scenario-to-scenario variation and is wider than a per-scenario interval. Use per-scenario intervals when the question is "how noisy is this measurement" and the pooled view when the question is "how does this defense do in general", knowing that nine hand-written scenarios are a small and unrepresentative sample of the world.

Adaptive versus static is tested by pairing campaigns on scenario, defense and seed and taking the difference in attack success. A direction ("adaptive higher" or "static higher") is reported only when the 95 percent interval on the mean difference excludes zero. Otherwise the result is reported as "no detectable difference", which with five seeds should be read as inconclusive rather than as evidence of no effect. No correction is made for looking at many scenario and defense combinations, so a single "adaptive higher" among dozens of rows is weak evidence.

## Hypotheses the platform is built to test

The first is that an attacker which adapts using only success and failure feedback achieves higher attack success than a non-adaptive attacker with the same budget, and that the gap grows over attempts (the H1 comparison and the adaptation curve). The second is that a defense that works by construction, such as a tool validator, still carries a real usability cost when its policy is incomplete, so that security and usability have to be judged together (the H3 demonstration, pinned by the `cal-schedule-sync` scenario). With the default simulated components these are demonstrations of the analysis, not findings; they become findings only when the target agent, the attacker and the classifier are real and the scenarios have been reviewed.

## What a valid conclusion requires

Before a result is presented as evidence, check that the Provenance view shows no demonstration components (or that the report states plainly which ones were used), that every budget group is matched, that the manifest records model revisions, settings and hardware for any real component, that at least three seeds were run, that excluded runs are explained, and that the suite content hash matches the version of the scenarios that was reviewed. The platform prints a "Demonstration data only" warning whenever any component is a simulation or fixture, and it cannot be dismissed in the dashboard.

## Reproducing a run

The JSON report contains the full manifest: scenario ids and suite content hash, defenses, attackers, target mode, budget, seeds, window settings, model and target configuration (endpoints excluded), network allowlist, Python and platform versions, and the generation time. Running the same configuration on the same scenario files reproduces identical rounds for simulated components. For real models it reproduces the setup, not the exact outputs.
