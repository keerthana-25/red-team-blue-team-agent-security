# Result interpretation guide

A short guide to reading what this platform actually produces, for anyone who did not build it — a professor, a teammate returning after a break, a future reader of the paper.

## Read the banner first

Every screen and every export says, in some form, whether what you are looking at is `measured_result` or `simulated_result`. If it says demonstration data, treat every number on that screen as an illustration of the method, not as a finding. This is not a formality — the default configuration of this platform is entirely simulated, and it will happily produce a clean-looking comparison table full of numbers that describe a deterministic stand-in, not a real defense.

## "Attack success rate" answers a narrower question than it sounds like

It is the share of valid attack rounds where the attacker's specific declared objective was achieved, checked against environment state, never against the attacker's payload text or the target's claims. It is not the share of rounds where anything unsafe happened — that is `unauthorized_action_executed_rate`, which can be higher, because it also counts an unsafe action that was not the attacker's actual goal (see the oracle code `UNSAFE_ACTION_EXECUTED_OFF_OBJECTIVE`).

## A defense's security number means nothing alone

Read attack success and legitimate-task completion together, always. A defense that shows 0% attack success and 0% task completion has not solved the problem — it has refused to do anything. The `cal-schedule-sync` scenario is built specifically so this shows up starkly: the tool validator there stops every attack and also blocks the entire legitimate task, because its policy is missing a destination. This is a demonstration of the platform's design, kept exactly as it is on purpose — see `docs/SCENARIO_REVIEW.md`.

## A confidence interval's absence is informative

Below three independent seeds, no between-campaign interval is shown at all, on purpose, instead of a falsely precise one. A single campaign's own Wilson interval (labeled "within-campaign") is a different, narrower claim — it describes the spread of that one campaign's own rounds, not the spread you would see across repeated seeds, and it is not meaningful at all for an adaptive attacker, whose rounds are not independent of each other.

## "No detectable difference" is not "no difference"

The static-versus-adaptive comparison reports a direction only when its interval excludes zero. With the platform's default of 3–5 seeds, most comparisons will land on "no detectable difference" — read that as "this experiment cannot tell," not as evidence that adaptation does not help. More seeds narrow the interval; they do not change the underlying effect.

## Attempted, blocked, and executed are three different numbers

The Compare view's grouped bar makes this visual on purpose: the full bar is how often the target proposed an unauthorized action at all, the colored-in portion is how much of that actually executed, and the remainder was blocked. A defense can look identical on "executed" while being very different on "attempted" — one may face fewer temptations to begin with (a different scenario mix), and one may face the same temptations but block nearly all of them.

## Provenance is how you check any of this yourself

Every exported report carries a scenario-suite content hash, a source-tree hash, the exact seeds and budget, and (when available) a Git commit — enough to know exactly what code and what scenario version produced a given number. Sidecar `.hashes.json` files let you confirm a report file has not been altered since it was written. If a number in a slide or a paper draft cannot be traced back through these to an actual run, do not present it as a result.

## When in doubt

Open the Audit view for the specific round in question. It shows the exact payload, the exact tool calls, the defense's decision and reason code, and the oracle's verdict — the ground truth every aggregate number in this platform is computed from.
