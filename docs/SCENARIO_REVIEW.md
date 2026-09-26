# Scenario review workflow

Every scenario ships as `author`-written and `validation_status: "unreviewed"`. This document is how that status changes, and what a reviewer actually checks.

## Run the validator first

```
python3 scripts/validate_scenarios.py
```

This is a prerequisite for review, not a substitute for it. Loading the suite (which this script does, and which every test run also does) already enforces schema validity, tool availability, injection-slot existence, and that the attack objective is never also an authorized action — see `parse_scenario()` in `src/rtbt/scenario_registry.py` for exactly what that covers. The script adds four checks that need a running environment rather than just the JSON:

- **Reset independence** — two environments built from the same scenario must never share mutated state, and building or using one must never change the scenario's own `initial_state`.
- **Deterministic oracle behavior / reproducibility** — the same scripted round, run twice with the same seed, must produce the identical oracle verdict.
- **Policy consistency** — the scenario's own legitimate action, run through its own policy, must not be blocked. A failure here means the policy and the simulated behavior disagree about what the task is allowed to do.
- **Unique identifiers** — enforced by loading the suite at all; a duplicate id raises before the script gets a chance to check anything else.

The script never changes `validation_status`. A clean run is necessary before a scenario is reviewed; it is not what makes a scenario reviewed.

One scenario is a documented, pre-approved exception to the policy-consistency check: `cal-schedule-sync`'s policy deliberately omits a legitimate destination to demonstrate a real security-versus-utility cost (see `docs/EXPERIMENT_PROTOCOL.md`). It declares this via `known_check_exceptions: ["policy_consistency"]` in its own JSON, with a `notes` field explaining why. The script reports it as `[WARN (approved)]`, prints the note next to it, and exits `0` — a declared, explained exception is not the same thing as a passing script silently hiding a problem, and it is not the same thing as an undeclared failure, which still exits `1` and still fails loudly.

## What a human reviewer checks that the script cannot

The script only catches what can be checked mechanically. Review is for judgment calls:

- Does the injected payload actually resemble the `category` and `difficulty` the scenario claims?
- Is the `attack_objective` a plausible thing a real attacker would want, described honestly in `brief` without giving away more than the real attacker boundary allows (see `docs/THREAT_MODEL.md`)?
- Does `utility` actually capture what "did the task correctly" means, or does it accept a shortcut?
- Is the policy realistic — would a reasonable team actually configure it this way — or is it a strawman that makes a defense look better or worse than it would in practice?
- Does the scenario's `notes` field explain every deliberately unusual design choice, the way `cal-schedule-sync` and `email-reply-lookalike` do?

## Recording a review

A reviewer sets four fields directly in the scenario's JSON file:

- `validation_status`: `"reviewed"` or `"rejected"`.
- `reviewer`: the reviewer's name.
- `review_date`: an ISO date, e.g. `"2026-10-01"`.
- `solvability_status`: whether the scenario's legitimate task is actually achievable as written — `"solvable_by_construction"` when the simulated behavior was checked against the policy and utility by hand, `"unverified"` otherwise.
- `oracle_validation_status`: whether the oracle's verdict was checked against a hand trace of the scenario — `"matches_hand_trace"` once it has been, `"unverified"` otherwise.

Editing any of these fields changes the scenario's `content_hash`, which is folded into the suite's own hash and recorded in every experiment manifest — so a report from before a review and one from after can never be mistaken for the same scenario version.

## What review is not

Passing `validate_scenarios.py` is not review. Review is not automatic, is never granted by this script, and is never granted by an AI assistant editing the file — `validation_status` starts at `"unreviewed"` and stays there until a person who is not the scenario's author sets it otherwise.
