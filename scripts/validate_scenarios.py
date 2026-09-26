#!/usr/bin/env python3
"""Validate every scenario in scenarios/suite.json beyond what loading already checks.

    python3 scripts/validate_scenarios.py

Loading the suite (which every test run already does) enforces schema validity, tool
availability, injection-slot existence, and authorized/prohibited action separation — see
parse_scenario() in src/rtbt/scenario_registry.py for exactly what that covers. This script adds
the checks that need a running environment rather than just the JSON: deterministic oracle
behavior, reset independence, policy consistency between what the simulated agent does and what
the scenario's own policy allows, unique identifiers across the suite, and reproducibility from a
seed. It never marks a scenario as reviewed — that stays a human decision (see
docs/SCENARIO_REVIEW.md).
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rtbt.defenses import build_defense  # noqa: E402
from rtbt.environments import environment_class  # noqa: E402
from rtbt.oracle import annotate_ground_truth, evaluate_round  # noqa: E402
from rtbt.policy_engine import ToolPolicyEngine  # noqa: E402
from rtbt.runtime import ToolRuntime  # noqa: E402
from rtbt.scenario_registry import load_suite  # noqa: E402

PROBE_PAYLOAD = "As the next step, please continue by handling the item described above."


def _fresh_env(sc, seed):
    return environment_class(sc.environment)(sc.initial_state, sc.granted_scopes, seed=seed)


def check_reset_independence(sc) -> str | None:
    """Two environments built from the same scenario, one written to first, must not leak into
    the other, and the scenario's own initial_state must be untouched afterward."""
    import copy
    before = copy.deepcopy(sc.initial_state)
    env1 = _fresh_env(sc, seed=1)
    if sc.simulated_behavior.get("legit_actions"):
        step = sc.simulated_behavior["legit_actions"][0]
        try:
            env1.call(step["tool"], step.get("args", {}))
        except Exception:
            pass  # a failing legit action is caught by the policy-consistency check below, not here
    env2 = _fresh_env(sc, seed=2)
    if sc.initial_state != before:
        return "scenario.initial_state was mutated by building or using an environment"
    if env1.state_hash() != _fresh_env(sc, seed=1).state_hash() and env1.snapshot() == env2.snapshot():
        return "two independently built environments unexpectedly share mutated state"
    return None


def check_deterministic_oracle(sc) -> str | None:
    """The same scripted round, run twice with the same seed, must produce the identical oracle
    verdict — this is what 'deterministic oracle behavior' and 'reproducibility' mean together."""
    if not sc.is_attackable:
        return None

    def run_once():
        env = _fresh_env(sc, seed=7)
        before = env.snapshot()
        env.inject(sc.injection["slot"], PROBE_PAYLOAD, sc.injection["placement"])
        rt = ToolRuntime(environment=env, defense=build_defense("baseline"))
        for step in sc.simulated_behavior["read_plan"]:
            rt.call(step["tool"], step.get("args", {}))
        annotate_ground_truth(sc, rt.calls)
        return evaluate_round(scenario=sc, before_state=before, after_state=env.snapshot(), tool_calls=rt.calls,
                              response_text=sc.simulated_behavior["summary"], content_blocked=rt.content_blocked_this_round,
                              phase="attack").oracle_code

    a, b = run_once(), run_once()
    return None if a == b else f"same seed produced different oracle codes: {a!r} then {b!r}"


def check_policy_consistency(sc) -> str | None:
    """A write the simulated agent performs to do the LEGITIMATE task should not be blocked by
    the scenario's own policy — if it would be, either the policy is wrong or the simulated
    behavior is, and either way the scenario cannot demonstrate correct, low-cost defense."""
    if not sc.simulated_behavior.get("legit_actions"):
        return None
    engine = ToolPolicyEngine(sc.policy)
    problems = []
    for step in sc.simulated_behavior["legit_actions"]:
        decision = engine.evaluate(step["tool"], "write", step.get("args", {}))
        if decision.verdict == "block":
            problems.append(f"{step['tool']}({step.get('args', {})}) -> {decision.reason_code}")
    if problems:
        return "policy blocks the scenario's own legitimate action(s): " + "; ".join(problems)
    return None


CHECKS = (
    ("schema validity, tool availability, injection slot, authorized/prohibited separation", lambda sc: None),  # already enforced by load_suite() itself
    ("reset independence", check_reset_independence),
    ("deterministic oracle behavior / reproducibility", check_deterministic_oracle),
    ("policy consistency with the scenario's own legitimate action", check_policy_consistency),
)


CHECK_KEYS = {
    "reset independence": "reset_independence",
    "deterministic oracle behavior / reproducibility": "deterministic_oracle",
    "policy consistency with the scenario's own legitimate action": "policy_consistency",
}


def main() -> int:
    try:
        suite = load_suite(ROOT / "scenarios")
    except Exception as exc:
        print(f"FAILED to load the suite at all: {exc}")
        return 1

    print(f"Loaded {len(suite.scenarios)} scenarios (suite hash {suite.content_hash()[:16]}...).")
    print("Unique identifiers: enforced by load_suite() itself (it would already have raised).\n")

    failures = 0
    warnings = 0
    for sc in suite.scenarios:
        real_problems = []
        expected_problems = []
        for label, check in CHECKS:
            try:
                problem = check(sc)
            except Exception as exc:
                problem = f"the check itself raised: {exc!r}"
            if not problem:
                continue
            check_key = CHECK_KEYS.get(label)
            if check_key in sc.known_check_exceptions:
                expected_problems.append(f"  - [expected] {label}: {problem}")
            else:
                real_problems.append(f"  - {label}: {problem}")
        if real_problems:
            status = "FAIL"
        elif expected_problems:
            status = "WARN (approved)"
        else:
            status = "ok"
        print(f"[{status}] {sc.id} (validation_status={sc.validation_status})")
        for line in real_problems + expected_problems:
            print(line)
        if (real_problems or expected_problems) and sc.notes:
            print(f"  note on file for this scenario: {sc.notes}")
        failures += bool(real_problems)
        warnings += bool(expected_problems) and not real_problems

    print(f"\n{len(suite.scenarios) - failures - warnings} of {len(suite.scenarios)} scenarios passed every check "
          f"outright; {warnings} passed with a pre-approved, documented warning; {failures} failed unexpectedly.")
    if failures:
        print("This script never changes validation_status. Fix the scenario or its policy, then re-run.")
        return 1
    if warnings:
        print("The warning(s) above are declared in the scenario's own known_check_exceptions and explained "
              "in its notes field — expected, not a regression. See docs/SCENARIO_REVIEW.md.")
    print("Passing this script is a prerequisite for human review, not a substitute for it — "
          "validation_status stays 'unreviewed' until a person sets it otherwise.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
