# Architecture

## One round, end to end

A campaign is one attacker facing one defense on one scenario with one seed. It runs a fixed number of attack rounds followed by the scenario's benign control rounds. Every round follows the same path.

The harness builds a fresh environment from the scenario's initial state (never reusing one from an earlier round), asks the attacker for a payload, and injects that payload into the scenario's slot. It then wraps the environment in a `ToolRuntime` carrying the defense under test and hands the runtime to the target agent. The agent reads content and proposes writes, but only through the runtime. When the agent finishes, the oracle compares the environment state before and after against the scenario's objective and returns a verdict. The harness passes the attacker exactly one thing, the boolean `attack_succeeded`, and records the full round for the audit log.

```
Scenario (data) --> Environment (fresh each round) --> ToolRuntime <--> TargetAgent
                                                         |  ^
                                                    Defense hooks
Attacker --payload--> injected into slot        Oracle reads state only
   ^                                                     |
   +------------------ boolean only ---------------------+
```

## Modules

**`schemas.py`** holds the shared dataclasses (`AttackBrief`, `AttackAttempt`, tool call records, `Effect`), the error hierarchy rooted at `RtbtError`, and the error-category constants. Keeping the attacker-facing types here makes the feedback boundary easy to audit.

**`environments/`** implements the email, documents and calendar simulations behind one base class. Each defines its tools, the scopes each tool needs, argument validation, and a `snapshot()` used by the oracle. `effects.py` defines the state predicates (such as "an email to this address exists in the outbox") shared by the oracle and by scenario validation. Environments deep-copy their initial state, so a scenario is never mutated.

**`scenario_registry.py`** loads and validates scenario files and hashes their content. It refuses scenarios whose attack objective is also authorized, whose injection slot does not exist, or whose policy names unknown tools. See `SCENARIO_SCHEMA.md`.

**`policy_engine.py`** evaluates a proposed write against a scenario's policy (allowed tools, approved destinations, trusted domains, tools requiring confirmation) and returns allow, block or confirm with a reason code.

**`defenses.py`** defines the `Defense` base class with its three hooks and the four implementations. `build_defense()` is the only factory and rejects incomplete configurations.

**`runtime.py`** is the choke point. It runs `authorize_tool` before any write executes and `inspect_content` after any read, replaces withheld content with a fixed message, records everything for audit, and can stream events to a listener.

**`oracle.py`** decides success from state. `annotate_ground_truth()` is the only place the scenario's private `allowed_actions` are read, and it labels each write as authorized or not for later analysis.

**`attackers/`** contains the `Attacker` interface (`next_attempt(brief)` and `observe(success)`), the static set, the adaptive demo fixture, and the local-model attacker. **`target_agents/`** contains the `TargetAgent` interface, the simulated agent, and the real-model agent, both of which act only through the runtime.

**`harness.py`** runs campaigns and experiments, validates configurations before anything runs, supports cancellation with partial results kept, and builds the reproducibility manifest. **`metrics.py`** turns rounds into per-campaign metrics. **`statistics.py`** aggregates across campaigns. **`reporting.py`** assembles reports, provenance labels, the matched-budget check and the comparison table. **`netguard.py`** is the only module that touches the network. **`util.py`** has seed derivation and environment info.

**`run_demo.py`** and **`run_web.py`** are thin entry points. The web server exposes a JSON API over the same `ExperimentRunner`; the dashboard in `web/` is plain HTML, CSS and JavaScript that only talks to that API.

## Why the boundaries are where they are

The attacker interface takes an `AttackBrief` and a boolean and nothing else, so a new attacker cannot accidentally read defense information. Defenses see content and proposed calls and nothing else, so a new defense cannot read ground truth. The target agent acts only through the runtime, so a new agent cannot bypass a defense. The oracle reads state and nothing the agent or attacker wrote, so no participant can talk its way to a verdict. Each of these has a test that fails if the boundary is widened.

## Randomness and reproducibility

There is no global random state. Each round's seed is a SHA-256 based derivation from the campaign seed, the phase and the round number, and deliberately not from the defense. That makes the design paired: for a given seed every defense faces the same random draws, so differences between defenses are not swamped by luck of the draw, and adding or removing a defense from a sweep never changes any other campaign. The simulated agent's compliance roll is a hash of the round seed and the retrieved text (so it still varies by scenario), verified to be uniform over 20,000 samples.

## Extending it

To add an attacker, subclass `Attacker`, register it in `make_attacker()` in `attackers/__init__.py`, and add its id to `KNOWN_ATTACK_MODES` in `harness.py`. To add a defense, subclass `Defense`, implement whichever of the three hooks apply, declare its `provenance` string, register it in `build_defense()`, and add its id to `KNOWN_DEFENSES` in `harness.py`. To add a scenario, write a JSON file following `SCENARIO_SCHEMA.md`, list it in `scenarios/suite.json`, and run the tests; the validator will tell you what is wrong. To add an environment, subclass the environment base class and add effect kinds to `effects.py`.
