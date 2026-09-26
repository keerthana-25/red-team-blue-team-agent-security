# Roadmap

## Initial prototype (done)

One synthetic environment, a deterministic target, static and deterministic-adaptive attackers, baseline and two defenses, basic metrics, logs, an initial dashboard. Superseded by the CMPE 295A prototype below, which covers everything here and more; kept as a historical milestone, not a separate thing to maintain.

## CMPE 295A research prototype (done, for the platform; not done, for the research)

**The platform is built and tested:** all three environments, a validated scenario schema with a review workflow (`docs/SCENARIO_REVIEW.md`) and a quarantined generation prototype, four defenses behind one interface, model adapters for a local attacker and a real target (written and unit-tested, never run against a live model), a repeatable evaluation pipeline with matched budgets and an explicit `model_failure_policy`, bounded statistics (Wilson and bootstrap intervals), a six-category evidence-status taxonomy that cannot be bypassed, enriched provenance (source-tree hash, artifact sidecar hashes), cost/token accounting, and SQLite-backed crash recovery. 156 tests, all passing.

**What CMPE 295A itself still needs, beyond the platform:**
- the formal threat model and research questions written as their own reviewed documents (this roadmap points at `docs/THREAT_MODEL.md` and `docs/RESEARCH_QUESTIONS.md`, which exist, but neither has been reviewed by anyone other than whoever wrote them);
- a literature review and a mapping from this benchmark's scenarios to any comparable published one;
- at least one pilot run against a real target model and a real model-backed attacker, with the outcome honestly labeled `measured_result` only if it earns that label (see `docs/EXPERIMENT_PROTOCOL.md` and the evidence-status rules in `src/rtbt/schemas.py`);
- human review of the scenario suite (`docs/SCENARIO_REVIEW.md`) — every scenario is still `unreviewed`;
- an advisor-ready demonstration built from a real pilot, not only the simulated defaults.

## CMPE 295B experimental study (not started)

Repeated matched-budget experiments across many seeds; the full static-versus-adaptive comparison run for real, not as a demonstration of the analysis; all four defense families evaluated against real components; confidence intervals reported honestly at whatever width the seed count actually supports; ablation studies (which parts of a defense matter); sensitivity analysis (how much do results move with the classifier threshold, the model temperature, the scenario set); error analysis (what invalid rounds and excluded runs looked like and why); a reproducibility package a third party could actually run; the final research paper; the final presentation and demonstration.

## Future work, beyond CMPE 295B

Ideas that are out of scope for either semester but worth recording so they are not lost: additional environments beyond email/documents/calendar; a trained (not regex) classifier; multi-turn conversational attacks; defenses that compose (more than one active at once); a hosted-classifier integration with real pricing; expanding scenario generation from a template-based stretch prototype into something that proposes genuinely novel scenarios, still under the same human-approval gate.

Nothing above is marked complete unless the corresponding tests or a documented human review actually back it up. Where this document and `docs/REQUIREMENTS_TRACEABILITY.md` seem to disagree on a status, the traceability document is the more precise source — this file is the narrative, that one is the ledger.
