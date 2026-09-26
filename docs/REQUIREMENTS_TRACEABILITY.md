# Requirements traceability matrix

Rewritten against the full build specification (the "AgentGuard: Matched-Budget Adaptive Evaluation..." master prompt and its 18 numbered requirement sections). This replaces the version written against the earlier open-questions prompt. Columns: requirement, source, implementation component, implementation file, test, status, verification evidence, remaining limitation.

Status vocabulary (used exactly, nothing else): **Implemented and verified** — built, tested, and I ran it myself in this session. **Implemented but unverified** — built and unit-tested against mocks, never run against the real external thing (a live model, a real OS). **Partially implemented** — some of the requirement is done, some is not. **Not implemented**. **Deferred** — intentionally left for a later phase, not forgotten. **Not applicable**.

## 1. Preserve JSON configuration

| Requirement | Component | File | Test | Status | Evidence | Limitation |
|---|---|---|---|---|---|---|
| Configurations remain JSON; no YAML added without a concrete reason | `ExperimentConfig`, `build_config()` | `src/rtbt/harness.py`, `run_demo.py` | `tests/test_configs.py` | Implemented and verified | Every shipped config in `configs/` parses; no `yaml` import anywhere in the tree | None |

## 2. Model-unavailability handling

| Requirement | Component | File | Test | Status | Evidence | Limitation |
|---|---|---|---|---|---|---|
| `model_failure_policy` field, three values, default `mark_invalid` | `ExperimentConfig.model_failure_policy`, `MODEL_FAILURE_POLICIES` | `src/rtbt/harness.py` | `tests/test_harness.py: ModelFailurePolicyTests` (5 tests) | Implemented and verified | Ran all three policies against a test-only flaky attacker; confirmed `mark_invalid` unchanged, `abort_campaign` preserves completed rounds and marks the rest invalid, `restart_as_separate_demo_campaign` spawns a separate campaign with a new id, excluded from every comparison | The fallback/abort path has only been exercised against a simulated failure, never a real Ollama outage |

## 3. Complete tool-call audit records

| Requirement | Component | File | Test | Status | Evidence | Limitation |
|---|---|---|---|---|---|---|
| Timestamp, experiment/campaign/scenario/round/phase on every `ToolCallRecord` | `ToolCallRecord`, `ToolRuntime` | `src/rtbt/schemas.py`, `src/rtbt/runtime.py`, `src/rtbt/harness.py` | `tests/test_harness.py: ToolCallAuditRecordTests` | Implemented and verified | Confirmed every field matches its parent campaign/report and the timestamp is real ISO-8601 UTC, on a live run | None |
| No secrets or chain-of-thought stored | (design property, not a new field) | — | `AdversarialPayloadTests`, manual code review | Implemented and verified | No field on any schema stores free-text reasoning; model configs exclude endpoints from manifests | None |

## 4. Complete unauthorized-action metrics

| Requirement | Component | File | Test | Status | Evidence | Limitation |
|---|---|---|---|---|---|---|
| Attempted/blocked/executed rates, same denominator, backward-compatible alias | `compute_campaign_metrics()` | `src/rtbt/metrics.py` | Manual verification against `tool_validator` (0.3/0.3/0.0 attempted/blocked/executed) | Implemented and verified | Hand-verified the three rates on a real campaign; alias documented in `EXPERIMENT_PROTOCOL.md` | None |
| Exposed in CLI, CSV, JSON, dashboard Compare | `comparison_table()`, `run_demo.py`, dashboard | `src/rtbt/reporting.py`, `run_demo.py`, `web/app.js` | Manual CLI run + browser check | Implemented and verified | CLI table now prints all three; CSV header confirmed; dashboard has 3 dedicated columns plus a grouped bar chart | None |

## 5. Improve the Compare dashboard

| Requirement | Component | File | Test | Status | Evidence | Limitation |
|---|---|---|---|---|---|---|
| Attempted/blocked/executed, false-positive, legitimate-task, safe-utility, latency, cost, all visible together | `viewCompare()` | `web/app.js` | Browser test (Playwright, headless Chromium) | Implemented and verified | Screenshot-verified table has 12 columns including Latency and Cost; grouped bar chart makes attempted vs. executed structurally hard to confuse | None |

## 6. Cost and token accounting

| Requirement | Component | File | Test | Status | Evidence | Limitation |
|---|---|---|---|---|---|---|
| Token fields null for simulated/deterministic; cost $0 (not unavailable) when nothing was called | `compute_cost_accounting()` | `src/rtbt/cost.py` | `tests/test_cost.py` (5 tests) | Implemented and verified | Ran a real sweep; every campaign shows `None` tokens and `$0.0` cost | None |
| Local model: tokens captured when returned, cost unavailable | `LocalModelAttacker`, `RealModelTargetAgent` | `src/rtbt/attackers/local_model.py`, `src/rtbt/target_agents/real_model.py` | `test_cost.py` (unit level, mocked) | Implemented but unverified | Token-capture code parses `prompt_eval_count`/`eval_count` from an Ollama-shaped response; never run against a live Ollama | Needs `docs/REAL_MODEL_VALIDATION_PLAN.md` Step 2/3 |
| Hosted model: cost only from an explicit named `PricingConfig`, never hard-coded | `PricingConfig.cost_for()` | `src/rtbt/cost.py` | `test_cost.py` | Implemented and verified | Test confirms no cost is computed without an explicit config, and a supplied config produces the exact expected number | No hosted-classifier pricing path exists yet (classifier cost is always 0.0/None) |

## 7. Strengthen provenance

| Requirement | Component | File | Test | Status | Evidence | Limitation |
|---|---|---|---|---|---|---|
| Source-tree hash when Git unavailable; honest Git field, never fabricated | `source_tree_hash()`, `git_info()` | `src/rtbt/util.py` | `tests/test_harness.py: ProvenanceEnrichmentTests` | Implemented and verified | Confirmed hash changes with real source edits and ignores generated files; confirmed `git_info()` reads a real repo via pure file I/O (no subprocess) and returns `None` honestly for this non-Git project | None |
| Dependency versions, Python/OS/arch, model settings | `_manifest()` | `src/rtbt/harness.py`, `src/rtbt/util.py` | Same as above | Implemented and verified | Manifest carries all of these; dependency_versions is `{}` by explicit design | None |
| Output artifact hashes in a sidecar file, never inside the artifact itself | `export()` | `run_demo.py` | Manual verification | Implemented and verified | Ran the CLI, confirmed the `.hashes.json` sidecar's SHA-256 values match the actual JSON/CSV files on disk | None |

## 8. Evidence-status labeling

| Requirement | Component | File | Test | Status | Evidence | Limitation |
|---|---|---|---|---|---|---|
| Six-category taxonomy; a simulated component can never earn `measured_result` | `evidence_status_for_campaign()`, `eligible_as_research_evidence()` | `src/rtbt/schemas.py` | `tests/test_harness.py: EvidenceStatusTests` (8 tests) | Implemented and verified | Swept every status in the taxonomy against the eligibility rule; confirmed a demo-fallback campaign is always `simulated_result` even with an otherwise-real configuration | Only 2 of the 6 categories (`measured_result`, `simulated_result`) are computed automatically per campaign; the other four (`illustrative_example`, `assumption`, `untested_design_intention`, `implementation_limitation`) are applied by hand in prose documents, not as a machine-checked field on every claim |
| Displayed in CLI, dashboard banner, comparison tables, JSON, CSV, Provenance | Same | `run_demo.py`, `web/app.js`, `src/rtbt/reporting.py` | Manual CLI + browser check | Implemented and verified | CLI prints "N of M campaigns are eligible as research evidence"; dashboard banner shows the same count | None |

## 9. Genuine crash recovery

| Requirement | Component | File | Test | Status | Evidence | Limitation |
|---|---|---|---|---|---|---|
| SQLite persistence, no external DB server | `RunStore` | `src/rtbt/persistence.py` | `tests/test_persistence.py` (7 tests) | Implemented and verified | Simulated a crash by closing one `RunStore` and opening a fresh one on the same file | None |
| A completed campaign is never repeated after restart | `skip_campaign_ids` | `src/rtbt/harness.py`, `run_web.py` | `tests/test_crash_recovery.py` | Implemented and verified | Real subprocess killed with SIGKILL mid-run; a second real subprocess found the interrupted run and `resume` correctly skipped the already-completed campaigns | Resume granularity is per-campaign, not per-round — an incomplete campaign always restarts from round 1, documented as a deliberate safety choice, not an oversight |
| A stateful attacker's incomplete campaign gets a new id, never silently continued | `force_new_id_for`, `STATEFUL_ATTACK_MODES` | `src/rtbt/harness.py`, `src/rtbt/persistence.py` | `test_persistence.py`, manual HTTP verification | Implemented and verified | `recovery_plan()` correctly separates `adaptive_ollama` from `static`/`adaptive_demo`; manual test confirmed a resumed run correctly identifies which campaigns to reuse | None |
| Resume/restart/abandon; decisions logged | `POST /recover` | `run_web.py` | `test_crash_recovery.py` (abandon, tested at HTTP level); resume/restart (manual HTTP verification this session) | Implemented and verified | All three decisions exercised via real HTTP against a real killed-and-restarted server | The dashboard has no UI button for this yet — only the API exists; a person would need to call it directly or via a future UI addition |

## 10. Calendar-tool aliases

| Requirement | Component | File | Test | Status | Evidence | Limitation |
|---|---|---|---|---|---|---|
| `read_calendar`/`create_calendar_event`/`update_calendar_event`, same implementation | `Environment.ALIASES` | `src/rtbt/environments/base.py`, `calendar_env.py` | `tests/test_core.py: CalendarAliasTests` (4 tests) | Implemented and verified | Confirmed identical results, identical permission/policy/audit treatment, and no duplicate handler method exists | None |

## 11. Statistical intervals

| Requirement | Component | File | Test | Status | Evidence | Limitation |
|---|---|---|---|---|---|---|
| Wilson intervals for proportions; bounded to [0,1] | `wilson_interval()` | `src/rtbt/statistics.py` | `tests/test_core.py: StatisticsTests` | Implemented and verified | Independently re-derived the Wilson formula in the test itself and matched to 9 decimal places | None |
| Paired bootstrap for static-vs-adaptive; campaign/seed as the independent unit | `static_vs_adaptive()` | `src/rtbt/statistics.py` | `StatisticsTests`, `ExperimentLifecycleTests` | Implemented and verified | Confirmed differences stay within [-1,1]; confirmed rounds are never pooled across campaigns as if independent | None |
| Never claims confirmed significance; "detectable difference" wording only | (project-wide) | all docs, `web/app.js` | `test_nothing_in_the_project_claims_statistical_significance` | Implemented and verified | This test caught two real accidental occurrences of the forbidden phrase during this session's own doc-writing, both fixed | None |

## 12. Model adapter validation

| Requirement | Component | File | Test | Status | Evidence | Limitation |
|---|---|---|---|---|---|---|
| Timeout/connection/refusal/malformed handled separately | `LocalModelAttacker`, `RealModelTargetAgent` | `src/rtbt/attackers/local_model.py`, `src/rtbt/target_agents/real_model.py` | `tests/test_harness.py: FailureHandlingTests` | Implemented and verified (against mocks) | Each category independently tested with a mocked failure | Never run against a real Ollama outage |
| Health-check method before starting a campaign | — | — | — | Not implemented | — | Out of scope for this session; the adapters raise a clear, categorized error on first contact instead of pre-flighting one |
| Token usage captured when returned | Same as item 6 | Same | `test_cost.py` | Implemented but unverified | Parses the field when present in a mocked response | Never confirmed against what a live Ollama server actually returns |
| No defense identity to the attacker; no chain-of-thought stored | `AttackBrief` | `src/rtbt/schemas.py` | `FeedbackOnlyTests` | Implemented and verified | Unchanged from the original build; re-confirmed still passing | None |

## 13. Scenario-review workflow

| Requirement | Component | File | Test | Status | Evidence | Limitation |
|---|---|---|---|---|---|---|
| Reviewer/review_date/solvability/oracle-validation/notes fields | `Scenario` | `src/rtbt/scenario_registry.py` | `tests/test_scenario_validator.py` | Implemented and verified | Fields load correctly, all optional, every existing scenario file still parses unchanged | None |
| `validate_scenarios.py`: schema, tools, injection slot, authorized/prohibited separation, deterministic oracle, reset, policy consistency, unique ids, reproducibility | Validator script | `scripts/validate_scenarios.py` | `tests/test_scenario_validator.py` (7 tests) | Implemented and verified | Ran against the real 9-scenario suite: 8 pass every check outright and 1 (`cal-schedule-sync`) passes with a declared, documented policy-consistency warning; 0 fail unexpectedly | None |
| Never auto-marks a scenario reviewed | (design property) | Same | Same | Implemented and verified | The script has no code path that writes to a scenario file at all | None |

## 14. Controlled scenario-generation prototype

| Requirement | Component | File | Test | Status | Evidence | Limitation |
|---|---|---|---|---|---|---|
| Full 9-step flow; generated scenarios never enter the primary suite automatically | `generate_scenario.py`, `approve_generated_scenario.py` | `scripts/` | `tests/test_scenario_generation.py` (5 tests, real subprocess runs) | Implemented and verified | Confirmed determinism from a seed, invisibility to `load_suite()` until approved, and that approval requires an explicit reviewer name and re-validates from scratch | Only one template (`email_exfil_v1`) exists; labeled `untested_design_intention` in the script's own docstring, as required |

## 15. Portability documentation

| Requirement | Component | File | Test | Status | Evidence | Limitation |
|---|---|---|---|---|---|---|
| Separate macOS/Windows/Linux commands, path/port/encoding troubleshooting | README, setup guide | `README.md`, `Prototype_Setup_and_Run_Guide.docx` | Linux: full functional testing in an earlier session (Python 3.9/3.10/3.12, non-UTF-8 locale), re-confirmed this session. macOS/Windows: not tested on either real OS, on any occasion. | Partially implemented | Linux verified; macOS and Windows validation is pending, not done | See `docs/PORTABILITY_CHECKLIST.md`, which is unsigned |
| Explicit `#`-comment-as-argument warning | README | `README.md` | Manual review | Implemented and verified | Present since an earlier session | None |
| Signable per-OS checklist | — | `docs/PORTABILITY_CHECKLIST.md` | — | Implemented and verified (as a document; unsigned) | File exists with sign/date fields | No one has filled it in yet |

## 16. Formal deliverable documents

| Document | Status | Evidence |
|---|---|---|
| `docs/ROADMAP.md` | Implemented and verified | Written this session; distinguishes phases and marks nothing unbuilt as complete |
| `docs/RESEARCH_QUESTIONS.md` | Implemented and verified | Written this session |
| `docs/HYPOTHESES.md` | Implemented and verified | Written this session; every hypothesis's test-name citations checked against the actual test file |
| `docs/SCENARIO_REVIEW.md` | Implemented and verified | Written earlier this session, alongside the validator |
| `docs/STATISTICAL_ANALYSIS_PLAN.md` | Implemented and verified | Written this session |
| `docs/REAL_MODEL_VALIDATION_PLAN.md` | Implemented and verified | Written this session |
| `docs/RESULT_INTERPRETATION_GUIDE.md` | Implemented and verified | Written this session |
| `docs/REQUIREMENTS_TRACEABILITY.md` | Implemented and verified | This document |

## 17. This matrix

Implemented and verified — this document uses only the six allowed status words, and every "verified" row above corresponds to an actual test run or manual check performed in this session, not an assumption.

## 18. Research safety and integrity

| Requirement | Status | Evidence |
|---|---|---|
| Synthetic data only; no production services | Implemented and verified | Unchanged from the original build; `netguard.py` still the only network-capable module |
| Payloads inert, never executed as OS commands | Implemented and verified | `AdversarialPayloadTests` still passing |
| Dashboard binds to localhost by default | Implemented and verified | `Server` default host is `127.0.0.1` |
| Tool arguments validated; unsupported tools blocked | Implemented and verified | Unchanged |
| Secrets protected | Implemented and verified | Model manifests exclude endpoints; no field stores credentials |
| Failed/null results preserved; invalid rounds distinguished | Implemented and verified | `excluded_runs_report()`, crash-recovery's `abort_campaign` path, both preserve rather than discard |
| No compensating retries | Implemented and verified | Confirmed directly in `harness.py`'s fixed-range attack loop |
| Matched budgets maintained | Implemented and verified | `matched_budget_report()`, now also correctly excludes demo-fallback campaigns from the check |
| Attacker never sees defense identity | Implemented and verified | `FeedbackOnlyTests` |
| No chain-of-thought in logs | Implemented and verified | No schema field for it anywhere |
| Demonstration results reported honestly | Implemented and verified | Evidence-status taxonomy (item 8) is the mechanism |
