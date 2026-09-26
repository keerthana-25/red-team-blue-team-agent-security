# Real-model validation plan

This is the single biggest gap between "a working prototype" and "a research finding." It is written as a checklist because that is what it actually is — a sequence someone can follow and check off, not a description of work already done.

## Prerequisite

Ollama (or an equivalent local server exposing the same `/api/generate` request and response shape) installed and running on the machine that will run the experiment. Nothing in this plan requires a paid API; the adapters are written against a local, free model server.

## Step 1: health-check before anything else

Confirm the endpoint is reachable and returns a well-formed response for a trivial prompt, using the same `netguard.post_json` path the real adapters use (never a separate, unaudited request). If this fails, stop here — do not proceed to a campaign and do not report anything as tested.

## Step 2: real target, simulated attacker

Run a small sweep (`configs/real_target_example.json` is the starting point) with `target_mode: "real_model"` and the static attacker. This isolates one variable: does a real model behave like the simulated target agent assumes? Specifically check, via the Audit view:
- does the model actually call tools in the expected JSON shape, or does `TOOL_CALL_RX` in `target_agents/real_model.py` need adjustment for this model's actual output style;
- does it ever produce a malformed or truncated tool call, and is that correctly classified as an invalid round rather than crashing the campaign;
- do its plain-text final answers actually satisfy the scenarios' `utility.response_terms`, or do the scenarios need adjustment for how a real model phrases things.

Expect to iterate on the regex and possibly the scenario wording before this step is genuinely clean. Do not skip to Step 3 until it is.

## Step 3: real attacker, simulated target

Run `configs/local_model_attacker_example.json`'s shape with `attack_mode: "adaptive_ollama"` against the simulated target. Check, via the Audit view and `attacker_stats()`:
- refusal rate — does this model refuse the attacker role outright, making the abliterated-vs-standard comparison the project intends actually possible;
- whether token counts are being captured (`prompt_eval_count`/`eval_count` in the raw Ollama response) — if the local model's response never includes them, that is worth recording as a fact about this model, not silently ignored;
- whether `model_failure_policy` behaves as expected if the model is stopped mid-campaign (a good opportunity to deliberately test this against a real process, not just the test suite's mocks).

## Step 4: both real at once

Only after Steps 2 and 3 are individually clean. Run a small matched-budget sweep with both real, across all four defenses, 3–5 seeds. This is the first campaign whose `evidence_status` can legitimately read `measured_result` (see `src/rtbt/schemas.py: evidence_status_for_campaign` — it requires every component to be real, not just one).

## Step 5: record what changed

Update `docs/LIMITATIONS.md` (remove "never run against a live model" once it no longer applies), `docs/RESEARCH_QUESTIONS.md` (fill in actual answers where they exist now), and `docs/REQUIREMENTS_TRACEABILITY.md` (move the relevant rows from "Implemented but unverified" to "Implemented and verified"). Record the exact model name, revision, quantization, and hardware in the run's manifest — this is why those fields exist.

## What this plan is not

It is not a claim that any of this has happened. As of this document, every step above is unstarted. The adapters exist and pass their unit tests against mocked responses; nothing here has touched a live model. Anyone completing a step should say so plainly, with the actual output, not just check a box.
