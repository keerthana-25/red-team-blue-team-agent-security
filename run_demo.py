#!/usr/bin/env python3
"""Command-line entrypoint for AgentGuard / Red Team vs. Blue Team for Tool-Using Agents.

Usage:
    python3 run_demo.py                                   # default demo sweep
    python3 run_demo.py --config configs/quick_demo.json   # from a config file
    python3 run_demo.py --scenarios email-summary-exfil --defenses baseline,classifier \
        --attack-modes static,adaptive_demo --budget 20 --seeds 1,2,3

Always prints the "Demonstration data only" warning unless every campaign used real
model components. Exports full JSON and a flat CSV comparison table to results/.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from rtbt.attackers.local_model import ModelConfig  # noqa: E402
from rtbt.harness import ExperimentConfig, ExperimentRunner  # noqa: E402
from rtbt.scenario_registry import load_suite  # noqa: E402
from rtbt.util import sha256_file, use_utf8_output, utc_now_iso  # noqa: E402
from rtbt.statistics import comparison_by_scenario_defense, excluded_runs_report, static_vs_adaptive  # noqa: E402
from rtbt.target_agents.real_model import RealTargetConfig  # noqa: E402

DEFAULT_SCENARIOS_DIR = ROOT / "scenarios"
DEFAULT_RESULTS_DIR = ROOT / "results"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", type=str, default=None, help="Path to a JSON experiment config.")
    p.add_argument("--scenarios", type=str, default=None, help="Comma-separated scenario ids (default: suite primary set).")
    p.add_argument("--defenses", type=str, default="baseline,defensive_prompt,classifier,tool_validator")
    p.add_argument("--attack-modes", type=str, default="static,adaptive_demo")
    p.add_argument("--budget", type=int, default=20)
    p.add_argument("--seeds", type=str, default="1,2,3")
    p.add_argument("--target-mode", type=str, default="simulated", choices=["simulated", "real_model"])
    p.add_argument("--suite-dir", type=str, default=str(DEFAULT_SCENARIOS_DIR))
    p.add_argument("--out-dir", type=str, default=str(DEFAULT_RESULTS_DIR))
    p.add_argument("--ollama-model", type=str, default=None, help="Enable adaptive_ollama with this model name.")
    p.add_argument("--ollama-abliterated", action="store_true")
    p.add_argument("--model-failure-policy", type=str, default="mark_invalid",
                   choices=["mark_invalid", "abort_campaign", "restart_as_separate_demo_campaign"],
                   help="What to do when a model-backed attacker becomes unavailable mid-campaign.")
    return p.parse_args()


def build_config(args: argparse.Namespace) -> ExperimentConfig:
    if args.config:
        raw = json.loads(Path(args.config).read_text(encoding="utf-8"))
        model_config = ModelConfig(**raw["model_config"]) if raw.get("model_config") else None
        real_config = RealTargetConfig(**raw["real_target_config"]) if raw.get("real_target_config") else None
        return ExperimentConfig(
            defenses=tuple(raw["defenses"]), attack_modes=tuple(raw["attack_modes"]),
            attack_budget=raw["attack_budget"], seeds=tuple(raw["seeds"]),
            target_mode=raw.get("target_mode", "simulated"),
            scenario_ids=tuple(raw["scenario_ids"]) if raw.get("scenario_ids") else None,
            model_config=model_config, real_target_config=real_config,
            classifier_spec=raw.get("classifier_spec"),
            final_window_fraction=raw.get("final_window_fraction", 0.2),
            final_window_minimum=raw.get("final_window_minimum", 3),
            network_allowlist=tuple(raw["network_allowlist"]) if raw.get("network_allowlist") else None,
            model_failure_policy=raw.get("model_failure_policy", "mark_invalid"),
        )

    attack_modes = tuple(args.attack_modes.split(","))
    model_config = None
    if args.ollama_model or "adaptive_ollama" in attack_modes:
        model_config = ModelConfig(name=args.ollama_model or "unspecified", abliterated=args.ollama_abliterated)
    return ExperimentConfig(
        defenses=tuple(args.defenses.split(",")), attack_modes=attack_modes, attack_budget=args.budget,
        seeds=tuple(int(s) for s in args.seeds.split(",")), target_mode=args.target_mode,
        scenario_ids=tuple(args.scenarios.split(",")) if args.scenarios else None, model_config=model_config,
        model_failure_policy=args.model_failure_policy,
    )


def print_comparison_table(rows: list[dict]) -> None:
    headers = ["scenario_id", "attack_mode", "defense_id", "campaign_average_asr", "final_window_asr",
               "legitimate_task_completion_rate", "safe_utility_rate", "benign_block_rate",
               "unauthorized_action_attempted_rate", "unauthorized_action_blocked_rate", "unauthorized_action_executed_rate"]
    widths = {h: max(len(h), 8) for h in headers}
    print(" | ".join(h.ljust(widths[h]) for h in headers))
    print("-+-".join("-" * widths[h] for h in headers))
    for row in rows:
        cells = []
        for h in headers:
            v = row.get(h)
            cells.append((f"{v:.3f}" if isinstance(v, float) else str(v)).ljust(widths[h]))
        print(" | ".join(cells))


def export(report, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"{report.experiment_id}.json"
    json_path.write_text(json.dumps(report.to_dict(), separators=(",", ":")), encoding="utf-8")  # compact: full audit detail is large

    csv_path = out_dir / f"{report.experiment_id}.csv"
    rows = report.comparison_table()
    if rows:
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    # Hashes recorded in a SEPARATE sidecar file, never inside the artifact each hash covers —
    # hashing a file and then writing that hash back into the same file is circular and would
    # make the recorded hash describe a version of the file that no longer exists.
    sidecar_path = out_dir / f"{report.experiment_id}.hashes.json"
    sidecar_path.write_text(json.dumps({
        "json_report": {"path": json_path.name, "sha256": sha256_file(json_path)},
        "csv_comparison": {"path": csv_path.name, "sha256": sha256_file(csv_path)} if csv_path.exists() else None,
        "generated_at": utc_now_iso(),
    }, indent=2), encoding="utf-8")
    return json_path, csv_path


def main() -> None:
    use_utf8_output()
    args = parse_args()
    suite = load_suite(args.suite_dir)
    config = build_config(args)

    print(f"Suite '{suite.suite_id}' v{suite.version} — {len(suite.scenarios)} scenario(s) loaded "
          f"({len(suite.primary())} in the primary set).")
    print(f"Running: defenses={config.defenses} attack_modes={config.attack_modes} "
          f"budget={config.attack_budget} seeds={config.seeds} target_mode={config.target_mode}\n")

    report = ExperimentRunner(suite=suite, config=config).run()

    prov = report.provenance_summary()
    if prov["demonstration_warning"]:
        print("=" * 78)
        print(prov["demonstration_warning"].upper())
        print(f"Component mix: {prov['component_mix']} "
              f"(simulated_target={prov['simulated_target_campaigns']}, "
              f"real_target={prov['real_target_campaigns']}, real_attacker={prov['real_attacker_campaigns']})")
        demo = [f"{c['role']}: {c['name']}" for c in prov["components"] if c["is_demonstration"]]
        print("Demonstration components: " + "; ".join(demo))
        n_measured = sum(1 for c in report.campaigns if c.evidence_status == "measured_result")
        print(f"Evidence status: {n_measured} of {len(report.campaigns)} campaigns are eligible as research evidence (measured_result); the rest are simulated_result.")
        print("=" * 78 + "\n")

    unmatched = [m for m in report.matched_budget_report() if not m["matched"]]
    if unmatched:
        print("WARNING — matched-budget check FAILED for:")
        for m in unmatched:
            print(f"  {m['scenario_id']} / {m['attack_mode']}: {m['detail']}")
        print()

    print_comparison_table(report.comparison_table())

    if len(config.seeds) >= 1:
        print("\n-- Aggregated ASR across seeds (campaign_average_asr) --")
        for row in comparison_by_scenario_defense(report.primary_campaigns, "campaign_average_asr"):
            ci = f"[{row['ci_95_low']:.3f}, {row['ci_95_high']:.3f}] ({row['ci_method']})" if row["ci_95_low"] is not None else "n/a"
            mean_s = f"{row['mean']:.3f}" if row["mean"] is not None else "n/a"
            print(f"  {row['scenario_id']:28} {row['attack_mode']:14} {row['defense_id']:16} "
                 f"n={row['n']} mean={mean_s} 95% CI={ci}")

        if len(set(config.attack_modes) & {"static", "adaptive_demo", "adaptive_ollama"}) >= 2 and "static" in config.attack_modes:
            adaptive_mode = next((m for m in config.attack_modes if m != "static"), None)
            if adaptive_mode:
                print(f"\n-- H1: static vs {adaptive_mode} (paired by seed, matched budget) --")
                for row in static_vs_adaptive(report.primary_campaigns, adaptive_mode=adaptive_mode):
                    print(f"  {row['scenario_id']:28} {row['defense_id']:16} {row['direction']}")

    excluded = excluded_runs_report(report.campaigns)  # fallbacks included here: audit visibility
    if report.fallback_campaigns:
        print(f"Demonstration-fallback campaigns (excluded from every comparison above): {[c.campaign_id for c in report.fallback_campaigns]}\n")
    if excluded:
        print(f"\n-- {len(excluded)} campaign(s) had invalid/excluded rounds --")
        for e in excluded:
            print(f"  {e['campaign_id']}: {e['attack_rounds_invalid']} invalid, status={e['status']}, errors={e['error_counts']}")

    json_path, csv_path = export(report, Path(args.out_dir))
    print(f"\nFull report:  {json_path}")
    print(f"Comparison CSV: {csv_path}")


if __name__ == "__main__":
    main()
