"""Aggregation across repeated, independently-seeded campaigns.

The unit of statistical independence here is a CAMPAIGN (one full seeded run), not a
round within an adaptive campaign — rounds inside one adaptive run are dependent on
each other by construction (the attacker's strategy at round k depends on rounds
1..k-1), so they are never treated as separate samples. This module only ever
aggregates ACROSS campaigns.

Everything is stdlib (``statistics`` + ``random`` for the bootstrap), matching the
project's zero-third-party-dependency policy. The normal-approximation CI is the
default because it is transparent and auditable; call it out as an approximation, and
prefer the bootstrap CI when a metric's distribution is likely skewed (e.g. a rate near
0 or 1 with few campaigns).
"""
from __future__ import annotations

import random
import statistics as pystats
from dataclasses import dataclass
from typing import Any, Callable

from .schemas import eligible_as_research_evidence, evidence_status_for_campaign

Z_95 = 1.959963985

MIN_REPS_FOR_CI = 3  # below this, report descriptive statistics only for the BETWEEN-campaign CI


def wilson_interval(successes: int, n: int, z: float = Z_95) -> tuple[float, float, float]:
    """Wilson score interval for a single binomial proportion. Bounded to [0, 1] by
    construction (unlike the normal approximation). Hand-checkable against any Wilson
    calculator: e.g. wilson_interval(0, 20) ~= (0.0, 0.0, 0.161)."""
    if n == 0:
        return (0.0, 0.0, 0.0)
    phat = successes / n
    denom = 1 + z * z / n
    centre = phat + z * z / (2 * n)
    margin = z * ((phat * (1 - phat) / n) + (z * z / (4 * n * n))) ** 0.5
    lo = max(0.0, (centre - margin) / denom)
    hi = min(1.0, (centre + margin) / denom)
    return phat, lo, hi


@dataclass
class AggregateStat:
    metric: str
    n: int
    values: list[float]
    mean: float | None
    stdev: float | None
    ci_low: float | None
    ci_high: float | None
    ci_method: str
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric": self.metric, "n": self.n, "values": self.values, "mean": self.mean,
            "stdev": self.stdev, "ci_95_low": self.ci_low, "ci_95_high": self.ci_high,
            "ci_method": self.ci_method, "note": self.note,
        }


def _clean(values: list[float | None]) -> list[float]:
    return [v for v in values if v is not None]


def normal_ci(values: list[float]) -> tuple[float, float, float]:
    mean = pystats.fmean(values)
    if len(values) < 2:
        return mean, mean, mean
    sd = pystats.stdev(values)
    margin = Z_95 * sd / (len(values) ** 0.5)
    return mean, mean - margin, mean + margin


def bootstrap_ci(values: list[float], resamples: int = 2000, seed: int = 0) -> tuple[float, float, float]:
    rng = random.Random(seed)
    n = len(values)
    means = []
    for _ in range(resamples):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        means.append(pystats.fmean(sample))
    means.sort()
    lo = means[int(0.025 * resamples)]
    hi = means[int(0.975 * resamples) - 1]
    return pystats.fmean(values), lo, hi


def aggregate(metric_name: str, values: list[float | None], *, method: str = "bootstrap") -> AggregateStat:
    clean = _clean(values)
    n = len(clean)
    if n == 0:
        return AggregateStat(metric_name, 0, [], None, None, None, None, "n/a", "No valid campaigns for this metric.")
    if n < MIN_REPS_FOR_CI:
        mean = pystats.fmean(clean)
        return AggregateStat(
            metric_name, n, clean, mean, None, None, None, "none",
            f"Only {n} independent campaign repetition(s) — reporting the descriptive mean only. "
            f"A between-campaign confidence interval needs at least {MIN_REPS_FOR_CI}. See "
            f"'within_campaign_wilson' on the individual campaign's own metrics for a bounded, "
            f"hand-checkable descriptive interval over that one campaign's observed rounds instead "
            f"(not a substitute for a between-campaign interval, and not meaningful for an adaptive "
            f"attacker whose rounds are correlated by design).",
        )
    sd = pystats.stdev(clean) if n >= 2 else None
    if method == "normal":
        mean, lo, hi = normal_ci(clean)
        note = (f"Normal approximation over {n} independent campaign repetitions. This can overshoot "
                f"[0, 1] for a rate near the edges with few campaigns; prefer 'bootstrap' for rates.")
    else:
        mean, lo, hi = bootstrap_ci(clean)
        note = (f"Percentile bootstrap over {n} independent campaign repetitions (2000 resamples, seeded, "
                f"deterministic). Bounded to the observed range by construction, so a rate's interval can "
                f"never fall outside [0, 1].")
    return AggregateStat(metric_name, n, clean, mean, sd, lo, hi, method, note)


def group_evidence_status(campaigns: list) -> str:
    """A group is measured_result only if EVERY campaign in it is — one simulated campaign in
    the mix is enough to keep the whole aggregate from being called research evidence."""
    statuses = {evidence_status_for_campaign(c) for c in campaigns}
    return "measured_result" if statuses == {"measured_result"} else "simulated_result"


def group_campaigns(campaigns: list, key: Callable[[Any], tuple]) -> dict[tuple, list]:
    groups: dict[tuple, list] = {}
    for c in campaigns:
        groups.setdefault(key(c), []).append(c)
    return groups


def comparison_by_scenario_defense(campaigns: list, metric: str = "campaign_average_asr") -> list[dict[str, Any]]:
    """One row per (scenario, attack_mode, defense), aggregated across seeds."""
    groups = group_campaigns(campaigns, lambda c: (c.scenario_id, c.attack_mode, c.defense_id))
    rows = []
    for (scenario_id, attack_mode, defense_id), group in sorted(groups.items()):
        values = [c.metrics().get(metric) for c in group]
        stat = aggregate(metric, values)
        status = group_evidence_status(group)
        rows.append({"scenario_id": scenario_id, "attack_mode": attack_mode, "defense_id": defense_id,
                    "evidence_status": status, "eligible_as_research_evidence": eligible_as_research_evidence(status),
                    **stat.to_dict()})
    return rows


def comparison_by_environment(campaigns: list, metric: str = "campaign_average_asr") -> list[dict[str, Any]]:
    groups = group_campaigns(campaigns, lambda c: (c.environment, c.attack_mode, c.defense_id))
    rows = []
    for (environment, attack_mode, defense_id), group in sorted(groups.items()):
        values = [c.metrics().get(metric) for c in group]
        stat = aggregate(metric, values)
        rows.append({"environment": environment, "attack_mode": attack_mode, "defense_id": defense_id,
                    **stat.to_dict()})
    return rows


def static_vs_adaptive(
    campaigns: list, *, adaptive_mode: str = "adaptive_demo", static_mode: str = "static",
    metric: str = "campaign_average_asr",
) -> list[dict[str, Any]]:
    """H1: paired comparison at matched budget. Pairing key is (scenario_id, defense_id,
    seed) — the seed is what makes this a fair paired comparison rather than two
    unrelated samples."""
    by_key: dict[tuple, dict[str, float | None]] = {}
    for c in campaigns:
        if c.attack_mode not in (adaptive_mode, static_mode):
            continue
        key = (c.scenario_id, c.defense_id, c.seed)
        by_key.setdefault(key, {})[c.attack_mode] = c.metrics().get(metric)

    per_defense: dict[tuple[str, str], list[float]] = {}
    for (scenario_id, defense_id, _seed), pair in by_key.items():
        if adaptive_mode in pair and static_mode in pair and pair[adaptive_mode] is not None and pair[static_mode] is not None:
            per_defense.setdefault((scenario_id, defense_id), []).append(pair[adaptive_mode] - pair[static_mode])

    per_defense_group: dict[tuple[str, str], list] = {}
    for c in campaigns:
        if c.attack_mode in (adaptive_mode, static_mode):
            per_defense_group.setdefault((c.scenario_id, c.defense_id), []).append(c)

    rows = []
    for (scenario_id, defense_id), diffs in sorted(per_defense.items()):
        stat = aggregate(f"{metric}_diff({adaptive_mode}-{static_mode})", diffs, method="bootstrap")  # paired: diffs are already paired by seed
        direction = "null_or_undetermined"
        if stat.ci_low is not None and stat.ci_high is not None:
            if stat.ci_low > 0:
                direction = "adaptive_higher"
            elif stat.ci_high < 0:
                direction = "static_higher"
        elif stat.mean is not None:
            direction = "descriptive_only"
        status = group_evidence_status(per_defense_group.get((scenario_id, defense_id), []))
        rows.append({"scenario_id": scenario_id, "defense_id": defense_id, "direction": direction,
                     "evidence_status": status, "eligible_as_research_evidence": eligible_as_research_evidence(status),
                     **stat.to_dict()})
    return rows


def excluded_runs_report(campaigns: list) -> list[dict[str, Any]]:
    rows = []
    for c in campaigns:
        m = c.metrics()
        if m["attack_rounds_invalid"] or c.status != "complete":
            rows.append({
                "campaign_id": c.campaign_id, "status": c.status,
                "attack_rounds_invalid": m["attack_rounds_invalid"], "error_counts": m["error_counts"],
            })
    return rows


SUMMARY_METRICS = (
    "campaign_average_asr", "final_window_asr", "legitimate_task_completion_rate",
    "safe_utility_rate", "benign_block_rate",
    "unauthorized_action_attempted_rate", "unauthorized_action_blocked_rate", "unauthorized_action_executed_rate",
)


def summarize(campaigns: list, metrics: tuple[str, ...] = SUMMARY_METRICS) -> dict[str, Any]:
    """Every metric aggregated across independent campaigns, per scenario and pooled.

    The pooled rows treat every (scenario, seed) campaign as one observation, so their
    intervals reflect scenario-to-scenario spread as well as run-to-run noise. Per-scenario
    rows isolate run-to-run noise (seeds only). Both are labeled in the dashboard."""
    def block(group: list) -> dict[str, Any]:
        return {m: aggregate(m, [c.metrics().get(m) for c in group]).to_dict() for m in metrics}

    per_scenario = [
        {"scenario_id": sid, "attack_mode": mode, "defense_id": did, "evidence_status": group_evidence_status(group),
         "eligible_as_research_evidence": eligible_as_research_evidence(group_evidence_status(group)), "stats": block(group)}
        for (sid, mode, did), group in sorted(group_campaigns(campaigns, lambda c: (c.scenario_id, c.attack_mode, c.defense_id)).items())
    ]
    pooled = [
        {"attack_mode": mode, "defense_id": did, "evidence_status": group_evidence_status(group),
         "eligible_as_research_evidence": eligible_as_research_evidence(group_evidence_status(group)), "stats": block(group)}
        for (mode, did), group in sorted(group_campaigns(campaigns, lambda c: (c.attack_mode, c.defense_id)).items())
    ]
    return {"metrics": list(metrics), "per_scenario": per_scenario, "pooled": pooled}
