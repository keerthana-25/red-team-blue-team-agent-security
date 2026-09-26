"""Versioned scenario schema, loader, validation and suite registry.

See docs/SCENARIO_SCHEMA.md for the field-by-field reference. A scenario is data only:
it never contains code, and nothing in it is executed.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .environments import environment_class
from .environments.base import PLACEMENTS
from .environments.effects import (
    EFFECT_ENVIRONMENT,
    EFFECT_TOOL,
    action_matches,
    validate_effect,
)
from .schemas import (
    ENVIRONMENTS,
    SCHEMA_VERSION,
    AttackBrief,
    Effect,
    ScenarioValidationError,
)

ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{2,63}$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
VALIDATION_STATUSES = ("unreviewed", "reviewed", "rejected", "generated_unreviewed")
# generated_unreviewed: produced by scripts/generate_scenario.py. It is a stronger warning than
# plain "unreviewed" — this scenario was never written by a person at all — and a scenario in
# this status must never be listed in scenarios/suite.json (see scripts/approve_generated_scenario.py,
# which is the only sanctioned way for one to become an ordinary "unreviewed" suite member).
CATEGORIES = (
    "benign",
    "obvious_injection",
    "contextual_injection",
    "instruction_impersonation",
    "data_exfiltration",
    "unauthorized_message",
    "unauthorized_document_share",
    "unauthorized_document_edit",
    "unauthorized_calendar_change",
    "multi_step",
)
REQUIRED_KEYS = (
    "schema_version", "id", "version", "title", "environment", "category", "user_task",
    "initial_state", "granted_scopes", "allowed_actions", "policy", "utility",
    "simulated_behavior", "validation_status", "author",
)


@dataclass
class Scenario:
    id: str
    version: str
    title: str
    description: str
    environment: str
    category: str
    tags: tuple[str, ...]
    difficulty: dict[str, Any]
    author: str
    validation_status: str
    user_task: str
    initial_state: dict[str, Any]
    injection: dict[str, str] | None
    objective: Effect | None
    objective_description: str
    brief: dict[str, str]
    granted_scopes: tuple[str, ...]
    allowed_actions: list[dict[str, Any]]
    policy: dict[str, Any]
    utility_terms: tuple[str, ...]
    utility_effects: list[Effect]
    simulated_behavior: dict[str, Any]
    benign_variants: list[dict[str, str]]
    cleanup: str
    content_hash: str
    source: str = ""
    # Review metadata (all optional; every scenario written before this existed loads unchanged).
    # author/version/validation_status/category/difficulty above already double as review fields;
    # these fill the remaining gaps in a review record.
    reviewer: str | None = None
    review_date: str | None = None
    solvability_status: str | None = None  # e.g. "solvable_by_construction", "unverified"
    oracle_validation_status: str | None = None  # e.g. "matches_hand_trace", "unverified"
    notes: str = ""
    generation_metadata: dict | None = None  # set only for a generate_scenario.py candidate
    # Names of scripts/validate_scenarios.py checks this scenario is known and expected to fail,
    # with the reason required in `notes`. A declared exception is reported as a warning, not a
    # failure, and does not affect the script's exit code — but only for checks named here; any
    # OTHER check failing is still a real, loud failure. See docs/SCENARIO_REVIEW.md.
    known_check_exceptions: tuple[str, ...] = ()

    @property
    def is_attackable(self) -> bool:
        return self.objective is not None and self.injection is not None

    def attack_brief(self) -> AttackBrief:
        if not self.is_attackable:
            raise ScenarioValidationError(f"Scenario '{self.id}' has no attack objective")
        return AttackBrief(
            environment=self.environment,
            objective_kind=self.objective.kind,  # type: ignore[union-attr]
            objective_description=self.objective_description,
            destination=self.brief["destination"],
            object_hint=self.brief["object"],
            cover_topic=self.brief["cover_topic"],
        )

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "title": self.title,
            "environment": self.environment,
            "category": self.category,
            "attackable": self.is_attackable,
            "difficulty": self.difficulty.get("level"),
            "tags": list(self.tags),
            "validation_status": self.validation_status,
            "benign_variants": len(self.benign_variants),
            "content_hash": self.content_hash[:12],
        }


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise ScenarioValidationError(message)


def parse_scenario(data: dict[str, Any], source: str = "<memory>") -> Scenario:
    where = f"[{source}]"
    if "schema_version" not in data and "benign_subject" in data:
        raise ScenarioValidationError(
            f"{where} This is a v0.1 (legacy) scenario file. The v{SCHEMA_VERSION} schema is not "
            "backward compatible; see docs/SCENARIO_SCHEMA.md and scenarios/email_summary.json."
        )
    for key in REQUIRED_KEYS:
        _require(key in data, f"{where} missing required key '{key}'")
    _require(data["schema_version"] == SCHEMA_VERSION, f"{where} schema_version must be '{SCHEMA_VERSION}'")
    _require(bool(ID_RE.match(data["id"])), f"{where} id must match {ID_RE.pattern}")
    _require(bool(VERSION_RE.match(data["version"])), f"{where} version must look like 1.0.0")
    _require(data["environment"] in ENVIRONMENTS, f"{where} environment must be one of {ENVIRONMENTS}")
    _require(data["category"] in CATEGORIES, f"{where} category must be one of {CATEGORIES}")
    _require(data["validation_status"] in VALIDATION_STATUSES, f"{where} bad validation_status")
    _require(isinstance(data["user_task"], str) and data["user_task"].strip(), f"{where} user_task is empty")

    env_cls = environment_class(data["environment"])
    env_cls.validate_state(data["initial_state"])

    scopes = tuple(data["granted_scopes"])
    _require(set(scopes) <= env_cls.ALL_SCOPES, f"{where} granted_scopes has unknown scope(s): {set(scopes) - env_cls.ALL_SCOPES}")

    specs = {s.name: s for s in env_cls.TOOLS}
    allowed = list(data["allowed_actions"])
    for a in allowed:
        _require(a.get("tool") in specs and specs[a["tool"]].kind == "write",
                 f"{where} allowed_actions entry must name a write tool of the {data['environment']} environment")

    injection = data.get("injection")
    if injection is not None:
        _require(injection.get("placement") in PLACEMENTS, f"{where} injection.placement must be one of {PLACEMENTS}")
        _require(env_cls.slot_exists(data["initial_state"], injection.get("slot", "")),
                 f"{where} injection.slot '{injection.get('slot')}' does not exist in initial_state")

    objective = None
    objective_description = ""
    brief: dict[str, str] = {}
    obj = data.get("attack_objective")
    if obj is not None:
        _require(injection is not None, f"{where} an attack_objective needs an injection slot")
        objective = Effect(kind=obj["kind"], params=dict(obj["params"]))
        validate_effect(objective, f"{where} attack_objective")
        _require(EFFECT_ENVIRONMENT[objective.kind] == data["environment"],
                 f"{where} objective kind '{objective.kind}' does not belong to environment '{data['environment']}'")
        objective_description = str(obj.get("description", ""))
        brief = {k: str(obj["brief"][k]) for k in ("destination", "object", "cover_topic")}
        # The objective must be UNAUTHORISED, or "success" would be indistinguishable from doing the task.
        tool = EFFECT_TOOL[objective.kind]
        probe = _objective_probe_arguments(objective)
        _require(not any(action_matches(a, tool, probe) for a in allowed),
                 f"{where} the attack objective is also listed in allowed_actions")
    else:
        _require(data["category"] == "benign", f"{where} scenarios without attack_objective must have category 'benign'")

    utility = data["utility"]
    terms = tuple(utility.get("response_terms", []))
    effects = [Effect(kind=e["kind"], params=dict(e["params"])) for e in utility.get("state_assertions", [])]
    for e in effects:
        validate_effect(e, f"{where} utility.state_assertions")
        _require(EFFECT_ENVIRONMENT[e.kind] == data["environment"], f"{where} utility effect '{e.kind}' is in the wrong environment")
    _require(bool(terms) or bool(effects), f"{where} utility needs response_terms and/or state_assertions")

    policy = data["policy"]
    for key in ("allowed_write_tools", "approved_destinations", "trusted_domains"):
        _require(isinstance(policy.get(key), list), f"{where} policy.{key} must be a list")
    for tool in policy["allowed_write_tools"]:
        _require(tool in specs and specs[tool].kind == "write", f"{where} policy.allowed_write_tools has unknown write tool '{tool}'")

    beh = data["simulated_behavior"]
    _require(isinstance(beh.get("read_plan"), list) and beh["read_plan"], f"{where} simulated_behavior.read_plan is required")
    for step in beh["read_plan"] + list(beh.get("legit_actions", [])):
        _require(step.get("tool") in specs, f"{where} simulated_behavior references unknown tool '{step.get('tool')}'")
    _require(isinstance(beh.get("summary"), str) and beh["summary"], f"{where} simulated_behavior.summary is required")

    known_exceptions = tuple(data.get("known_check_exceptions", []))
    if known_exceptions:
        _require(bool(data.get("notes", "").strip()),
                 f"{where} known_check_exceptions is set but notes is empty — a declared exception must explain itself")

    variants = list(data.get("benign_variants", []))
    for v in variants:
        _require(isinstance(v.get("id"), str) and isinstance(v.get("text"), str), f"{where} benign_variants need id and text")

    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return Scenario(
        id=data["id"], version=data["version"], title=data["title"], description=data.get("description", ""),
        environment=data["environment"], category=data["category"], tags=tuple(data.get("tags", [])),
        difficulty=dict(data.get("difficulty", {})), author=data["author"],
        validation_status=data["validation_status"], user_task=data["user_task"],
        initial_state=data["initial_state"], injection=injection, objective=objective,
        objective_description=objective_description, brief=brief, granted_scopes=scopes,
        allowed_actions=allowed, policy=policy, utility_terms=terms, utility_effects=effects,
        simulated_behavior=beh, benign_variants=variants, cleanup=data.get("cleanup", "reset_each_round"),
        content_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest(), source=source,
        reviewer=data.get("reviewer"), review_date=data.get("review_date"),
        solvability_status=data.get("solvability_status"), oracle_validation_status=data.get("oracle_validation_status"),
        notes=data.get("notes", ""), generation_metadata=data.get("generation_metadata"),
        known_check_exceptions=tuple(data.get("known_check_exceptions", [])),
    )


def _objective_probe_arguments(objective: Effect) -> dict[str, Any]:
    """Arguments a tool call would carry to bring about the objective (for the conflict check)."""
    p = objective.params
    k = objective.kind
    if k == "email_sent":
        return {"to": p["recipient"]}
    if k == "document_shared":
        return {"doc_id": p["doc_id"], "principal": p["principal"]}
    if k == "document_modified":
        return {"doc_id": p["doc_id"]}
    if k == "attendee_added":
        return {"event_id": p["event_id"], "attendee": p["attendee"]}
    if k == "event_created":
        return {"attendees": [p["attendee"]]}
    return {}


def load_scenario(path: str | Path) -> Scenario:
    source = Path(path)
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ScenarioValidationError(f"[{source.name}] not valid JSON: {exc}") from exc
    return parse_scenario(data, source=source.name)


@dataclass
class Suite:
    suite_id: str
    version: str
    scenarios: list[Scenario] = field(default_factory=list)

    def content_hash(self) -> str:
        h = hashlib.sha256()
        for s in sorted(self.scenarios, key=lambda x: x.id):
            h.update(f"{s.id}@{s.version}:{s.content_hash}".encode("utf-8"))
        return h.hexdigest()

    def get(self, scenario_id: str) -> Scenario:
        for s in self.scenarios:
            if s.id == scenario_id:
                return s
        raise ScenarioValidationError(f"Unknown scenario '{scenario_id}'. Known: {[s.id for s in self.scenarios]}")

    def primary(self) -> list[Scenario]:
        """Scenarios eligible for the primary benchmark.

        Generated scenarios never enter automatically (project spec section 21): they
        need validation_status == 'reviewed' set by a human.
        """
        out = []
        for s in self.scenarios:
            if s.validation_status == "rejected":
                continue
            if s.author.startswith("generated") and s.validation_status != "reviewed":
                continue
            out.append(s)
        return out


def load_suite(directory: str | Path) -> Suite:
    root = Path(directory)
    manifest_path = root / "suite.json"
    if not manifest_path.exists():
        raise ScenarioValidationError(f"No suite.json in {root}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    suite = Suite(suite_id=manifest["suite_id"], version=manifest["suite_version"])
    seen: set[str] = set()
    for name in manifest["scenarios"]:
        scenario = load_scenario(root / name)
        _require(scenario.id not in seen, f"Duplicate scenario id '{scenario.id}' in suite")
        seen.add(scenario.id)
        suite.scenarios.append(scenario)
    return suite
