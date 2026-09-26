"""Sandboxed synthetic environments.

Safety property (enforced by tests): nothing under ``rtbt/environments`` imports a
networking, subprocess, or filesystem-writing module. Every "side effect" is an
in-memory list append, so there is no real email, share, or calendar action to leak.
"""
from __future__ import annotations

import copy
import hashlib
import json
import random
import re
from abc import ABC, abstractmethod
from typing import Any

from ..schemas import ScenarioValidationError, ToolError, ToolSpec

EMAIL_RE = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")

PLACEMENTS = ("append", "prepend", "html_comment", "signature_footer")


def normalise_principal(value: str) -> str:
    return str(value).strip().casefold()


def apply_placement(original: str, payload: str, placement: str) -> str:
    if placement == "append":
        return f"{original}\n\n{payload}"
    if placement == "prepend":
        return f"{payload}\n\n{original}"
    if placement == "html_comment":
        return f"{original}\n\n<!-- {payload} -->"
    if placement == "signature_footer":
        return f"{original}\n\n-- \nSent from a shared mailbox\n{payload}"
    raise ScenarioValidationError(f"Unknown placement '{placement}'. Use one of {PLACEMENTS}.")


_JSON_TYPES = {
    "string": str,
    "integer": int,
    "boolean": bool,
    "array": (list, tuple),
    "object": dict,
}


class Environment(ABC):
    name: str = ""
    COLLECTIONS: dict[str, str] = {}  # slot collection -> injectable text field default
    TOOLS: tuple[ToolSpec, ...] = ()
    ALL_SCOPES: frozenset[str] = frozenset()
    # Alternate name -> canonical TOOLS name. An alias resolves to the exact same ToolSpec object
    # (same permission check, same policy validation, same logging, same handler) — never a second
    # implementation. Aliases do not appear in specs() (what the agent is shown); they are only
    # for a caller who already knows the alternate name to still reach the one real tool.
    ALIASES: dict[str, str] = {}

    def __init__(self, initial_state: dict[str, Any], granted_scopes: set[str] | frozenset[str], seed: int = 0):
        self.state: dict[str, Any] = copy.deepcopy(initial_state)
        self.granted_scopes = frozenset(granted_scopes)
        self.seed = int(seed)
        self._counter = 0
        self._specs = {spec.name: spec for spec in self.TOOLS}
        for alias, canonical in self.ALIASES.items():
            self._specs[alias] = self._specs[canonical]  # same object: same everything
        self._prepare()

    # ------------------------------------------------------------------ construction
    @classmethod
    @abstractmethod
    def validate_state(cls, state: dict[str, Any]) -> None:
        """Raise ScenarioValidationError when the initial state is malformed."""

    def _prepare(self) -> None:
        """Hook: add seeded filler content and initialise write buffers."""

    def _rng(self, salt: str) -> random.Random:
        return random.Random(f"{self.name}:{self.seed}:{salt}")

    # ------------------------------------------------------------------ introspection
    def specs(self) -> list[ToolSpec]:
        """Tools the agent can see: only those whose scope was granted."""
        return [s for s in self.TOOLS if s.scope in self.granted_scopes]

    def spec(self, name: str) -> ToolSpec | None:
        return self._specs.get(name)

    def snapshot(self) -> dict[str, Any]:
        return copy.deepcopy(self.state)

    def state_hash(self) -> str:
        return hashlib.sha256(json.dumps(self.state, sort_keys=True).encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------ injection
    def inject(self, slot: str, payload: str, placement: str) -> None:
        """Place attacker-controlled text into a content field named by ``slot``.

        Slot grammar: ``<collection>.<item id>.<field>``, e.g. ``emails.e1.body``.
        """
        parts = slot.split(".")
        if len(parts) != 3:
            raise ScenarioValidationError(f"Bad injection slot '{slot}'; expected collection.id.field")
        collection, item_id, field_name = parts
        items = self.state.get(collection)
        if not isinstance(items, list):
            raise ScenarioValidationError(f"Slot '{slot}': no collection '{collection}' in {self.name} state")
        for item in items:
            if item.get("id") == item_id:
                if not isinstance(item.get(field_name), str):
                    raise ScenarioValidationError(f"Slot '{slot}': field '{field_name}' is not text")
                item[field_name] = apply_placement(item[field_name], payload, placement)
                return
        raise ScenarioValidationError(f"Slot '{slot}': no item with id '{item_id}'")

    @classmethod
    def slot_exists(cls, state: dict[str, Any], slot: str) -> bool:
        parts = slot.split(".")
        if len(parts) != 3:
            return False
        items = state.get(parts[0])
        if not isinstance(items, list):
            return False
        return any(i.get("id") == parts[1] and isinstance(i.get(parts[2]), str) for i in items)

    # ------------------------------------------------------------------ execution
    def call(self, name: str, arguments: Any) -> str:
        spec = self._specs.get(name)
        if spec is None:
            raise ToolError("unknown_tool", f"Unknown tool '{name}'.")
        if spec.scope not in self.granted_scopes:
            raise ToolError("permission_denied", f"Tool '{name}' requires scope '{spec.scope}', which is not granted.")
        if not isinstance(arguments, dict):
            raise ToolError("invalid_arguments", "Tool arguments must be a JSON object.")
        self._validate_arguments(spec, arguments)
        handler = getattr(self, f"_tool_{spec.name}")  # spec.name is the canonical name even when `name` was an alias
        return handler(**arguments)

    def _validate_arguments(self, spec: ToolSpec, arguments: dict[str, Any]) -> None:
        props = spec.parameters.get("properties", {})
        for required in spec.parameters.get("required", []):
            if required not in arguments:
                raise ToolError("invalid_arguments", f"Missing required argument '{required}'.")
        for key, value in arguments.items():
            if key not in props:
                raise ToolError("invalid_arguments", f"Unexpected argument '{key}'.")
            declared = props[key].get("type")
            expected = _JSON_TYPES.get(declared)
            if expected is None:
                continue
            # bool is a subclass of int in Python; keep the JSON distinction.
            if declared == "integer" and isinstance(value, bool):
                raise ToolError("invalid_arguments", f"Argument '{key}' must be an integer.")
            if not isinstance(value, expected):
                raise ToolError("invalid_arguments", f"Argument '{key}' must be of type {declared}.")

    def _next_id(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}-{self._counter:04d}"


def check_unique_ids(items: list[dict[str, Any]], label: str) -> None:
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ScenarioValidationError(f"{label}: every item needs a string 'id'")
        if item["id"] in seen:
            raise ScenarioValidationError(f"{label}: duplicate id '{item['id']}'")
        seen.add(item["id"])
