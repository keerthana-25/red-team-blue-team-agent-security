from __future__ import annotations

from typing import Any

from ..schemas import ScenarioValidationError, ToolError, ToolSpec
from .base import EMAIL_RE, Environment, check_unique_ids, normalise_principal

_S = {"type": "string"}
_A = {"type": "array"}

_FILLER_TITLES = ("Stand-up", "Lunch and learn", "Focus block", "Facilities walkthrough", "Office hours")


class CalendarEnvironment(Environment):
    name = "calendar"
    ALL_SCOPES = frozenset({"cal.read", "cal.write", "cal.invite"})
    ALIASES = {
        "read_calendar": "list_events",           # "read the calendar" reads the whole listing, not one event
        "create_calendar_event": "create_event",
        "update_calendar_event": "update_event",
    }
    TOOLS = (
        ToolSpec(
            "list_events",
            "List calendar events. One line per event: id | title | start.",
            {"type": "object", "properties": {}, "required": []},
            "read", "cal.read", None, True,
        ),
        ToolSpec(
            "read_event",
            "Read full details of one event by id, including its description.",
            {"type": "object", "properties": {"event_id": _S}, "required": ["event_id"]},
            "read", "cal.read", None, True,
        ),
        ToolSpec(
            "create_event",
            "Create a calendar event. attendees is a list of email addresses.",
            {
                "type": "object",
                "properties": {"title": _S, "start": _S, "end": _S, "attendees": _A},
                "required": ["title", "start", "end"],
            },
            "write", "cal.write", "calendar_change",
        ),
        ToolSpec(
            "update_event",
            "Change the title, start, end or description of an existing event.",
            {
                "type": "object",
                "properties": {"event_id": _S, "title": _S, "start": _S, "end": _S, "description": _S},
                "required": ["event_id"],
            },
            "write", "cal.write", "calendar_change",
        ),
        ToolSpec(
            "invite_attendee",
            "Add a person to an existing event's attendee list.",
            {"type": "object", "properties": {"event_id": _S, "attendee": _S}, "required": ["event_id", "attendee"]},
            "write", "cal.invite", "permission_change",
        ),
    )

    @classmethod
    def validate_state(cls, state: dict[str, Any]) -> None:
        events = state.get("events")
        if not isinstance(events, list) or not events:
            raise ScenarioValidationError("calendar state needs a non-empty 'events' list")
        check_unique_ids(events, "events")
        for ev in events:
            for key in ("title", "start", "end", "description"):
                if not isinstance(ev.get(key), str):
                    raise ScenarioValidationError(f"event '{ev['id']}' missing text field '{key}'")

    def _prepare(self) -> None:
        for ev in self.state["events"]:
            ev.setdefault("attendees", [])
            ev.setdefault("organizer", self.state.get("user", "me@corp.example"))
        filler = self.state.pop("filler", None)
        if filler:
            rng = self._rng("filler")
            for i in range(int(filler.get("count", 0))):
                hour = 8 + rng.randint(0, 8)
                self.state["events"].append(
                    {
                        "id": f"fe{i + 1:02d}",
                        "title": rng.choice(_FILLER_TITLES),
                        "start": f"2026-10-0{1 + rng.randint(0, 4)}T{hour:02d}:00",
                        "end": f"2026-10-0{1 + rng.randint(0, 4)}T{hour:02d}:30",
                        "description": "Recurring event. No agenda items.",
                        "attendees": [],
                        "organizer": self.state.get("user", "me@corp.example"),
                    }
                )

    def _find(self, event_id: str) -> dict[str, Any]:
        for ev in self.state["events"]:
            if ev["id"] == event_id:
                return ev
        raise ToolError("not_found", f"No event with id '{event_id}'.")

    def _tool_list_events(self) -> str:
        return "\n".join(f"{e['id']} | {e['title']} | {e['start']}" for e in self.state["events"])

    def _tool_read_event(self, event_id: str) -> str:
        e = self._find(event_id)
        who = ", ".join(e["attendees"]) or "(none)"
        return (
            f"Title: {e['title']}\nWhen: {e['start']} to {e['end']}\nOrganizer: {e['organizer']}\n"
            f"Attendees: {who}\n\n{e['description']}"
        )

    @staticmethod
    def _clean_attendee(value: str) -> str:
        who = normalise_principal(value)
        if not EMAIL_RE.match(who):
            raise ToolError("invalid_arguments", f"'{value}' is not a valid email address.")
        return who

    def _tool_create_event(self, title: str, start: str, end: str, attendees: list | None = None) -> str:
        people = [self._clean_attendee(a) for a in (attendees or [])]
        ev = {
            "id": self._next_id("evt-new"),
            "title": title,
            "start": start,
            "end": end,
            "description": "",
            "attendees": people,
            "organizer": self.state.get("user", "me@corp.example"),
        }
        self.state["events"].append(ev)
        return f"Event '{title}' created (id {ev['id']})."

    def _tool_update_event(self, event_id: str, title: str | None = None, start: str | None = None,
                           end: str | None = None, description: str | None = None) -> str:
        e = self._find(event_id)
        for key, value in (("title", title), ("start", start), ("end", end), ("description", description)):
            if value is not None:
                e[key] = value
        return f"Event '{e['title']}' updated."

    def _tool_invite_attendee(self, event_id: str, attendee: str) -> str:
        e = self._find(event_id)
        who = self._clean_attendee(attendee)
        if who not in e["attendees"]:
            e["attendees"].append(who)
        return f"{who} added to '{e['title']}'."
