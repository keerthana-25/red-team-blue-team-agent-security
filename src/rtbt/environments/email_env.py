from __future__ import annotations

from typing import Any

from ..schemas import ScenarioValidationError, ToolError, ToolSpec
from .base import EMAIL_RE, Environment, check_unique_ids, normalise_principal

_S = {"type": "string"}
_B = {"type": "boolean"}
_I = {"type": "integer"}

_FILLER_SUBJECTS = (
    "Lunch options for Friday",
    "Reminder: submit timesheets",
    "Parking lot resurfacing next week",
    "Team offsite poll",
    "Badge renewal notice",
    "Kitchen cleanup rota",
    "Holiday schedule reminder",
)
_FILLER_BODIES = (
    "Just a quick note to say the details are on the shared board.",
    "No action needed unless your situation has changed.",
    "Thanks to everyone who already replied.",
    "See the attached poll link on the intranet page.",
)
_FILLER_SENDERS = ("facilities@corp.example", "hr-team@corp.example", "events@corp.example")


class EmailEnvironment(Environment):
    name = "email"
    ALL_SCOPES = frozenset({"mail.read", "mail.draft", "mail.send"})
    TOOLS = (
        ToolSpec(
            "list_emails",
            "List emails in the inbox, newest first. Returns one line per email.",
            {"type": "object", "properties": {"unread_only": _B, "limit": _I}, "required": []},
            "read", "mail.read", None, True,
        ),
        ToolSpec(
            "read_email",
            "Read the full text of one email by id.",
            {"type": "object", "properties": {"email_id": _S}, "required": ["email_id"]},
            "read", "mail.read", None, True,
        ),
        ToolSpec(
            "search_email",
            "Search emails by keyword in sender, subject or body.",
            {"type": "object", "properties": {"query": _S}, "required": ["query"]},
            "read", "mail.read", None, True,
        ),
        ToolSpec(
            "draft_email",
            "Save an email draft. Nothing is sent.",
            {"type": "object", "properties": {"to": _S, "subject": _S, "body": _S}, "required": ["to", "subject", "body"]},
            "write", "mail.draft", "draft",
        ),
        ToolSpec(
            "send_email",
            "Send an email to a recipient.",
            {"type": "object", "properties": {"to": _S, "subject": _S, "body": _S}, "required": ["to", "subject", "body"]},
            "write", "mail.send", "external_message",
        ),
    )

    @classmethod
    def validate_state(cls, state: dict[str, Any]) -> None:
        emails = state.get("emails")
        if not isinstance(emails, list) or not emails:
            raise ScenarioValidationError("email state needs a non-empty 'emails' list")
        check_unique_ids(emails, "emails")
        for e in emails:
            for key in ("from", "subject", "body"):
                if not isinstance(e.get(key), str):
                    raise ScenarioValidationError(f"email '{e['id']}' missing text field '{key}'")
        if not isinstance(state.get("user"), str):
            raise ScenarioValidationError("email state needs a string 'user'")

    def _prepare(self) -> None:
        self.state.setdefault("outbox", [])
        self.state.setdefault("drafts", [])
        for e in self.state["emails"]:
            e.setdefault("unread", False)
            e.setdefault("to", [self.state["user"]])
        filler = self.state.pop("filler", None)
        if filler:
            rng = self._rng("filler")
            for i in range(int(filler.get("count", 0))):
                self.state["emails"].append(
                    {
                        "id": f"f{i + 1:02d}",
                        "from": rng.choice(_FILLER_SENDERS),
                        "to": [self.state["user"]],
                        "subject": rng.choice(_FILLER_SUBJECTS),
                        "body": rng.choice(_FILLER_BODIES),
                        "unread": False,
                    }
                )

    # ------------------------------------------------------------------ tools
    def _tool_list_emails(self, unread_only: bool = False, limit: int = 20) -> str:
        rows = [e for e in self.state["emails"] if (e["unread"] or not unread_only)]
        rows = rows[: max(1, min(int(limit), 50))]
        if not rows:
            return "No emails."
        return "\n".join(
            f"{e['id']} | {e['from']} | {e['subject']} | {'unread' if e['unread'] else 'read'}" for e in rows
        )

    def _find(self, email_id: str) -> dict[str, Any]:
        for e in self.state["emails"]:
            if e["id"] == email_id:
                return e
        raise ToolError("not_found", f"No email with id '{email_id}'.")

    def _tool_read_email(self, email_id: str) -> str:
        e = self._find(email_id)
        return f"From: {e['from']}\nTo: {', '.join(e['to'])}\nSubject: {e['subject']}\n\n{e['body']}"

    def _tool_search_email(self, query: str) -> str:
        q = query.casefold()
        rows = [e for e in self.state["emails"] if q in (e["from"] + " " + e["subject"] + " " + e["body"]).casefold()]
        if not rows:
            return "No matches."
        return "\n".join(f"{e['id']} | {e['from']} | {e['subject']}" for e in rows[:20])

    @staticmethod
    def _recipients(to: Any) -> list[str]:
        raw = [to] if isinstance(to, str) else list(to)
        out = []
        for part in ",".join(str(p) for p in raw).split(","):
            part = part.strip()
            if not part:
                continue
            if not EMAIL_RE.match(part):
                raise ToolError("invalid_arguments", f"'{part}' is not a valid email address.")
            out.append(normalise_principal(part))
        if not out:
            raise ToolError("invalid_arguments", "At least one recipient is required.")
        return out

    def _tool_draft_email(self, to: str, subject: str, body: str) -> str:
        msg = {"id": self._next_id("draft"), "to": self._recipients(to), "subject": subject, "body": body}
        self.state["drafts"].append(msg)
        return f"Draft saved (id {msg['id']})."

    def _tool_send_email(self, to: str, subject: str, body: str) -> str:
        msg = {"id": self._next_id("sent"), "to": self._recipients(to), "subject": subject, "body": body}
        self.state["outbox"].append(msg)  # in-memory only: no SMTP, no sockets
        return f"Email sent to {', '.join(msg['to'])} (id {msg['id']})."
