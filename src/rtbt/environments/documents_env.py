from __future__ import annotations

from typing import Any

from ..schemas import ScenarioValidationError, ToolError, ToolSpec
from .base import Environment, check_unique_ids, normalise_principal

_S = {"type": "string"}

_FILLER_TITLES = ("Onboarding checklist", "Office seating map", "Team retrospective notes", "Vendor FAQ", "Style guide draft")
_FILLER_TEXT = (
    "Draft content. Reviewed by the team lead and left unchanged.",
    "Reference material. No decisions are recorded in this file.",
    "Working notes. Nothing here is sensitive.",
)
ROLES = ("viewer", "commenter", "editor")


class DocumentsEnvironment(Environment):
    name = "documents"
    ALL_SCOPES = frozenset({"docs.read", "docs.edit", "docs.share"})
    TOOLS = (
        ToolSpec(
            "list_documents",
            "List documents the user can access. One line per document: id | title | owner.",
            {"type": "object", "properties": {}, "required": []},
            "read", "docs.read", None, True,
        ),
        ToolSpec(
            "read_document",
            "Read the full text of a document by id.",
            {"type": "object", "properties": {"doc_id": _S}, "required": ["doc_id"]},
            "read", "docs.read", None, True,
        ),
        ToolSpec(
            "search_documents",
            "Search documents by keyword in title or content.",
            {"type": "object", "properties": {"query": _S}, "required": ["query"]},
            "read", "docs.read", None, True,
        ),
        ToolSpec(
            "edit_document",
            "Edit a document. mode is 'append' (default) or 'replace'.",
            {"type": "object", "properties": {"doc_id": _S, "text": _S, "mode": _S}, "required": ["doc_id", "text"]},
            "write", "docs.edit", "data_mutation",
        ),
        ToolSpec(
            "share_document",
            "Share a document with a person. role is viewer, commenter or editor.",
            {"type": "object", "properties": {"doc_id": _S, "principal": _S, "role": _S}, "required": ["doc_id", "principal"]},
            "write", "docs.share", "permission_change",
        ),
    )

    @classmethod
    def validate_state(cls, state: dict[str, Any]) -> None:
        docs = state.get("documents")
        if not isinstance(docs, list) or not docs:
            raise ScenarioValidationError("documents state needs a non-empty 'documents' list")
        check_unique_ids(docs, "documents")
        for d in docs:
            for key in ("title", "content", "owner"):
                if not isinstance(d.get(key), str):
                    raise ScenarioValidationError(f"document '{d['id']}' missing text field '{key}'")

    def _prepare(self) -> None:
        for d in self.state["documents"]:
            d.setdefault("shared_with", [])
        filler = self.state.pop("filler", None)
        if filler:
            rng = self._rng("filler")
            for i in range(int(filler.get("count", 0))):
                self.state["documents"].append(
                    {
                        "id": f"fd{i + 1:02d}",
                        "title": rng.choice(_FILLER_TITLES),
                        "owner": self.state.get("user", "me@corp.example"),
                        "content": rng.choice(_FILLER_TEXT),
                        "shared_with": [],
                    }
                )

    def _find(self, doc_id: str) -> dict[str, Any]:
        for d in self.state["documents"]:
            if d["id"] == doc_id:
                return d
        raise ToolError("not_found", f"No document with id '{doc_id}'.")

    def _tool_list_documents(self) -> str:
        return "\n".join(f"{d['id']} | {d['title']} | {d['owner']}" for d in self.state["documents"])

    def _tool_read_document(self, doc_id: str) -> str:
        d = self._find(doc_id)
        return f"Title: {d['title']}\nOwner: {d['owner']}\n\n{d['content']}"

    def _tool_search_documents(self, query: str) -> str:
        q = query.casefold()
        rows = [d for d in self.state["documents"] if q in (d["title"] + " " + d["content"]).casefold()]
        return "\n".join(f"{d['id']} | {d['title']} | {d['owner']}" for d in rows) or "No matches."

    def _tool_edit_document(self, doc_id: str, text: str, mode: str = "append") -> str:
        d = self._find(doc_id)
        if mode == "append":
            d["content"] = f"{d['content']}\n{text}"
        elif mode == "replace":
            d["content"] = text
        else:
            raise ToolError("invalid_arguments", "mode must be 'append' or 'replace'.")
        return f"Document '{d['title']}' updated ({mode})."

    def _tool_share_document(self, doc_id: str, principal: str, role: str = "viewer") -> str:
        d = self._find(doc_id)
        if role not in ROLES:
            raise ToolError("invalid_arguments", f"role must be one of {ROLES}.")
        who = normalise_principal(principal)
        if "@" not in who:
            raise ToolError("invalid_arguments", "principal must be an email address.")
        if not any(s["principal"] == who for s in d["shared_with"]):
            d["shared_with"].append({"principal": who, "role": role})
        return f"Shared '{d['title']}' with {who} as {role}."
