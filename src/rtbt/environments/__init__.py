"""Environment registry."""
from __future__ import annotations

from ..schemas import ConfigurationError
from .base import Environment
from .calendar_env import CalendarEnvironment
from .documents_env import DocumentsEnvironment
from .email_env import EmailEnvironment

ENVIRONMENT_CLASSES: dict[str, type[Environment]] = {
    "email": EmailEnvironment,
    "documents": DocumentsEnvironment,
    "calendar": CalendarEnvironment,
}


def environment_class(name: str) -> type[Environment]:
    try:
        return ENVIRONMENT_CLASSES[name]
    except KeyError as exc:
        raise ConfigurationError(f"Unknown environment '{name}'. Known: {sorted(ENVIRONMENT_CLASSES)}") from exc


__all__ = ["Environment", "ENVIRONMENT_CLASSES", "environment_class"]
