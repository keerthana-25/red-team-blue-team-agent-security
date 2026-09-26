from __future__ import annotations

from ..schemas import ConfigurationError
from .adaptive_demo import AdaptiveDemoAttacker
from .base import Attacker
from .local_model import LocalModelAttacker, ModelConfig
from .static_attacker import StaticAttackSet


def make_attacker(mode: str, seed: int, *, model_config: ModelConfig | None = None,
                   allowlist: tuple[str, ...] | None = None) -> Attacker:
    if mode == "static":
        return StaticAttackSet(seed=seed)
    if mode == "adaptive_demo":
        return AdaptiveDemoAttacker(seed=seed)
    if mode == "adaptive_ollama":
        if model_config is None:
            raise ConfigurationError("adaptive_ollama requires a model_config")
        return LocalModelAttacker(config=model_config, seed=seed, allowlist=allowlist)
    raise ConfigurationError(f"Unknown attack mode '{mode}'. Use static, adaptive_demo or adaptive_ollama.")


__all__ = ["Attacker", "StaticAttackSet", "AdaptiveDemoAttacker", "LocalModelAttacker", "ModelConfig", "make_attacker"]
