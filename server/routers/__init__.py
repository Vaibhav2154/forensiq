"""Router package with lazy submodule exports to isolate workstream imports."""

from __future__ import annotations

import importlib
from typing import Any

_LAZY_SUBMODULES = {"auth", "users", "analysis", "mitre", "monitoring", "knowledge", "investigations"}
_LAZY_ROUTERS = {
    "auth_router": ".auth",
    "users_router": ".users",
    "analysis_router": ".analysis",
    "knowledge_router": ".knowledge",
    "investigations_router": ".investigations",
}

__all__ = [
    "auth_router",
    "users_router",
    "analysis_router",
    "knowledge_router",
    "investigations_router",
]


def __getattr__(name: str) -> Any:
    if name in _LAZY_ROUTERS:
        module = importlib.import_module(_LAZY_ROUTERS[name], __name__)
        return getattr(module, "router")
    if name in _LAZY_SUBMODULES:
        return importlib.import_module(f".{name}", __name__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")