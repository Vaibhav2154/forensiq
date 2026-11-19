"""Service package with lazy exports so workstream subpackages stay isolated."""

from __future__ import annotations

import importlib
from typing import Any

_EXPORTS: dict[str, tuple[str, str]] = {
    "GeminiService": (".gemini_service", "GeminiService"),
    "EncryptionService": (".encryption_service", "EncryptionService"),
    "AnalysisStorageService": (".analysis_storage_service", "AnalysisStorageService"),
    "analysis_storage_service": (".analysis_storage_service", "analysis_storage_service"),
}

__all__ = [
    "GeminiService",
    "EncryptionService",
    "AnalysisStorageService",
    "analysis_storage_service",
]


def __getattr__(name: str) -> Any:
    if name in _EXPORTS:
        mod_path, attr = _EXPORTS[name]
        module = importlib.import_module(mod_path, __name__)
        return getattr(module, attr)
    if name == "knowledge":
        return importlib.import_module(".knowledge", __name__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")