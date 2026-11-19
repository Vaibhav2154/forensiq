"""Non-secret client configuration.

Stored at ``~/.config/forensiq/config.json``. Tokens never live here; they are
owned by :mod:`cli_agent.services.auth_service`.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from .errors import ConfigurationError

DEFAULT_BASE_URL = "http://localhost:8000"
DEFAULT_CONFIG_PATH = Path.home() / ".config" / "forensiq" / "config.json"

# Mirrors the backend's accepted range for max_results (le=20).
MIN_INTERVAL = 10
MAX_INTERVAL = 86_400
MIN_MAX_RESULTS = 1
MAX_MAX_RESULTS = 20


@dataclass(frozen=True)
class ClientConfig:
    """Everything the client needs that is not a credential."""

    base_url: str = DEFAULT_BASE_URL
    interval_seconds: int = 300
    max_results: int = 5
    enhance_with_ai: bool = True
    monitoring_type: str = "dynamic"
    sources: tuple[str, ...] = ()
    log_path: str | None = None

    def validated(self) -> "ClientConfig":
        if not isinstance(self.base_url, str) or not self.base_url.strip():
            raise ConfigurationError("base_url must be a non-empty string")
        if not (MIN_INTERVAL <= int(self.interval_seconds) <= MAX_INTERVAL):
            raise ConfigurationError(
                f"interval_seconds must be between {MIN_INTERVAL} and {MAX_INTERVAL}"
            )
        if not (MIN_MAX_RESULTS <= int(self.max_results) <= MAX_MAX_RESULTS):
            raise ConfigurationError(
                f"max_results must be between {MIN_MAX_RESULTS} and {MAX_MAX_RESULTS}"
            )
        if self.monitoring_type not in {"dynamic", "file"}:
            raise ConfigurationError("monitoring_type must be 'dynamic' or 'file'")
        return self


class ConfigService:
    """Load/save :class:`ClientConfig` with validation and atomic writes."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path is not None else DEFAULT_CONFIG_PATH

    def load(self) -> ClientConfig:
        if not self.path.exists():
            return ClientConfig()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ConfigurationError(f"cannot read config: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigurationError("config file must contain a JSON object")
        return _from_dict(raw).validated()

    def save(self, config: ClientConfig) -> ClientConfig:
        config = config.validated()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:  # pragma: no cover - platform dependent
            pass
        payload = json.dumps(asdict(config), indent=2, sort_keys=True)
        descriptor, temp_name = tempfile.mkstemp(
            dir=str(self.path.parent), prefix=".config-", suffix=".tmp"
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.replace(temp_name, self.path)
        except OSError as exc:
            Path(temp_name).unlink(missing_ok=True)
            raise ConfigurationError(f"cannot write config: {exc}") from exc
        return config

    def update(self, **changes: Any) -> ClientConfig:
        current = self.load()
        return self.save(replace(current, **changes))


def _from_dict(raw: dict[str, Any]) -> ClientConfig:
    defaults = ClientConfig()
    sources = raw.get("sources") or ()
    if isinstance(sources, str):
        sources = tuple(part.strip() for part in sources.split(",") if part.strip())
    else:
        sources = tuple(str(item) for item in sources)
    try:
        return ClientConfig(
            base_url=str(raw.get("base_url", defaults.base_url)),
            interval_seconds=int(raw.get("interval_seconds", defaults.interval_seconds)),
            max_results=int(raw.get("max_results", defaults.max_results)),
            enhance_with_ai=bool(raw.get("enhance_with_ai", defaults.enhance_with_ai)),
            monitoring_type=str(raw.get("monitoring_type", defaults.monitoring_type)),
            sources=sources,
            log_path=raw.get("log_path"),
        )
    except (TypeError, ValueError) as exc:
        raise ConfigurationError(f"invalid config value: {exc}") from exc
