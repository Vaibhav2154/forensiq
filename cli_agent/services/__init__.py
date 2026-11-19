"""Reusable ForensIQ application services.

Nothing in this package renders to a terminal, prompts for input, or exits the
process: that keeps it usable from the CLI today and from Textual later.
"""

from .api_client import ApiClient, AiohttpTransport, HttpResponse
from .auth_service import AuthService, Session, TokenStore
from .cli_service import CliService
from .collector_service import CollectionResult, CollectorService
from .config_service import ClientConfig, ConfigService
from .errors import (
    ApiError,
    AuthError,
    ConfigurationError,
    ForensIQError,
    ForbiddenError,
    MalformedResponseError,
    RateLimitError,
    ServerError,
    TransportError,
    UnauthorizedError,
    ValidationError,
)
from .monitoring_service import MonitoringService, MonitoringState, MonitoringStats
from .response_adapter import AnalysisView, Technique, adapt_analysis, next_interval

__all__ = [
    "AiohttpTransport",
    "AnalysisView",
    "ApiClient",
    "ApiError",
    "AuthError",
    "AuthService",
    "CliService",
    "ClientConfig",
    "CollectionResult",
    "CollectorService",
    "ConfigService",
    "ConfigurationError",
    "ForensIQError",
    "ForbiddenError",
    "HttpResponse",
    "MalformedResponseError",
    "MonitoringService",
    "MonitoringState",
    "MonitoringStats",
    "RateLimitError",
    "ServerError",
    "Session",
    "Technique",
    "TokenStore",
    "TransportError",
    "UnauthorizedError",
    "ValidationError",
    "adapt_analysis",
    "next_interval",
]
