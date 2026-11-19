"""JWT session handling for the ForensIQ client.

Security decisions (deliberate departures from the legacy CLI, documented in
``COMBINED_PHASE_2_3_REPORT.md``):

* only the access token and non-secret metadata are persisted;
* the user's password is never written to disk;
* the session file is created with ``0600`` permissions;
* there is no password-based silent re-authentication: the backend exposes no
  refresh endpoint, so an expired token means the user must log in again;
* token values never appear in error messages or logs.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .api_client import ApiClient
from .errors import AuthError, ConfigurationError, UnauthorizedError

DEFAULT_SESSION_PATH = Path.home() / ".config" / "forensiq" / "session.json"
EXPIRY_LEEWAY_SECONDS = 30


@dataclass(frozen=True)
class Session:
    """An authenticated session. Never contains a password."""

    access_token: str
    username: str | None = None
    token_type: str = "bearer"
    issued_at: float | None = None
    expires_at: float | None = None

    def is_expired(self, now: float | None = None, leeway: int = EXPIRY_LEEWAY_SECONDS) -> bool | None:
        """True/False when ``exp`` is known, ``None`` when it cannot be decoded."""
        if self.expires_at is None:
            return None
        return (now if now is not None else time.time()) + leeway >= self.expires_at


def decode_jwt_expiry(token: str) -> float | None:
    """Read ``exp`` from a JWT payload without verifying the signature.

    This is a local UX hint only -- the backend remains the authority on token
    validity. Never used to make a security decision on its own.
    """
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except (ValueError, UnicodeError, TypeError):
        return None
    exp = data.get("exp") if isinstance(data, dict) else None
    if isinstance(exp, (int, float)):
        return float(exp)
    return None


class TokenStore:
    """Persist a :class:`Session` to a ``0600`` JSON file."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path is not None else DEFAULT_SESSION_PATH

    def save(self, session: Session) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _chmod_quietly(self.path.parent, 0o700)
        payload = json.dumps(asdict(session), indent=2, sort_keys=True)
        descriptor, temp_name = tempfile.mkstemp(
            dir=str(self.path.parent), prefix=".session-", suffix=".tmp"
        )
        try:
            os.chmod(temp_name, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.replace(temp_name, self.path)
            _chmod_quietly(self.path, 0o600)
        except OSError as exc:
            Path(temp_name).unlink(missing_ok=True)
            raise ConfigurationError(f"cannot write session file: {exc}") from exc

    def load(self) -> Session | None:
        if not self.path.exists():
            return None
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(raw, dict) or not raw.get("access_token"):
            return None
        return Session(
            access_token=str(raw["access_token"]),
            username=raw.get("username"),
            token_type=str(raw.get("token_type", "bearer")),
            issued_at=raw.get("issued_at"),
            expires_at=raw.get("expires_at"),
        )

    def clear(self) -> None:
        try:
            self.path.unlink(missing_ok=True)
        except OSError as exc:  # pragma: no cover - permission problems
            raise ConfigurationError(f"cannot remove session file: {exc}") from exc


class AuthService:
    """Login, session persistence, logout and bearer-header management."""

    def __init__(
        self,
        api_client: ApiClient | None = None,
        store: TokenStore | None = None,
        *,
        clock=time.time,
    ) -> None:
        self.store = store or TokenStore()
        self._api = api_client
        self._clock = clock
        self._session: Session | None = None

    # -- wiring ----------------------------------------------------------
    def bind_client(self, api_client: ApiClient) -> None:
        """Attach the HTTP client that carries this service's bearer token."""
        self._api = api_client

    @property
    def api(self) -> ApiClient:
        if self._api is None:  # pragma: no cover - guarded by construction
            raise ConfigurationError("AuthService has no ApiClient bound")
        return self._api

    @property
    def session(self) -> Session | None:
        return self._session

    @property
    def token(self) -> str | None:
        """Current bearer token, or ``None`` when logged out/expired.

        This is the single thing :class:`ApiClient` asks for, so the credential
        never has to be threaded through call sites.
        """
        if self._session is None:
            return None
        if self._session.is_expired(now=self._clock()) is True:
            return None
        return self._session.access_token

    @property
    def is_authenticated(self) -> bool:
        return self.token is not None

    # -- lifecycle -------------------------------------------------------
    async def login(self, username: str, password: str) -> Session:
        if not username or not password:
            raise AuthError("username and password are required")
        try:
            payload = await self.api.request(
                "POST",
                "/login",
                json_body={"username": username, "password": password},
                authenticated=False,
            )
        except UnauthorizedError as exc:
            raise AuthError("incorrect username or password") from exc

        token = (payload or {}).get("access_token") if isinstance(payload, dict) else None
        if not token:
            raise AuthError("login response did not contain an access token")

        now = self._clock()
        session = Session(
            access_token=str(token),
            username=username,
            token_type=str((payload or {}).get("token_type", "bearer")),
            issued_at=now,
            expires_at=decode_jwt_expiry(str(token)),
        )
        self.store.save(session)
        self._session = session
        return session

    def load_session(self) -> Session | None:
        """Restore a persisted session, discarding it if locally expired."""
        stored = self.store.load()
        if stored is None:
            self._session = None
            return None
        if stored.is_expired(now=self._clock()) is True:
            self.store.clear()
            self._session = None
            return None
        self._session = stored
        return stored

    def logout(self) -> None:
        """Drop the local session. The backend has no revocation endpoint."""
        self._session = None
        self.store.clear()

    def require_session(self) -> Session:
        session = self._session
        if session is None or self.token is None:
            raise AuthError(
                "authentication required", reauthentication_required=True
            )
        return session

    def auth_headers(self) -> dict[str, str]:
        token = self.token
        return {"Authorization": f"Bearer {token}"} if token else {}

    # -- account ---------------------------------------------------------
    async def profile(self) -> dict[str, Any]:
        self.require_session()
        try:
            payload = await self.api.request("GET", "/users/me")
        except UnauthorizedError as exc:
            self._session = None
            self.store.clear()
            raise AuthError(
                "session is no longer valid; please log in again",
                reauthentication_required=True,
            ) from exc
        return payload if isinstance(payload, dict) else {}

    async def register(self, username: str, email: str, password: str) -> dict[str, Any]:
        if not (username and email and password):
            raise AuthError("username, email and password are required")
        payload = await self.api.request(
            "POST",
            "/register",
            json_body={"username": username, "email": email, "password": password},
            authenticated=False,
        )
        return payload if isinstance(payload, dict) else {}


def _chmod_quietly(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:  # pragma: no cover - platform dependent
        pass
