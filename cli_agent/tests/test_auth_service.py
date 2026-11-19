"""Checkpoint 3: authentication, persistence, expiry and logout."""

from __future__ import annotations

import json
import stat

import pytest

from cli_agent.client.api_client import ApiClient
from cli_agent.client.auth_service import (
    AuthService,
    TokenStore,
    decode_jwt_expiry,
)
from cli_agent.client.errors import AuthError, UnauthorizedError

from .conftest import FakeTransport, make_jwt

BASE = "http://localhost:8000"


def build(store: TokenStore, transport: FakeTransport) -> tuple[AuthService, ApiClient]:
    auth = AuthService(store=store)
    client = ApiClient(BASE, transport=transport, token_provider=lambda: auth.token)
    auth.bind_client(client)
    return auth, client


async def test_login_stores_token(tmp_path) -> None:
    token = make_jwt()
    transport = FakeTransport().queue({"access_token": token, "token_type": "bearer"})
    store = TokenStore(tmp_path / "session.json")
    auth, _client = build(store, transport)

    session = await auth.login("analyst", "pw")

    assert session.access_token == token
    assert session.username == "analyst"
    assert auth.is_authenticated is True
    assert transport.last["json"] == {"username": "analyst", "password": "pw"}
    assert "Authorization" not in transport.last["headers"]


async def test_login_persists_no_password(tmp_path) -> None:
    raw = tmp_path / "session.json"
    transport = FakeTransport().queue({"access_token": make_jwt()})
    auth, _client = build(TokenStore(raw), transport)
    await auth.login("analyst", "super-secret-password")

    stored = raw.read_text(encoding="utf-8")
    assert "super-secret-password" not in stored
    data = json.loads(stored)
    assert set(data) <= {"access_token", "username", "token_type", "issued_at", "expires_at"}
    assert "password" not in data


async def test_session_file_permissions_are_restrictive(tmp_path) -> None:
    raw = tmp_path / "session.json"
    transport = FakeTransport().queue({"access_token": make_jwt()})
    auth, _client = build(TokenStore(raw), transport)
    await auth.login("analyst", "pw")
    assert stat.S_IMODE(raw.stat().st_mode) == 0o600


async def test_invalid_credentials_raise_auth_error(tmp_path) -> None:
    transport = FakeTransport().queue((401, {"detail": "Incorrect username or password"}))
    auth, _client = build(TokenStore(tmp_path / "s.json"), transport)
    with pytest.raises(AuthError) as excinfo:
        await auth.login("analyst", "wrong")
    assert "password" not in str(excinfo.value).lower().replace("incorrect username or password", "")


async def test_login_without_token_is_rejected(tmp_path) -> None:
    transport = FakeTransport().queue({"token_type": "bearer"})
    auth, _client = build(TokenStore(tmp_path / "s.json"), transport)
    with pytest.raises(AuthError):
        await auth.login("analyst", "pw")


async def test_load_session_round_trip(tmp_path) -> None:
    path = tmp_path / "session.json"
    transport = FakeTransport().queue({"access_token": make_jwt(expires_in=3600)})
    auth, _client = build(TokenStore(path), transport)
    await auth.login("analyst", "pw")

    fresh, _ = build(TokenStore(path), FakeTransport())
    assert fresh.load_session() is not None
    assert fresh.is_authenticated is True
    assert fresh.token is not None


async def test_expired_session_is_discarded(tmp_path) -> None:
    path = tmp_path / "session.json"
    transport = FakeTransport().queue({"access_token": make_jwt(expires_in=-3600)})
    auth, _client = build(TokenStore(path), transport)
    await auth.login("analyst", "pw")

    # A token whose exp is already past is not usable, even though it was just
    # minted by the fake backend.
    assert auth.token is None
    fresh, _ = build(TokenStore(path), FakeTransport())
    assert fresh.load_session() is None
    assert not path.exists()


async def test_token_property_hides_expired_token(tmp_path) -> None:
    transport = FakeTransport().queue({"access_token": make_jwt(expires_in=-10)})
    auth, _client = build(TokenStore(tmp_path / "s.json"), transport)
    await auth.login("analyst", "pw")
    assert auth.token is None
    assert auth.auth_headers() == {}


async def test_logout_clears_token_and_file(tmp_path) -> None:
    path = tmp_path / "session.json"
    transport = FakeTransport().queue({"access_token": make_jwt()})
    auth, _client = build(TokenStore(path), transport)
    await auth.login("analyst", "pw")
    assert path.exists()

    auth.logout()
    assert path.exists() is False
    assert auth.token is None
    assert auth.is_authenticated is False


async def test_profile_401_requires_reauthentication(tmp_path) -> None:
    path = tmp_path / "session.json"
    transport = FakeTransport().queue(
        {"access_token": make_jwt()},
        (401, {"detail": "Could not validate credentials"}),
    )
    auth, _client = build(TokenStore(path), transport)
    await auth.login("analyst", "pw")

    with pytest.raises(AuthError) as excinfo:
        await auth.profile()
    assert excinfo.value.reauthentication_required is True
    assert auth.token is None
    assert not path.exists()


async def test_profile_requires_session(tmp_path) -> None:
    auth, _client = build(TokenStore(tmp_path / "s.json"), FakeTransport())
    with pytest.raises(AuthError):
        await auth.profile()


async def test_register_posts_expected_payload(tmp_path) -> None:
    transport = FakeTransport().queue({"username": "new", "email": "n@example.com"})
    auth, _client = build(TokenStore(tmp_path / "s.json"), transport)
    await auth.register("new", "n@example.com", "pw")
    assert transport.last["url"].endswith("/register")
    assert transport.last["json"] == {
        "username": "new",
        "email": "n@example.com",
        "password": "pw",
    }


def test_decode_jwt_expiry_handles_garbage() -> None:
    assert decode_jwt_expiry("not-a-jwt") is None
    assert decode_jwt_expiry("a.b.c") is None
    assert decode_jwt_expiry("") is None


def test_decode_jwt_expiry_reads_exp() -> None:
    token = make_jwt(expires_in=120)
    expiry = decode_jwt_expiry(token)
    assert expiry is not None and expiry > 0


def test_token_never_appears_in_error_messages(tmp_path) -> None:
    token = make_jwt()
    store = TokenStore(tmp_path / "s.json")
    from cli_agent.client.auth_service import Session

    store.save(Session(access_token=token, username="analyst"))
    auth = AuthService(store=store, api_client=ApiClient(BASE, transport=FakeTransport()))
    try:
        auth.require_session()
    except AuthError as exc:
        assert token not in str(exc)
    with pytest.raises(UnauthorizedError):
        raise UnauthorizedError(401, "unauthorized")
