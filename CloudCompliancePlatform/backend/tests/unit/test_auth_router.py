"""
Unit tests for auth router and dependencies.
Covers login, register, refresh, and get_current_user endpoints.
"""
import datetime
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.models.database import get_db
from app.auth.jwt import create_access_token, create_refresh_token, hash_password

# ── shared mock user ──────────────────────────────────────────────────────────

def make_mock_user(user_id=1, email="test@example.com", role="viewer",
                   is_active=True, hashed_pw=None):
    user = MagicMock()
    user.id = user_id
    user.email = email
    user.role = role
    user.is_active = is_active
    user.hashed_password = hashed_pw or hash_password("password123")
    user.full_name = "Test User"
    user.created_at = datetime.datetime.now(datetime.timezone.utc)
    user.updated_at = datetime.datetime.now(datetime.timezone.utc)
    return user

# ── DB dependency override ────────────────────────────────────────────────────

def make_mock_db():
    mock_db = MagicMock()
    mock_db.__aenter__ = AsyncMock(return_value=mock_db)
    mock_db.__aexit__ = AsyncMock(return_value=False)
    mock_result = MagicMock()
    mock_db.execute = AsyncMock(return_value=mock_result)
    mock_result.scalar_one_or_none = MagicMock(return_value=None)
    return mock_db

# ── tests ─────────────────────────────────────────────────────────────────────

class TestAuthRouter:
    def setup_method(self):
        self.client = TestClient(app, raise_server_exceptions=False)

    def _override_db(self):
        db = make_mock_db()
        async def _inner():
            yield db
        return _inner

    def test_login_success(self):
        mock_user = make_mock_user()
        with patch("app.models.user.User.get_by_email", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_user
            with patch("app.auth.router.verify_password", return_value=True):
                app.dependency_overrides[get_db] = self._override_db()
                resp = self.client.post(
                    "/api/v1/auth/login",
                    data={"username": "test@example.com", "password": "password123"},
                )
                app.dependency_overrides.clear()
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_login_wrong_password(self):
        mock_user = make_mock_user()
        with patch("app.models.user.User.get_by_email", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_user
            with patch("app.auth.router.verify_password", return_value=False):
                app.dependency_overrides[get_db] = self._override_db()
                resp = self.client.post(
                    "/api/v1/auth/login",
                    data={"username": "test@example.com", "password": "wrong"},
                )
                app.dependency_overrides.clear()
        assert resp.status_code == 401

    def test_login_user_not_found(self):
        with patch("app.models.user.User.get_by_email", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = None
            app.dependency_overrides[get_db] = self._override_db()
            resp = self.client.post(
                "/api/v1/auth/login",
                data={"username": "nobody@example.com", "password": "x"},
            )
            app.dependency_overrides.clear()
        assert resp.status_code == 401

    def test_login_inactive_user(self):
        mock_user = make_mock_user(is_active=False)
        with patch("app.models.user.User.get_by_email", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_user
            with patch("app.auth.router.verify_password", return_value=True):
                app.dependency_overrides[get_db] = self._override_db()
                resp = self.client.post(
                    "/api/v1/auth/login",
                    data={"username": "test@example.com", "password": "p"},
                )
                app.dependency_overrides.clear()
        assert resp.status_code == 403

    def test_register_success(self):
        mock_user = make_mock_user()
        with patch("app.models.user.User.get_by_email", new_callable=AsyncMock) as mock_existing:
            mock_existing.return_value = None
            with patch("app.models.user.User.create", new_callable=AsyncMock) as mock_create:
                mock_create.return_value = mock_user
                app.dependency_overrides[get_db] = self._override_db()
                resp = self.client.post(
                    "/api/v1/auth/register",
                    json={"email": "new@example.com", "password": "Password123!", "full_name": "New User"},
                )
                app.dependency_overrides.clear()
        assert resp.status_code == 201

    def test_register_duplicate_email(self):
        mock_user = make_mock_user()
        with patch("app.models.user.User.get_by_email", new_callable=AsyncMock) as mock_existing:
            mock_existing.return_value = mock_user
            app.dependency_overrides[get_db] = self._override_db()
            resp = self.client.post(
                "/api/v1/auth/register",
                json={"email": "test@example.com", "password": "Password123!", "full_name": "Dup"},
            )
            app.dependency_overrides.clear()
        assert resp.status_code == 409

    def test_refresh_valid_token(self):
        mock_user = make_mock_user()
        refresh_token = create_refresh_token(str(mock_user.id))
        with patch("app.models.user.User.get_by_id", new_callable=AsyncMock) as mock_get_id:
            mock_get_id.return_value = mock_user
            app.dependency_overrides[get_db] = self._override_db()
            resp = self.client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": refresh_token},
            )
            app.dependency_overrides.clear()
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_refresh_invalid_token(self):
        app.dependency_overrides[get_db] = self._override_db()
        resp = self.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "not.a.valid.token"},
        )
        app.dependency_overrides.clear()
        assert resp.status_code == 401

    def test_refresh_access_token_rejected(self):
        """Refresh endpoint should reject access tokens (wrong type)."""
        access_token = create_access_token("1")
        app.dependency_overrides[get_db] = self._override_db()
        resp = self.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": access_token},
        )
        app.dependency_overrides.clear()
        assert resp.status_code == 401

    def test_get_me(self):
        mock_user = make_mock_user()
        access_token = create_access_token(str(mock_user.id), {"role": mock_user.role})
        with patch("app.auth.dependencies.User.get_by_id", new_callable=AsyncMock) as mock_get_id:
            mock_get_id.return_value = mock_user
            app.dependency_overrides[get_db] = self._override_db()
            resp = self.client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            app.dependency_overrides.clear()
        assert resp.status_code == 200

    def test_get_me_unauthorized(self):
        resp = self.client.get("/api/v1/auth/me")
        assert resp.status_code == 401


class TestAuthDependencies:
    """Tests targeting auth/dependencies.py uncovered branches."""

    def setup_method(self):
        self.client = TestClient(app, raise_server_exceptions=False)

    def _override_db(self):
        db = MagicMock()
        db.__aenter__ = AsyncMock(return_value=db)
        db.__aexit__ = AsyncMock(return_value=False)
        async def _inner():
            yield db
        return _inner

    def test_get_me_with_refresh_token_rejected(self):
        """Bearer token with type=refresh should be rejected (line 35)."""
        refresh_token = create_refresh_token("1")
        app.dependency_overrides[get_db] = self._override_db()
        resp = self.client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {refresh_token}"},
        )
        app.dependency_overrides.clear()
        assert resp.status_code == 401

    def test_get_me_user_not_found(self):
        """User not found in DB should return 401 (line 45)."""
        token = create_access_token("999")
        with patch("app.auth.dependencies.User.get_by_id", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = None
            app.dependency_overrides[get_db] = self._override_db()
            resp = self.client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {token}"},
            )
            app.dependency_overrides.clear()
        assert resp.status_code == 401

    def test_get_me_inactive_user(self):
        """Inactive user should return 403 (line 47)."""
        mock_user = make_mock_user(is_active=False)
        token = create_access_token(str(mock_user.id))
        with patch("app.auth.dependencies.User.get_by_id", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_user
            app.dependency_overrides[get_db] = self._override_db()
            resp = self.client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {token}"},
            )
            app.dependency_overrides.clear()
        assert resp.status_code == 403

    def test_admin_endpoint_non_admin_forbidden(self):
        """Non-admin user should get 403 on admin-only routes (lines 58-63)."""
        from app.auth.dependencies import require_admin, get_current_user
        mock_user = make_mock_user(role="viewer")
        import asyncio
        from fastapi import HTTPException

        async def run():
            return await require_admin(mock_user)

        with pytest.raises(HTTPException) as exc:
            asyncio.get_event_loop().run_until_complete(run())
        assert exc.value.status_code == 403

    def test_admin_endpoint_admin_allowed(self):
        """Admin user should pass require_admin without error."""
        from app.auth.dependencies import require_admin
        import asyncio

        mock_user = make_mock_user(role="admin")

        async def run():
            return await require_admin(mock_user)

        result = asyncio.get_event_loop().run_until_complete(run())
        assert result == mock_user
