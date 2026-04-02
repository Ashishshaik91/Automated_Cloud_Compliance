"""
Tests for org scoping helper — Feature 3.
Verifies apply_org_scope, require_write_access, and OrgScope behavior.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy import select

from app.auth.scoping import (
    OrgScope, apply_org_scope, require_write_access, require_org_context,
    MissingOrgContextError,
)


# ── OrgScope core properties ─────────────────────────────────────────────────

class TestOrgScope:
    def test_admin_scope_is_admin(self):
        scope = OrgScope(mode="all")
        assert scope.is_admin is True
        assert scope.is_read_only is False

    def test_auditor_scope_is_read_only(self):
        scope = OrgScope(mode="assigned", org_ids=[1, 2])
        assert scope.is_admin is False
        assert scope.is_read_only is True

    def test_customer_scope_is_own(self):
        scope = OrgScope(mode="own", org_ids=[5])
        assert scope.is_admin is False
        assert scope.is_read_only is False


# ── apply_org_scope ───────────────────────────────────────────────────────────

class TestApplyOrgScope:
    def _make_model(self):
        """Mock SQLAlchemy model with an organization_id column."""
        model = MagicMock()
        model.organization_id = MagicMock()
        model.organization_id.__eq__ = lambda self, other: f"org_id == {other}"
        model.organization_id.in_ = lambda ids: f"org_id IN {ids}"
        return model

    def _make_stmt(self):
        return MagicMock()

    def test_admin_scope_does_not_filter(self):
        """Admin mode returns the stmt unchanged (no WHERE clause)."""
        model = self._make_model()
        stmt = self._make_stmt()
        scope = OrgScope(mode="all")
        result = apply_org_scope(stmt, model, scope)
        # stmt.where should NOT be called for admin
        stmt.where.assert_not_called()
        assert result is stmt

    def test_own_scope_single_org(self):
        """Single-org user scopes to exact org_id."""
        model = MagicMock()
        stmt = MagicMock()
        stmt.where.return_value = stmt
        scope = OrgScope(mode="own", org_ids=[7])
        result = apply_org_scope(stmt, model, scope)
        stmt.where.assert_called_once()

    def test_auditor_scope_multi_org(self):
        """Multi-org auditor uses .in_() clause."""
        model = MagicMock()
        stmt = MagicMock()
        stmt.where.return_value = stmt
        scope = OrgScope(mode="assigned", org_ids=[1, 2, 3])
        result = apply_org_scope(stmt, model, scope)
        stmt.where.assert_called_once()

    def test_empty_org_ids_returns_impossible_filter(self):
        """Empty org list should produce a filter that returns no rows (-1 org_id)."""
        model = MagicMock()
        stmt = MagicMock()
        stmt.where.return_value = stmt
        scope = OrgScope(mode="own", org_ids=[])
        result = apply_org_scope(stmt, model, scope)
        stmt.where.assert_called_once()


# ── require_write_access ──────────────────────────────────────────────────────

class TestRequireWriteAccess:
    def test_admin_can_write(self):
        """Admin scope should not raise."""
        scope = OrgScope(mode="all")
        require_write_access(scope)  # no exception

    def test_customer_can_write(self):
        """Customer (dev/viewer) can write within their org."""
        scope = OrgScope(mode="own", org_ids=[1])
        require_write_access(scope)  # no exception

    def test_auditor_cannot_write(self):
        """Auditor (read-only) must raise 403."""
        from fastapi import HTTPException
        scope = OrgScope(mode="assigned", org_ids=[1, 2])
        with pytest.raises(HTTPException) as exc_info:
            require_write_access(scope)
        assert exc_info.value.status_code == 403

    def test_auditor_403_message_is_informative(self):
        """403 detail should explain read-only constraint."""
        from fastapi import HTTPException
        scope = OrgScope(mode="assigned", org_ids=[1])
        with pytest.raises(HTTPException) as exc_info:
            require_write_access(scope)
        assert "read-only" in exc_info.value.detail.lower()


# ── require_org_context ───────────────────────────────────────────────────────

class TestRequireOrgContext:
    def test_valid_org_id_passes_through(self):
        result = require_org_context(42)
        assert result == 42

    def test_none_raises_missing_context_error(self):
        with pytest.raises(MissingOrgContextError):
            require_org_context(None)

    def test_zero_org_id_raises(self):
        """org_id=0 is also invalid (falsy)."""
        with pytest.raises(MissingOrgContextError):
            require_org_context(None)


# ── get_org_scope (integration-ish) ──────────────────────────────────────────

class TestGetOrgScope:
    @pytest.mark.asyncio
    async def test_admin_user_gets_all_scope(self):
        from app.auth.scoping import get_org_scope

        user = MagicMock()
        user.role = "admin"
        user.id = 1
        user.organization_id = 1
        db = AsyncMock()

        scope = await get_org_scope(user, db)
        assert scope.mode == "all"
        assert scope.is_admin is True

    @pytest.mark.asyncio
    async def test_customer_user_gets_own_scope(self):
        from app.auth.scoping import get_org_scope

        user = MagicMock()
        user.role = "dev"
        user.id = 5
        user.organization_id = 3
        db = AsyncMock()

        scope = await get_org_scope(user, db)
        assert scope.mode == "own"
        assert scope.org_ids == [3]

    @pytest.mark.asyncio
    async def test_user_without_org_id_gets_empty_own_scope(self):
        from app.auth.scoping import get_org_scope
        import structlog

        user = MagicMock()
        user.role = "viewer"
        user.id = 99
        user.organization_id = None
        db = AsyncMock()

        scope = await get_org_scope(user, db)
        assert scope.mode == "own"
        assert scope.org_ids == []
