"""
Alembic environment configuration.

Uses the async SQLAlchemy engine and imports all app models so that
`alembic revision --autogenerate` can detect schema changes correctly.
"""

import asyncio
from logging.config import fileConfig
from typing import Any

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine

# Import Base + all model modules so their tables are registered
# before autogenerate runs. Order matters: Base first, then models
# that have no FK deps, then models with FKs.
from app.models.database import Base           # noqa: F401
from app.models.user import User               # noqa: F401
from app.models.org import (                   # noqa: F401
    Organization,
    UserAccountRole,
    AuditorOrgAssignment,
)
from app.models.compliance import (            # noqa: F401
    CloudAccount,
    ScanResult,
    ComplianceCheck,
)
from app.models.violations import (            # noqa: F401
    ViolationRule,
    Violation,
)
from app.models.dspm import (                  # noqa: F401
    DSPMFinding,
    DSPMCorrelation,
)
from app.models.audit_log import AuditLog      # noqa: F401

from app.config import get_settings

settings = get_settings()

# Alembic Config object (gives access to values in alembic.ini)
config = context.config

# Override sqlalchemy.url with the app's DATABASE_URL env-var
config.set_main_option("sqlalchemy.url", settings.database_url)

# Interpret the config file's logging settings
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata for autogenerate
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode.

    This configures the context with just a URL and not an Engine,
    though an Engine is acceptable here as well. By skipping the Engine
    creation we don't even need a DBAPI to be available.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Any) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations using the async engine."""
    engine = create_async_engine(
        settings.database_url,
        poolclass=pool.NullPool,  # Disable pooling for migrations
    )
    async with engine.begin() as conn:
        await conn.run_sync(do_run_migrations)
    await engine.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode with an actual DB connection."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
