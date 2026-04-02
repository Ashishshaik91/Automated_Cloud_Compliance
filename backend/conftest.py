"""
Backend test configuration.
Sets required environment variables and stubs out the asyncpg driver
before any app module is imported, so tests can run without Docker.
"""

import os
import sys
from unittest.mock import MagicMock

# ── 1. Set all required env vars ─────────────────────────────────────────────
_TEST_ENV = {
    "APP_SECRET_KEY":        "test-secret-key-for-unit-tests-only-32chars",
    "JWT_SECRET_KEY":        "test-jwt-secret-key-for-unit-tests-only",
    "DATABASE_URL":          "postgresql+asyncpg://test:test@localhost/testdb",
    "POSTGRES_PASSWORD":     "testpassword",
    "REDIS_URL":             "redis://localhost:6379/0",
    "REDIS_PASSWORD":        "testredispassword",
    "MINIO_ACCESS_KEY":      "testminiokey",
    "MINIO_SECRET_KEY":      "testminiosecret",
    "CELERY_BROKER_URL":     "redis://localhost:6379/1",
    "CELERY_RESULT_BACKEND": "redis://localhost:6379/2",
    "VIRUSTOTAL_API_KEY":    "",
    "MISP_API_KEY":          "",
    "NVD_API_KEY":           "",
    "TERRAFORM_MODE":        "json",
}
for key, value in _TEST_ENV.items():
    os.environ.setdefault(key, value)

# ── 2. Stub asyncpg so SQLAlchemy can create the engine without a real driver ─
_asyncpg_mock = MagicMock()
_asyncpg_mock.__version__ = "0.29.0"
sys.modules.setdefault("asyncpg", _asyncpg_mock)

# Also stub celery so importing celery_app doesn't require a broker
_celery_mock = MagicMock()
sys.modules.setdefault("celery", _celery_mock)

# Stub optional cloud SDK packages that may not be installed locally
for _sdk in [
    "boto3", "botocore",
    "azure.identity", "azure.mgmt.storage",
    "google.cloud.storage",
]:
    sys.modules.setdefault(_sdk, MagicMock())
