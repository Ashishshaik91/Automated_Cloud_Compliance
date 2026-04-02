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

# ── 3. Stub cloud + infra SDKs ─ submodule-aware ──────────────────────────
# boto3 / botocore — import chains do e.g. `from botocore.exceptions import X`
# so we must pre-register every sub-module that may be referenced.
_botocore_mock = MagicMock()
for _submod in (
    "botocore",
    "botocore.exceptions",
    "botocore.config",
    "botocore.client",
    "botocore.session",
):
    sys.modules.setdefault(_submod, _botocore_mock)

_boto3_mock = MagicMock()
for _submod in ("boto3", "boto3.session"):
    sys.modules.setdefault(_submod, _boto3_mock)

# Azure SDK stubs
for _sdk in (
    "azure",
    "azure.identity",
    "azure.mgmt",
    "azure.mgmt.storage",
    "azure.mgmt.compute",
    "azure.mgmt.network",
    "azure.mgmt.resource",
    "azure.mgmt.monitor",
    "azure.mgmt.sql",
    "azure.mgmt.keyvault",
):
    sys.modules.setdefault(_sdk, MagicMock())

# GCP SDK stubs
for _sdk in (
    "google",
    "google.cloud",
    "google.cloud.storage",
    "google.cloud.asset_v1",
    "google.cloud.logging",
    "google.cloud.securitycenter",
    "google.cloud.compute_v1",
    "google.cloud.resource_manager",
    "google.auth",
    "google.oauth2",
    "googleapiclient",
    "googleapiclient.discovery",
):
    sys.modules.setdefault(_sdk, MagicMock())

# Infra utility stubs (minio, alerting, celery sub-packages)
for _sdk in (
    "minio",
    "minio.error",
    "slack_sdk",
    "slack_sdk.web",
    "sendgrid",
    "kombu",
    "kombu.utils",
    "celery.utils",
    "celery.app",
    "requests",
    "aiohttp",
    "reportlab",
    "reportlab.lib",
    "jinja2",
    "pyod",
    "pyod.models",
):
    sys.modules.setdefault(_sdk, MagicMock())
