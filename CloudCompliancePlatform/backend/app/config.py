"""
Cloud Compliance Platform — Application Configuration
Reads all settings from environment variables using pydantic-settings.
Never hardcodes secrets.
"""

from functools import lru_cache
from typing import List

from pydantic import AnyHttpUrl, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ---- Application ----
    app_env: str = "development"
    app_secret_key: SecretStr
    app_debug: bool = False
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    allowed_origins: str = "http://localhost:3000"

    @property
    def cors_origins(self) -> List[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    # ---- JWT ----
    jwt_secret_key: SecretStr
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    # ---- Database ----
    database_url: str
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_db: str = "compliance_db"
    postgres_user: str = "compliance_user"
    postgres_password: SecretStr

    # ---- Redis ----
    redis_url: str
    redis_password: SecretStr

    # ---- MinIO ----
    minio_host: str = "minio"
    minio_port: int = 9000
    minio_access_key: SecretStr
    minio_secret_key: SecretStr
    minio_bucket_evidence: str = "compliance-evidence"
    minio_secure: bool = False

    # ---- OPA ----
    opa_url: str = "http://opa:8181"

    # ---- Cloud Connectors (all optional) ----
    aws_access_key_id: str = ""
    aws_secret_access_key: SecretStr = SecretStr("")
    aws_default_region: str = "us-east-1"
    aws_role_arn: str = ""

    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: SecretStr = SecretStr("")
    azure_subscription_id: str = ""

    gcp_project_id: str = ""
    gcp_service_account_json_path: str = ""

    # ---- Alerting ----
    slack_webhook_url: str = ""
    pagerduty_routing_key: SecretStr = SecretStr("")
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: SecretStr = SecretStr("")
    smtp_from_email: str = "alerts@localhost"

    # ---- Celery ----
    celery_broker_url: str
    celery_result_backend: str
    scan_interval_seconds: int = 300

    # ---- Logging ----
    log_level: str = "INFO"
    log_format: str = "json"

    @field_validator("app_env")
    @classmethod
    def validate_env(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v not in allowed:
            raise ValueError(f"app_env must be one of {allowed}")
        return v


@lru_cache()
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
