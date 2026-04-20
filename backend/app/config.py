"""
Cloud Compliance Platform — Application Configuration
Reads all settings from environment variables using pydantic-settings.
Never hardcodes secrets.
"""

from functools import lru_cache
from typing import List
from pathlib import Path

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
    jwt_secret_key: SecretStr = SecretStr("")
    jwt_dual_verify: bool = False   # True only during HS256→RS256 migration window
    jwt_algorithm: str = "RS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7
    
    @property
    def jwt_private_key(self) -> str:
        key_path = Path("/app/keys/jwt_private.pem") if self.app_env != "development" else Path(__file__).parent.parent / "keys" / "jwt_private.pem"
        return key_path.read_text() if key_path.exists() else ""

    @property
    def jwt_public_key(self) -> str:
        key_path = Path("/app/keys/jwt_public.pem") if self.app_env != "development" else Path(__file__).parent.parent / "keys" / "jwt_public.pem"
        return key_path.read_text() if key_path.exists() else ""

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
    opa_url: str = "https://opa:8181"

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

    # ---- Terraform State Ingestion (Feature 1) ----
    # Mode: "json" (default, parse .tfstate directly), "binary" (run terraform CLI), "remote" (download from backend)
    terraform_mode: str = "json"
    # Required when remote state bucket uses SSE-KMS encryption
    terraform_state_kms_key_arn: str = ""

    # ---- Threat Intelligence Enrichment (Feature 4) ----
    # NVD (National Vulnerability Database) — free tier available without key but rate-limited
    nvd_api_key: str = ""
    # VirusTotal v3 — free tier: 4 req/min; premium: unlimited
    virustotal_api_key: SecretStr = SecretStr("")
    # MISP — leave empty to disable; set to your MISP instance base URL to enable
    misp_url: str = ""
    misp_api_key: SecretStr = SecretStr("")
    # Path to a PEM CA certificate file used to verify the MISP server's TLS certificate.
    # Required when your MISP instance uses a self-signed or private-CA certificate.
    # Leave empty to use the system CA store (correct for publicly CA-signed MISP certs).
    # NEVER set verify=False — use this field instead.
    misp_ca_cert: str = ""

    # ---- Prometheus Metrics Scrape IP Allowlist ----
    # Comma-separated list of IPs and/or CIDR ranges allowed to scrape /metrics.
    # 127.0.0.1      — loopback (local scraper / dev)
    # 172.16.0.0/12  — Docker internal subnet (covers 172.16–172.31.x.x Compose networks)
    # ::1            — IPv6 loopback
    # Add your external Prometheus server IP/range here if scraping from outside.
    prometheus_allowed_ips: str = "127.0.0.1,::1,172.16.0.0/12"

    @property
    def parsed_prometheus_allowed_networks(self) -> list:
        """
        Parse prometheus_allowed_ips into a list of IPv4Network / IPv6Network objects.
        Single IPs are treated as host networks (/32 or /128) so the same
        ``ip_address in network`` check works uniformly for both IPs and CIDRs.
        Raises ValueError at startup if any entry is malformed.
        """
        import ipaddress
        networks = []
        for entry in self.prometheus_allowed_ips.split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                # strict=False allows e.g. 172.16.0.5/12 (host bits set)
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                raise ValueError(
                    f"Invalid PROMETHEUS_ALLOWED_IPS entry '{entry}'. "
                    "Must be an IP address (e.g. 192.168.1.5) or CIDR range (e.g. 172.16.0.0/12)."
                )
        return networks

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
