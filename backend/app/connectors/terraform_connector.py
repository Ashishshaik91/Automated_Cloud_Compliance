"""
Terraform State Connector — Feature 1.

Reads Terraform state files and normalises resources into the same
{resource_type, resource_id, config, terraform_declared_config} dict format
that the existing SDK connectors (aws_connector.py, etc.) produce.

Three modes (controlled by TERRAFORM_MODE env var):
  json   (default) — parse .tfstate JSON directly; no Terraform binary needed.
  binary           — run `terraform show -json`; requires Terraform CLI in container.
  remote           — download state from S3/GCS/Azure Blob first, then parse as JSON.

Deduplication rule (enforced in scanner.py, not here):
  When the same resource_id exists in both SDK and TF output, SDK config wins for
  live compliance checking. TF-declared config is preserved in terraform_declared_config
  for drift detection.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from typing import Any

import structlog

from app.config import get_settings
from app.connectors.base import CloudConnectorBase

logger = structlog.get_logger(__name__)

# Redis advisory lock key prefix for concurrent remote state reads
_LOCK_KEY_PREFIX = "tf_state_lock"
_LOCK_TTL_S = 60
_LOCK_RETRY_DELAY_S = 10
_LOCK_MAX_RETRIES = 3


class TerraformStateLockError(RuntimeError):
    """Raised when the Terraform remote state lock cannot be acquired."""


# ── Resource type normalisation map ─────────────────────────────────────────────
# Maps Terraform resource types to our internal resource_type strings
_TF_TYPE_MAP: dict[str, str] = {
    "aws_s3_bucket":            "s3_bucket",
    "aws_iam_user":             "iam_user",
    "aws_db_instance":          "rds_instance",
    "aws_instance":             "ec2_instance",
    "azurerm_storage_account":  "storage_account",
    "azurerm_sql_database":     "sql_database",
    "google_storage_bucket":    "gcs_bucket",
    "google_sql_database_instance": "cloud_sql_instance",
}


def _normalise_resource(tf_type: str, tf_name: str, attrs: dict[str, Any]) -> dict[str, Any]:
    """Convert a Terraform resource instance into the standard connector resource dict."""
    internal_type = _TF_TYPE_MAP.get(tf_type, tf_type)
    resource_id   = attrs.get("id") or attrs.get("name") or tf_name

    return {
        "resource_type":             internal_type,
        "resource_id":               str(resource_id),
        "config":                    attrs,
        "terraform_declared_config": attrs,   # kept for drift comparison in scanner.py
        "source":                    "terraform",
    }


def _parse_tfstate(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Parse a terraform.tfstate JSON blob and return normalised resource dicts.
    Handles both TF state format v4 (resources[].instances[].attributes)
    and the `terraform show -json` plan format.
    """
    resources: list[dict[str, Any]] = []

    # Standard .tfstate format (v4)
    for resource in raw.get("resources", []):
        tf_type = resource.get("type", "")
        tf_name = resource.get("name", "")
        mode    = resource.get("mode", "managed")

        if mode != "managed":
            continue  # skip data sources

        if tf_type not in _TF_TYPE_MAP:
            logger.debug("Skipping unsupported TF resource type", tf_type=tf_type)
            continue

        for instance in resource.get("instances", []):
            attrs = instance.get("attributes", {})
            resources.append(_normalise_resource(tf_type, tf_name, attrs))

    # `terraform show -json` format (values.root_module.resources[])
    values = raw.get("values", {})
    root_module = values.get("root_module", {})
    for resource in root_module.get("resources", []):
        tf_type = resource.get("type", "")
        tf_name = resource.get("name", "")
        mode    = resource.get("mode", "managed")

        if mode != "managed" or tf_type not in _TF_TYPE_MAP:
            continue

        attrs = resource.get("values", {})
        resources.append(_normalise_resource(tf_type, tf_name, attrs))

    logger.info("Terraform state parsed", resource_count=len(resources))
    return resources


class TerraformConnector:
    """
    Reads Terraform state and normalises resources for compliance scanning.
    Works in json, binary, or remote mode (see TERRAFORM_MODE config).
    """

    def __init__(
        self,
        state_path: str | Path | None = None,
        account_id: str = "",
        redis_client: Any = None,
        working_dir: str | Path | None = None,
    ) -> None:
        self.state_path   = Path(state_path) if state_path else None
        self.account_id   = account_id
        self.redis_client = redis_client
        self.settings     = get_settings()
        # Working directory for `terraform show -json` (binary mode)
        self.working_dir  = Path(working_dir) if working_dir else Path.cwd()

    @classmethod
    def from_working_dir(cls, working_dir: str | Path, account_id: str = "", redis_client: Any = None) -> "TerraformConnector":
        """
        Convenience constructor for binary mode.
        Sets working_dir and forces TERRAFORM_MODE=binary so enumerate_resources()
        immediately runs `terraform show -json` in that directory.
        """
        instance = cls(state_path=None, account_id=account_id, redis_client=redis_client, working_dir=working_dir)
        # Override mode at instance level (does not mutate global settings)
        instance._mode_override = "binary"
        return instance

    async def enumerate_resources(self) -> list[dict[str, Any]]:
        """
        Load and parse Terraform state, returning normalised resource dicts.
        Automatically selects mode based on TERRAFORM_MODE config,
        or the instance-level _mode_override set by from_working_dir().
        """
        mode = getattr(self, "_mode_override", None) or self.settings.terraform_mode.lower()

        if mode == "remote":
            return await self._from_remote()
        elif mode == "binary":
            return await self._from_binary()
        else:
            return await self._from_json_file()

    # ── JSON parse mode (default) ────────────────────────────────────────────

    async def _from_json_file(self) -> list[dict[str, Any]]:
        """Read and parse a local .tfstate file directly."""
        if not self.state_path or not self.state_path.exists():
            logger.warning("Terraform state file not found", path=str(self.state_path))
            return []

        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
            return _parse_tfstate(raw)
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Failed to parse .tfstate file", path=str(self.state_path), error=str(e))
            return []

    # ── Binary mode (opt-in) ─────────────────────────────────────────────────

    async def _from_binary(self) -> list[dict[str, Any]]:
        """Run `terraform show -json` in working_dir and parse its output."""
        cwd = self.working_dir
        if not cwd.is_dir():
            logger.error(
                "terraform show -json: working_dir does not exist or is not a directory",
                working_dir=str(cwd),
            )
            return []

        logger.info("Running terraform show -json", working_dir=str(cwd))
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(  # noqa: S603
                    ["terraform", "show", "-json"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    cwd=str(cwd),   # ← run inside the project directory
                ),
            )
            if result.returncode != 0:
                logger.error(
                    "terraform show -json failed",
                    returncode=result.returncode,
                    stderr=result.stderr[:800],
                    working_dir=str(cwd),
                )
                return []
            if not result.stdout.strip():
                logger.warning(
                    "terraform show -json produced no output — is the state initialized?",
                    working_dir=str(cwd),
                )
                return []
            raw = json.loads(result.stdout)
            return _parse_tfstate(raw)
        except FileNotFoundError:
            logger.error(
                "Terraform binary not found in PATH; install Terraform or use TERRAFORM_MODE=json",
                working_dir=str(cwd),
            )
            return []
        except subprocess.TimeoutExpired:
            logger.error("terraform show -json timed out after 60s", working_dir=str(cwd))
            return []
        except json.JSONDecodeError as e:
            logger.error("terraform show -json output is not valid JSON", error=str(e))
            return []

    # ── Remote mode (opt-in) ─────────────────────────────────────────────────

    async def _from_remote(self) -> list[dict[str, Any]]:
        """
        Download Terraform state from a remote backend (S3/GCS/Azure) and parse.
        Uses a Redis advisory lock to prevent concurrent reads of partial state.
        """
        if not self.state_path:
            logger.error("TERRAFORM_MODE=remote but no state_path (remote URI) provided")
            return []

        lock_key = f"{_LOCK_KEY_PREFIX}:{self.account_id}"
        acquired = await self._acquire_lock(lock_key)
        if not acquired:
            raise TerraformStateLockError(
                f"Could not acquire Terraform state lock for account {self.account_id}. "
                "Another scan may be reading the same remote state."
            )

        try:
            raw_bytes = await self._download_remote_state()
            if not raw_bytes:
                return []
            raw = json.loads(raw_bytes)
            return _parse_tfstate(raw)
        except json.JSONDecodeError as e:
            logger.error("Remote Terraform state is not valid JSON", error=str(e))
            return []
        finally:
            await self._release_lock(lock_key)

    async def _download_remote_state(self) -> bytes | None:
        """
        Download state from S3/GCS/Azure based on the state_path URI scheme.
        s3://bucket/key  → boto3
        gs://bucket/key  → google.cloud.storage
        https://...blob  → Azure Blob via azure-storage-blob
        """
        path = str(self.state_path)
        try:
            if path.startswith("s3://"):
                return await self._download_s3(path)
            elif path.startswith("gs://"):
                return await self._download_gcs(path)
            elif "blob.core.windows.net" in path:
                return await self._download_azure(path)
            else:
                logger.error("Unsupported remote state URI scheme", path=path)
                return None
        except Exception as e:
            logger.error("Failed to download remote Terraform state", path=path, error=str(e))
            return None

    async def _download_s3(self, uri: str) -> bytes:
        import boto3
        # Parse s3://bucket/key
        without_scheme = uri[5:]
        bucket, _, key = without_scheme.partition("/")
        loop = asyncio.get_event_loop()

        kms_key = self.settings.terraform_state_kms_key_arn or None

        def _get_object():
            s3 = boto3.client(
                "s3",
                aws_access_key_id=self.settings.aws_access_key_id or None,
                aws_secret_access_key=self.settings.aws_secret_access_key.get_secret_value() or None,
                region_name=self.settings.aws_default_region,
            )
            kwargs = {"Bucket": bucket, "Key": key}
            if kms_key:
                kwargs["SSECustomerAlgorithm"] = "aws:kms"
                kwargs["SSECustomerKey"] = kms_key
            return s3.get_object(**kwargs)["Body"].read()

        return await loop.run_in_executor(None, _get_object)

    async def _download_gcs(self, uri: str) -> bytes:
        from google.cloud import storage
        without_scheme = uri[5:]
        bucket_name, _, blob_name = without_scheme.partition("/")
        loop = asyncio.get_event_loop()

        def _get_blob():
            client = storage.Client()
            bucket = client.bucket(bucket_name)
            blob   = bucket.blob(blob_name)
            return blob.download_as_bytes()

        return await loop.run_in_executor(None, _get_blob)

    async def _download_azure(self, url: str) -> bytes:
        from azure.storage.blob import BlobClient
        loop = asyncio.get_event_loop()

        def _get_blob():
            client = BlobClient.from_blob_url(url)
            return client.download_blob().readall()

        return await loop.run_in_executor(None, _get_blob)

    # ── Redis advisory lock ───────────────────────────────────────────────────

    async def _acquire_lock(self, key: str) -> bool:
        if self.redis_client is None:
            return True  # No Redis — assume no concurrency issue

        for attempt in range(_LOCK_MAX_RETRIES):
            acquired = await self.redis_client.set(
                key, "1", nx=True, ex=_LOCK_TTL_S
            )
            if acquired:
                return True
            logger.warning(
                "Terraform state lock held by another worker; retrying",
                key=key,
                attempt=attempt + 1,
                delay_s=_LOCK_RETRY_DELAY_S,
            )
            await asyncio.sleep(_LOCK_RETRY_DELAY_S)

        return False

    async def _release_lock(self, key: str) -> None:
        if self.redis_client is None:
            return
        try:
            await self.redis_client.delete(key)
        except Exception as e:
            logger.warning("Failed to release Terraform state lock", key=key, error=str(e))
