"""
GCP Cloud Connector.
Uses google-cloud libraries. Credentials from env via service account JSON.
"""

import asyncio
from typing import Any

import structlog

from app.config import get_settings
from app.connectors.base import CloudConnectorBase
from app.models.compliance import CloudAccount

settings = get_settings()
logger = structlog.get_logger(__name__)


class GCPConnector(CloudConnectorBase):
    """Enumerates GCP resources for compliance checking."""

    def __init__(self, account: CloudAccount) -> None:
        super().__init__(account)
        self._project_id = settings.gcp_project_id or self.account_id

    async def enumerate_resources(self, framework: str) -> list[dict[str, Any]]:
        loop = asyncio.get_event_loop()
        tasks = [
            loop.run_in_executor(None, self._get_gcs_buckets),
            loop.run_in_executor(None, self._get_compute_instances),
            loop.run_in_executor(None, self._get_iam_policies),
            loop.run_in_executor(None, self._get_cloud_sql_instances),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        resources: list[dict[str, Any]] = []
        for r in results:
            if isinstance(r, Exception):
                logger.error("GCP enumeration error", error=str(r))
            else:
                resources.extend(r)  # type: ignore[arg-type]
        return resources

    async def get_resource_config(self, resource_id: str, resource_type: str) -> dict[str, Any]:
        return {}

    def _get_gcs_buckets(self) -> list[dict[str, Any]]:
        try:
            from google.cloud import storage
            client = storage.Client(project=self._project_id)
            resources = []
            for bucket in client.list_buckets():
                b = client.get_bucket(bucket.name)
                config = {
                    "name": bucket.name,
                    "location": bucket.location,
                    "uniform_bucket_level_access": b.iam_configuration.uniform_bucket_level_access_enabled,
                    "versioning_enabled": b.versioning_enabled,
                    "public_access_blocked": b.iam_configuration.public_access_prevention == "enforced",
                }
                resources.append(
                    self._normalize_resource(config, "gcs_bucket", bucket.name)
                )
            return resources
        except Exception as e:
            logger.error("GCS enumeration failed", error=str(e))
            return []

    def _get_compute_instances(self) -> list[dict[str, Any]]:
        try:
            from google.cloud import compute_v1
            client = compute_v1.InstancesClient()
            resources = []
            agg = client.aggregated_list(project=self._project_id)
            for zone, instances in agg:
                for inst in getattr(instances, "instances", []):
                    config = {
                        "name": inst.name,
                        "zone": zone,
                        "status": inst.status,
                        "can_ip_forward": inst.can_ip_forward,
                        "deletion_protection": inst.deletion_protection,
                        "shielded_vm": inst.shielded_instance_config is not None,
                    }
                    resources.append(
                        self._normalize_resource(config, "gcp_compute_instance", inst.name)
                    )
            return resources
        except Exception as e:
            logger.error("GCP Compute enumeration failed", error=str(e))
            return []

    def _get_iam_policies(self) -> list[dict[str, Any]]:
        try:
            from google.cloud import resourcemanager_v3
            client = resourcemanager_v3.ProjectsClient()
            project = client.get_project(name=f"projects/{self._project_id}")
            policy = client.get_iam_policy(resource=project.name)
            bindings_summary = []
            for binding in policy.bindings:
                for member in binding.members:
                    if "allUsers" in member or "allAuthenticatedUsers" in member:
                        bindings_summary.append({
                            "role": binding.role,
                            "member": member,
                            "is_public": True,
                        })
            config = {
                "project_id": self._project_id,
                "has_public_bindings": len(bindings_summary) > 0,
                "public_bindings": bindings_summary,
            }
            return [self._normalize_resource(config, "gcp_iam_policy", self._project_id)]
        except Exception as e:
            logger.error("GCP IAM enumeration failed", error=str(e))
            return []

    def _get_cloud_sql_instances(self) -> list[dict[str, Any]]:
        try:
            import googleapiclient.discovery
            service = googleapiclient.discovery.build("sqladmin", "v1")
            result = service.instances().list(project=self._project_id).execute()
            resources = []
            for inst in result.get("items", []):
                settings_data = inst.get("settings", {})
                config = {
                    "name": inst["name"],
                    "database_version": inst.get("databaseVersion"),
                    "ip_configuration_require_ssl": settings_data.get("ipConfiguration", {}).get("requireSsl", False),
                    "backup_enabled": settings_data.get("backupConfiguration", {}).get("enabled", False),
                    "authorized_networks": settings_data.get("ipConfiguration", {}).get("authorizedNetworks", []),
                }
                resources.append(
                    self._normalize_resource(config, "gcp_cloud_sql", inst["name"])
                )
            return resources
        except Exception as e:
            logger.error("GCP Cloud SQL enumeration failed", error=str(e))
            return []
