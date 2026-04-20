"""
GCP Cloud Connector.
Uses google-cloud libraries. Credentials from env via service account JSON.

Enumerates:
  - GCS Buckets             (gcs_bucket)
  - Compute Instances       (gcp_compute_instance)
  - IAM Policies            (gcp_iam_policy)
  - Cloud SQL Instances     (gcp_cloud_sql)
  - Firewall Rules          (gcp_firewall_rule)      ← NEW
  - Audit Log Config        (gcp_audit_log_config)   ← NEW
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
            loop.run_in_executor(None, self._get_firewall_rules),
            loop.run_in_executor(None, self._get_audit_log_config),
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

    # ─────────────────────────────────────────────────────────────────────────
    # GCS Buckets
    # ─────────────────────────────────────────────────────────────────────────
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

    # ─────────────────────────────────────────────────────────────────────────
    # Compute Instances
    # ─────────────────────────────────────────────────────────────────────────
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
                        # Shielded VM specifics
                        "shielded_secure_boot": getattr(
                            inst.shielded_instance_config, "enable_secure_boot", False
                        ) if inst.shielded_instance_config else False,
                        "shielded_vtpm": getattr(
                            inst.shielded_instance_config, "enable_vtpm", False
                        ) if inst.shielded_instance_config else False,
                    }
                    resources.append(
                        self._normalize_resource(config, "gcp_compute_instance", inst.name)
                    )
            return resources
        except Exception as e:
            logger.error("GCP Compute enumeration failed", error=str(e))
            return []

    # ─────────────────────────────────────────────────────────────────────────
    # IAM Policies
    # ─────────────────────────────────────────────────────────────────────────
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

    # ─────────────────────────────────────────────────────────────────────────
    # Cloud SQL Instances
    # ─────────────────────────────────────────────────────────────────────────
    def _get_cloud_sql_instances(self) -> list[dict[str, Any]]:
        try:
            import googleapiclient.discovery
            service = googleapiclient.discovery.build("sqladmin", "v1")
            result = service.instances().list(project=self._project_id).execute()
            resources = []
            for inst in result.get("items", []):
                settings_data = inst.get("settings", {})
                ip_cfg = settings_data.get("ipConfiguration", {})
                authorized_networks = ip_cfg.get("authorizedNetworks", [])
                config = {
                    "name": inst["name"],
                    "database_version": inst.get("databaseVersion"),
                    "ip_configuration_require_ssl": ip_cfg.get("requireSsl", False),
                    "backup_enabled": settings_data.get("backupConfiguration", {}).get("enabled", False),
                    "authorized_networks": authorized_networks,
                    "publicly_accessible": any(
                        n.get("value") == "0.0.0.0/0" for n in authorized_networks
                    ),
                }
                resources.append(
                    self._normalize_resource(config, "gcp_cloud_sql", inst["name"])
                )
            return resources
        except Exception as e:
            logger.error("GCP Cloud SQL enumeration failed", error=str(e))
            return []

    # ─────────────────────────────────────────────────────────────────────────
    # Firewall Rules  [NEW — targets GCP-FW-001]
    # ─────────────────────────────────────────────────────────────────────────
    def _get_firewall_rules(self) -> list[dict[str, Any]]:
        """
        Enumerate VPC firewall rules. Flags any rule that:
          - direction = INGRESS
          - source_ranges includes 0.0.0.0/0 or ::/0
          - allows ALL protocols or all TCP/UDP ports (0-65535)
        """
        try:
            from google.cloud import compute_v1
            client = compute_v1.FirewallsClient()
            resources = []
            for rule in client.list(project=self._project_id):
                source_ranges = list(rule.source_ranges)
                # Note: compute_v1 proto uses I_p_protocol (capital I and P)
                allows = [
                    {"protocol": getattr(a, "I_p_protocol", "") or getattr(a, "ip_protocol", ""), "ports": list(a.ports)}
                    for a in rule.allowed
                ]
                denies = [
                    {"protocol": getattr(d, "I_p_protocol", "") or getattr(d, "ip_protocol", ""), "ports": list(d.ports)}
                    for d in rule.denied
                ]

                # Determine if this is a wide-open ingress rule
                is_all_ingress = (
                    rule.direction == "INGRESS"
                    and ("0.0.0.0/0" in source_ranges or "::/0" in source_ranges)
                    and any(
                        a["protocol"] == "all"
                        or (a["protocol"] in ("tcp", "udp") and not a["ports"])
                        for a in allows
                    )
                )

                config = {
                    "name": rule.name,
                    "direction": rule.direction,
                    "source_ranges": source_ranges,
                    "allowed": allows,
                    "denied": denies,
                    "disabled": rule.disabled,
                    "priority": rule.priority,
                    "allows_all_ingress": is_all_ingress,
                    "allows_public_ingress": (
                        rule.direction == "INGRESS"
                        and ("0.0.0.0/0" in source_ranges or "::/0" in source_ranges)
                        and not rule.disabled
                    ),
                }
                resources.append(
                    self._normalize_resource(config, "gcp_firewall_rule", rule.name)
                )
            return resources
        except Exception as e:
            logger.error("GCP Firewall enumeration failed", error=str(e))
            return []


    # ─────────────────────────────────────────────────────────────────────────
    # Audit Log Config  [NEW — targets GCP-LOG-001]
    # ─────────────────────────────────────────────────────────────────────────
    def _get_audit_log_config(self) -> list[dict[str, Any]]:
        """
        Check project-level IAM audit configuration.
        Flags if DATA_READ or DATA_WRITE audit logs are not enabled
        for critical services (storage, compute, cloudresourcemanager).
        """
        try:
            from google.cloud import resourcemanager_v3
            client = resourcemanager_v3.ProjectsClient()
            project = client.get_project(name=f"projects/{self._project_id}")
            policy = client.get_iam_policy(resource=project.name)

            # Parse audit configs from the policy
            audit_configs: dict[str, set[str]] = {}
            for ac in policy.audit_configs:
                service = ac.service  # e.g. "storage.googleapis.com"
                log_types = {lc.log_type.name for lc in ac.audit_log_configs}
                audit_configs[service] = log_types

            # Services we care about
            critical_services = [
                "storage.googleapis.com",
                "compute.googleapis.com",
                "cloudresourcemanager.googleapis.com",
                "iam.googleapis.com",
            ]
            required_log_types = {"DATA_READ", "DATA_WRITE", "ADMIN_READ"}

            findings = []
            for svc in critical_services:
                configured = audit_configs.get(svc, set())
                missing = required_log_types - configured
                findings.append({
                    "service": svc,
                    "configured_log_types": list(configured),
                    "missing_log_types": list(missing),
                    "fully_configured": len(missing) == 0,
                })

            # A single resource representing the project audit posture
            all_configured = all(f["fully_configured"] for f in findings)
            config = {
                "project_id": self._project_id,
                "audit_log_findings": findings,
                "all_critical_services_audited": all_configured,
                "audit_logs_enabled": all_configured,  # key field for policy checks
            }
            return [self._normalize_resource(
                config, "gcp_audit_log_config", f"{self._project_id}-audit-log"
            )]
        except Exception as e:
            logger.error("GCP Audit Log config enumeration failed", error=str(e))
            return []
