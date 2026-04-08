"""
Continuous scanning module.
Orchestrates cloud resource enumeration and CaC evaluation.
Celery tasks for periodic and event-driven scanning.
"""

import asyncio
from datetime import datetime, timezone
from typing import Any

import structlog
from celery import shared_task
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.connectors.base import CloudConnectorBase
from app.connectors.aws_connector import AWSConnector
from app.connectors.azure_connector import AzureConnector
from app.connectors.gcp_connector import GCPConnector
from app.connectors.terraform_connector import TerraformConnector
from app.core.cac_engine import CaCEngine
from app.core.policy_loader import PolicyLoader
from app.core.evidence import EvidenceManager
from app.models.compliance import CloudAccount, ScanResult, ComplianceCheck
from app.models.database import AsyncSessionLocal

settings = get_settings()
logger = structlog.get_logger(__name__)

CONNECTOR_MAP: dict[str, type[CloudConnectorBase]] = {
    "aws": AWSConnector,
    "azure": AzureConnector,
    "gcp": GCPConnector,
    # Terraform connector: parses .tfstate / terraform show -json for drift detection.
    # Enabled when TERRAFORM_MODE != '' and account.provider == 'terraform'.
    "terraform": TerraformConnector,
}


def _merge_resources(
    sdk_resources: list[dict],
    tf_resources: list[dict],
) -> list[dict]:
    """
    Merge SDK-enumerated resources with Terraform-declared resources.

    Deduplication rule:
    - If the same resource_id exists in both SDK and TF output, the SDK config
      wins for the 'config' field (live state) so compliance checks run against
      the actual cloud state.
    - The TF-declared attributes are preserved in 'terraform_declared_config'
      on the merged record for downstream drift detection.
    - TF-only resources (not yet created in the cloud, or orphaned) are included
      as-is so drift policies can flag them.
    """
    sdk_by_id: dict[str, dict] = {r["resource_id"]: r for r in sdk_resources}

    for tf_res in tf_resources:
        rid = tf_res["resource_id"]
        if rid in sdk_by_id:
            # SDK record exists — annotate it with the TF-declared config
            sdk_by_id[rid]["terraform_declared_config"] = tf_res.get(
                "terraform_declared_config", tf_res.get("config", {})
            )
        else:
            # TF-only resource (no live SDK counterpart)
            sdk_by_id[rid] = tf_res

    return list(sdk_by_id.values())


class ScanOrchestrator:
    """
    Orchestrates a full compliance scan:
    1. Enumerate cloud resources via connector
    2. Evaluate each resource with the CaC engine
    3. Persist results + evidence
    """

    def __init__(
        self,
        db: AsyncSession,
        policy_loader: PolicyLoader,
        evidence_manager: EvidenceManager,
    ) -> None:
        self.db = db
        self.policy_loader = policy_loader
        self.engine = CaCEngine(policy_loader)
        self.evidence_manager = evidence_manager

    async def run_scan(
        self,
        account: CloudAccount,
        framework: str,
        triggered_by: str = "scheduled",
        dry_run: bool = False,
        organization_id: int | None = None,
        terraform_state_path: str | None = None,
        terraform_working_dir: str | None = None,
    ) -> ScanResult:
        """Execute a full compliance scan for an account.

        When terraform_state_path or terraform_working_dir is supplied:
        - A TerraformConnector runs alongside (or instead of) the SDK connector.
        - Resources from both are merged: SDK config wins for live compliance;
          TF-declared config is preserved in terraform_declared_config for drift.
        """
        logger.info(
            "Starting scan",
            account_id=account.id,
            organization_id=organization_id,
            framework=framework,
            dry_run=dry_run,
            terraform_state_path=terraform_state_path,
        )

        # Create scan record
        scan = ScanResult(
            account_id=account.id,
            framework=framework,
            started_at=datetime.now(timezone.utc),
            triggered_by=triggered_by,
        )
        self.db.add(scan)
        await self.db.flush()  # get scan.id without full commit

        # ── Enumerate cloud resources via SDK connector ───────────────────────
        connector_cls = CONNECTOR_MAP.get(account.provider.lower())
        resources: list[dict] = []

        if connector_cls and account.provider.lower() != "terraform":
            # Standard SDK connector (AWS / Azure / GCP)
            connector = connector_cls(account)
            resources = await connector.enumerate_resources(framework)
        elif account.provider.lower() == "terraform" and not terraform_state_path and not terraform_working_dir:
            # Pure terraform account with no path override — use settings-level defaults
            connector = TerraformConnector(account_id=str(account.id))
            resources = await connector.enumerate_resources()
        elif not connector_cls:
            logger.warning("No connector for provider", provider=account.provider)
            scan.completed_at = datetime.now(timezone.utc)
            return scan
        else:
            connector = connector_cls(account)
            resources = await connector.enumerate_resources(framework)

        # ── Optionally merge Terraform state resources ────────────────────────
        # Triggered when the scan request carries terraform_state_path or
        # terraform_working_dir (real-time `terraform show -json` wiring).
        if terraform_state_path or terraform_working_dir:
            tf_resources = await self._fetch_terraform_resources(
                account_id=str(account.id),
                state_path=terraform_state_path,
                working_dir=terraform_working_dir,
            )
            resources = _merge_resources(resources, tf_resources)
            logger.info(
                "Merged SDK + Terraform resources",
                sdk_count=len(resources) - len(tf_resources),
                tf_count=len(tf_resources),
                merged_count=len(resources),
            )

        checks: list[ComplianceCheck] = []
        passed = failed = 0

        for resource in resources:
            check_results = await self.engine.evaluate(
                framework, resource.get("resource_type", "all"), resource
            )
            for result in check_results:
                status = result["status"]
                check = ComplianceCheck(
                    scan_id=scan.id,
                    policy_id=result["policy_id"],
                    policy_name=result["policy_name"],
                    framework=result["framework"],
                    resource_id=result.get("resource_id"),
                    resource_type=result.get("resource_type"),
                    status=status,
                    severity=result["severity"],
                    details=result.get("details"),
                    remediation_hint=result.get("remediation_hint"),
                )
                if not dry_run:
                    self.db.add(check)
                    await self.db.flush()
                    # Store evidence
                    await self.evidence_manager.store(check, result)

                if status == "pass":
                    passed += 1
                else:
                    failed += 1
                checks.append(check)

        # Update scan summary
        total = passed + failed
        scan.total_checks = total
        scan.passed_checks = passed
        scan.failed_checks = failed
        scan.compliance_score = round((passed / total * 100) if total > 0 else 0.0, 2)
        scan.completed_at = datetime.now(timezone.utc)

        if not dry_run:
            await self.db.flush()

        logger.info(
            "Scan completed",
            scan_id=scan.id,
            total=total,
            passed=passed,
            failed=failed,
            score=scan.compliance_score,
        )
        await self.engine.close()
        return scan

    # ── Terraform resource fetching ───────────────────────────────────────────

    async def _fetch_terraform_resources(
        self,
        account_id: str,
        state_path: str | None,
        working_dir: str | None,
    ) -> list[dict]:
        """Create the right TerraformConnector variant and enumerate resources."""
        from app.connectors.terraform_connector import TerraformConnector

        if working_dir or (state_path and state_path.lower() == "binary"):
            # Real-time: run `terraform show -json` in the working directory
            resolved_dir = working_dir or "."
            tf = TerraformConnector.from_working_dir(
                working_dir=resolved_dir,
                account_id=account_id,
            )
        elif state_path:
            # Parse a local .tfstate file or download from a remote URI
            tf = TerraformConnector(
                state_path=state_path,
                account_id=account_id,
            )
        else:
            return []

        try:
            return await tf.enumerate_resources()
        except Exception as exc:
            logger.error("Terraform resource fetch failed", error=str(exc))
            return []  # fail-open: continue with SDK resources only


# ---- Celery Tasks ----

@shared_task(name="tasks.run_scheduled_scan", bind=True, max_retries=3)
def run_scheduled_scan(
    self,
    account_id: int,
    framework: str = "all",
    organization_id: int | None = None,
    terraform_state_path: str | None = None,
    terraform_working_dir: str | None = None,
) -> dict[str, Any]:
    """
    Celery task: run a compliance scan for a cloud account.

    organization_id is propagated from the API layer so that
    background scan results can be attributed to the correct org.

    terraform_state_path / terraform_working_dir enable real-time
    Terraform state ingestion alongside the SDK connector scan.
    """
    try:
        return asyncio.run(
            _async_scheduled_scan(
                account_id, framework, organization_id,
                terraform_state_path=terraform_state_path,
                terraform_working_dir=terraform_working_dir,
            )
        )
    except Exception as exc:
        logger.error(
            "Scan task failed",
            account_id=account_id,
            organization_id=organization_id,
            error=str(exc),
        )
        raise self.retry(exc=exc, countdown=60)


async def _async_scheduled_scan(
    account_id: int,
    framework: str,
    organization_id: int | None = None,
    terraform_state_path: str | None = None,
    terraform_working_dir: str | None = None,
) -> dict[str, Any]:
    from app.models.database import engine
    # CRITICAL: Force the SQLAlchemy async engine to drop old connections tied
    # to dead event loops from previous Celery task runs.
    await engine.dispose()

    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        result = await db.execute(
            select(CloudAccount).where(CloudAccount.id == account_id)
        )
        account = result.scalar_one_or_none()
        if not account:
            return {"error": f"Account {account_id} not found"}

        # Validate org ownership — ensure account belongs to the dispatching org
        if organization_id is not None and account.organization_id != organization_id:
            logger.warning(
                "Scan task org mismatch — account does not belong to dispatching org",
                account_id=account_id,
                account_org=account.organization_id,
                dispatched_org=organization_id,
            )
            return {
                "error": "Account does not belong to the specified organization",
                "account_id": account_id,
                "organization_id": organization_id,
            }

        policy_loader = PolicyLoader()
        evidence_manager = EvidenceManager()
        orchestrator = ScanOrchestrator(db, policy_loader, evidence_manager)
        scan = await orchestrator.run_scan(
            account,
            framework,
            organization_id=organization_id,
            terraform_state_path=terraform_state_path,
            terraform_working_dir=terraform_working_dir,
        )
        await db.commit()
        return {
            "scan_id":          scan.id,
            "compliance_score": scan.compliance_score,
            "total_checks":     scan.total_checks,
            "organization_id":  organization_id,
        }
