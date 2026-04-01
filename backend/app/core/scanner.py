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
}


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
    ) -> ScanResult:
        """Execute a full compliance scan for an account."""
        logger.info(
            "Starting scan",
            account_id=account.id,
            framework=framework,
            dry_run=dry_run,
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

        # Instantiate the right connector
        connector_cls = CONNECTOR_MAP.get(account.provider.lower())
        if not connector_cls:
            logger.warning("No connector for provider", provider=account.provider)
            scan.completed_at = datetime.now(timezone.utc)
            return scan

        connector = connector_cls(account)
        resources = await connector.enumerate_resources(framework)

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


# ---- Celery Tasks ----

@shared_task(name="tasks.run_scheduled_scan", bind=True, max_retries=3)
def run_scheduled_scan(self, account_id: int, framework: str = "all") -> dict[str, Any]:
    """Celery task: run a compliance scan for a cloud account."""
    try:
        return asyncio.run(_async_scheduled_scan(account_id, framework))
    except Exception as exc:
        logger.error("Scan task failed", account_id=account_id, error=str(exc))
        raise self.retry(exc=exc, countdown=60)


async def _async_scheduled_scan(account_id: int, framework: str) -> dict[str, Any]:
    from app.models.database import engine
    # CRITICAL: Force the SQLAlchemy async engine to drop old connections tied
    # to dead event loops from previous Celery task runs
    await engine.dispose()
    
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        result = await db.execute(
            select(CloudAccount).where(CloudAccount.id == account_id)
        )
        account = result.scalar_one_or_none()
        if not account:
            return {"error": f"Account {account_id} not found"}

        policy_loader = PolicyLoader()
        evidence_manager = EvidenceManager()
        orchestrator = ScanOrchestrator(db, policy_loader, evidence_manager)
        scan = await orchestrator.run_scan(account, framework)
        await db.commit()
        return {
            "scan_id": scan.id,
            "compliance_score": scan.compliance_score,
            "total_checks": scan.total_checks,
        }
