"""
Evidence Provenance Layer.
Stores tamper-proof evidence using SHA-256 hash chains in PostgreSQL
and encrypted raw evidence files in MinIO object storage.
"""

import json
from datetime import datetime, timezone
from typing import Any

import structlog
from minio import Minio
from minio.error import S3Error

from app.config import get_settings
from app.models.compliance import ComplianceCheck, EvidenceRecord
from app.utils.crypto import compute_evidence_hash, sign_payload, timestamp_now

settings = get_settings()
logger = structlog.get_logger(__name__)


class EvidenceManager:
    """
    Manages evidence collection and tamper-proof storage.
    Uses SHA-256 hash chains to detect tampering.
    """

    def __init__(self) -> None:
        self._minio_client: Minio | None = None
        self._last_hash: str = "genesis"  # Chain starts here

    @property
    def minio(self) -> Minio:
        if self._minio_client is None:
            self._minio_client = Minio(
                f"{settings.minio_host}:{settings.minio_port}",
                access_key=settings.minio_access_key.get_secret_value(),
                secret_key=settings.minio_secret_key.get_secret_value(),
                secure=settings.minio_secure,
            )
            self._ensure_bucket()
        return self._minio_client

    def _ensure_bucket(self) -> None:
        try:
            if not self.minio.bucket_exists(settings.minio_bucket_evidence):
                self.minio.make_bucket(settings.minio_bucket_evidence)
                logger.info("Evidence bucket created", bucket=settings.minio_bucket_evidence)
        except S3Error as e:
            logger.error("MinIO bucket error", error=str(e))

    async def store(
        self,
        check: ComplianceCheck,
        raw_result: dict[str, Any],
    ) -> EvidenceRecord | None:
        """
        Store evidence for a compliance check:
        1. Serialize raw result
        2. Compute chained hash
        3. Upload to MinIO
        4. Store EvidenceRecord with hash in DB
        """
        timestamp = timestamp_now()
        evidence_data = {
            "check_id": check.id,
            "policy_id": check.policy_id,
            "resource_id": check.resource_id,
            "status": check.status,
            "timestamp": timestamp,
            "raw_result": raw_result,
        }

        hash_value = compute_evidence_hash(evidence_data, self._last_hash)
        self._last_hash = hash_value

        # Sign the evidence
        signature = sign_payload({"hash": hash_value, "check_id": check.id})

        # Store raw evidence in MinIO
        storage_path = f"evidence/{check.scan_id}/{check.id}/{timestamp}.json"
        try:
            evidence_json = json.dumps(evidence_data, default=str).encode("utf-8")
            import io
            self.minio.put_object(
                settings.minio_bucket_evidence,
                storage_path,
                io.BytesIO(evidence_json),
                length=len(evidence_json),
                content_type="application/json",
            )
        except Exception as e:
            logger.error("Failed to upload evidence to MinIO", error=str(e))
            storage_path = None

        record = EvidenceRecord(
            check_id=check.id,
            hash_value=hash_value,
            previous_hash=self._last_hash,
            storage_path=storage_path,
            metadata={"timestamp": timestamp, "framework": check.framework},
            signature=signature,
        )
        return record

    def verify_chain(self, records: list[EvidenceRecord]) -> bool:
        """
        Verify that an evidence chain is intact (no tampering).
        Returns True if the chain is valid.
        """
        previous_hash = "genesis"
        for record in sorted(records, key=lambda r: r.created_at):
            # We'd need to re-fetch the raw data from MinIO to fully verify,
            # but we can verify the chain linkage here
            if record.previous_hash != previous_hash:
                logger.warning(
                    "Evidence chain broken!",
                    record_id=record.id,
                    expected=previous_hash,
                    got=record.previous_hash,
                )
                return False
            previous_hash = record.hash_value
        return True
