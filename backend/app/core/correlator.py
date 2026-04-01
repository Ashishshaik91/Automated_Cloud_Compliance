"""
Correlator — links Violations to DSPM Findings using normalised resource URNs.

Matching strategy (in priority order):
1. Exact URN match         : violation.resource_urn == dspm.data_store_urn
2. Resource-ID substring   : the resource_id segment of the violation URN is
                             contained in (or equals) the data_store_id — handles
                             short names like "pii-production-lake" vs full ARNs.

For every matched pair a DSPMCorrelation row is created (idempotent).
The combined_risk is set to the higher of the two individual risk levels.
"""

from __future__ import annotations

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dspm import DSPMCorrelation, DSPMFinding, RiskLevel
from app.models.violations import Violation

logger = structlog.get_logger(__name__)

_RANK = {
    RiskLevel.CRITICAL: 4,
    RiskLevel.HIGH:     3,
    RiskLevel.MEDIUM:   2,
    RiskLevel.LOW:      1,
    RiskLevel.NONE:     0,
}


def _combined(viol_sev: str, dspm_lvl: str) -> str:
    """Return the higher of violation severity and DSPM risk_level."""
    sev_rank = _RANK.get(RiskLevel(viol_sev) if viol_sev in _RANK else RiskLevel.LOW, 1)
    dspm_rank = _RANK.get(RiskLevel(dspm_lvl) if dspm_lvl in _RANK else RiskLevel.NONE, 0)
    return list(_RANK.keys())[4 - max(sev_rank, dspm_rank)].value


async def run_correlator(db: AsyncSession) -> int:
    """
    Match all OPEN violations against DSPM findings.
    Idempotent: skips pairs that already have a DSPMCorrelation row.
    Returns number of new correlations created.
    """
    violations = (await db.execute(
        select(Violation).where(Violation.status == "open")
    )).scalars().all()

    findings = (await db.execute(select(DSPMFinding))).scalars().all()

    # Build quick-lookup maps
    dspm_by_urn: dict[str, DSPMFinding]     = {f.data_store_urn: f for f in findings}
    dspm_by_id:  dict[str, list[DSPMFinding]] = {}
    for f in findings:
        key = f.data_store_id.lower()
        dspm_by_id.setdefault(key, []).append(f)

    # Existing correlations — avoid duplicates
    existing_pairs: set[tuple[int, int]] = set(
        (row.dspm_finding_id, row.violation_id)
        for row in (await db.execute(select(DSPMCorrelation))).scalars().all()
    )

    created = 0
    for v in violations:
        matched: list[DSPMFinding] = []

        # Strategy 1 — exact URN
        if v.resource_urn in dspm_by_urn:
            matched.append(dspm_by_urn[v.resource_urn])

        # Strategy 2 — resource_id substring match
        v_rid = v.resource_id.lower()
        for store_id, store_list in dspm_by_id.items():
            if v_rid == store_id or v_rid in store_id or store_id in v_rid:
                for s in store_list:
                    if s not in matched:
                        matched.append(s)

        for dspm in matched:
            pair = (dspm.id, v.id)
            if pair in existing_pairs:
                continue

            classes = dspm.classifications
            risk_label = (
                f"{v.rule_id} → {dspm.data_store_name} "
                f"[{classes}] | {v.severity.upper()} violation exposes "
                f"{'publicly accessible ' if dspm.public_access else ''}"
                f"{dspm.encryption_status} data store"
            )
            combined = _combined(v.severity, dspm.risk_level)

            db.add(DSPMCorrelation(
                dspm_finding_id=dspm.id,
                violation_id=v.id,
                risk_label=risk_label,
                combined_risk=combined,
            ))
            existing_pairs.add(pair)
            created += 1

    await db.flush()
    logger.info("Correlator run complete", new_correlations=created)
    return created
