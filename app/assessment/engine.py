"""Assessment engine: run the built-in checks against collected snapshots."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from sqlalchemy.orm import Session

from app.assessment.registry import get_registered_checks
from app.models import Asset, Finding, Scan, Snapshot
from app.schemas import NormalizedFinding

logger = logging.getLogger(__name__)

# Check-id prefix -> collector service the check reads from.
CHECK_SERVICE = {
    "iam": "iam",
    "s3": "s3",
    "sg": "ec2",
    "vpc": "ec2",
    "ebs": "ec2",
    "ec2": "ec2",
    "cloudtrail": "cloudtrail",
    "guardduty": "guardduty",
    "kms": "kms",
    "rds": "rds",
}


def _index_snapshots(snapshots: list[Snapshot]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = defaultdict(dict)
    for snap in snapshots:
        indexed[snap.service][snap.resource_id] = snap.config_json
    return indexed


def _ensure_checks_loaded() -> None:
    # Importing the package registers all decorated checks
    import app.assessment.checks  # noqa: F401


def run_custom_checks(snapshot_index: dict[str, dict[str, Any]]) -> list[NormalizedFinding]:
    _ensure_checks_loaded()
    findings: list[NormalizedFinding] = []
    for check_id, fn in get_registered_checks().items():
        try:
            findings.extend(fn(snapshot_index))
        except Exception as exc:  # noqa: BLE001
            logger.exception("Check %s failed: %s", check_id, exc)
            findings.append(
                NormalizedFinding(
                    check_id=check_id,
                    source="custom",
                    title=f"Check error: {check_id}",
                    description=str(exc),
                    severity="medium",
                    status="ERROR",
                    evidence={"error": str(exc)},
                    remediation="Investigate check failure.",
                )
            )
    return findings


def persist_findings(
    db: Session,
    scan: Scan,
    normalized: list[NormalizedFinding],
) -> list[Finding]:
    asset_by_arn = {a.arn: a for a in db.query(Asset).all()}
    saved: list[Finding] = []
    for nf in normalized:
        asset_id = None
        if nf.asset_arn:
            if nf.asset_arn not in asset_by_arn:
                # Account/region settings (GuardDuty, EBS default, VPCs) have no collected
                # asset row; create one so each gets its own risk-register entry.
                parts = nf.asset_arn.split(":")
                service = parts[2] if len(parts) > 2 else "aws"
                asset = Asset(
                    arn=nf.asset_arn,
                    type=f"{service}-setting",
                    service=service,
                    name=parts[-1] or nf.asset_arn,
                    region=(parts[3] if len(parts) > 3 else "") or "global",
                )
                db.add(asset)
                db.flush()
                asset_by_arn[nf.asset_arn] = asset
            asset_id = asset_by_arn[nf.asset_arn].id
        row = Finding(
            scan_id=scan.id,
            check_id=nf.check_id,
            source=nf.source,
            asset_id=asset_id,
            title=nf.title,
            description=nf.description,
            severity=nf.severity,
            status=nf.status,
            evidence_json=nf.evidence,
            remediation=nf.remediation,
        )
        db.add(row)
        saved.append(row)
    db.flush()
    return saved


def apply_collect_errors(
    findings: list[NormalizedFinding], collect_errors: dict[str, dict]
) -> list[NormalizedFinding]:
    """Turn collection failures into ERROR findings so missing data never reads as PASS.

    Service failed completely -> the check's findings are replaced by one ERROR.
    Failed in some regions -> real per-resource findings are kept, "nothing found"
    placeholders (no asset) are dropped, and one ERROR is added.
    """
    if not collect_errors:
        return findings
    out: list[NormalizedFinding] = []
    error_checks: dict[str, str] = {}
    for nf in findings:
        service = CHECK_SERVICE.get(nf.check_id.split("_")[0])
        err = collect_errors.get(service) if service else None
        if err is None:
            out.append(nf)
            continue
        error_checks[nf.check_id] = service
        if not err["complete"] and nf.asset_arn:
            out.append(nf)
    for check_id, service in error_checks.items():
        err = collect_errors[service]
        out.append(
            NormalizedFinding(
                check_id=check_id,
                source="custom",
                title=f"Could not assess {check_id}: {service} collection failed",
                description="; ".join(err["messages"])[:2000],
                severity="medium",
                status="ERROR",
                evidence={"service": service, "errors": err["messages"]},
                remediation="Grant the scanning identity SecurityAudit + ViewOnlyAccess, then re-scan.",
            )
        )
    return out


def run_assessment(
    db: Session,
    scan: Scan,
    snapshots: list[Snapshot],
    collect_errors: dict[str, dict] | None = None,
) -> list[Finding]:
    indexed = _index_snapshots(snapshots)
    normalized = apply_collect_errors(run_custom_checks(indexed), collect_errors or {})
    return persist_findings(db, scan, normalized)
