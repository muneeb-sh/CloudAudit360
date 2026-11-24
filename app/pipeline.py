"""End-to-end pipeline: Collect -> Assess -> Map -> Score -> Register -> Reviews."""

from __future__ import annotations

import logging
from datetime import datetime

import boto3
from sqlalchemy.orm import Session

from app.assessment.engine import run_assessment
from app.collector.aws_collector import Progress, collect, resolve_regions
from app.config import get_settings
from app.grc.compliance import evaluate_controls
from app.grc.register import expire_exceptions, update_risk_register
from app.grc.review import generate_review_tasks
from app.models import Scan

logger = logging.getLogger(__name__)


def aws_session(profile: str | None = None) -> boto3.Session:
    """boto3 session from the standard credential chain (profile, env vars, role)."""
    return boto3.Session(profile_name=profile or get_settings().aws_profile or None)


def caller_identity(session: boto3.Session) -> dict:
    """sts:GetCallerIdentity; raises botocore errors when credentials are missing/invalid."""
    return session.client("sts", region_name=session.region_name or "us-east-1").get_caller_identity()


def run_scan(
    db: Session,
    *,
    label: str | None = None,
    triggered_by: str = "system",
    session: boto3.Session | None = None,
    regions: list[str] | None = None,
    identity: dict | None = None,
    progress: Progress = lambda _msg: None,
) -> Scan:
    session = session or aws_session()
    identity = identity or caller_identity(session)
    regions = regions or resolve_regions(session)
    account_id = identity["Account"]

    expire_exceptions(db)
    scan = Scan(
        status="running",
        label=label or f"AWS {account_id}",
        triggered_by=triggered_by,
        started_at=datetime.utcnow(),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        progress(f"Regions: {', '.join(regions)}")
        snapshots, errors = collect(
            db, scan, session=session, regions=regions, account_id=account_id, progress=progress
        )
        db.commit()

        run_assessment(db, scan, snapshots, collect_errors=errors)
        db.commit()

        # Risks first so compliance can honor exceptions tied to risks
        update_risk_register(db, scan.id)
        db.commit()

        evaluate_controls(db, scan.id)
        db.commit()

        generate_review_tasks(db)
        db.commit()

        scan.status = "completed"
        scan.finished_at = datetime.utcnow()
        db.commit()
        db.refresh(scan)
        logger.info("Scan %s completed (%s snapshots)", scan.id, len(snapshots))
        return scan
    except Exception as exc:  # noqa: BLE001
        logger.exception("Scan failed: %s", exc)
        db.rollback()
        scan.status = "failed"
        scan.finished_at = datetime.utcnow()
        db.commit()
        raise
