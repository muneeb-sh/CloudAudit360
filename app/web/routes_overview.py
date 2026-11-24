from __future__ import annotations

from collections import Counter
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.db import get_db
from app.grc.compliance import framework_scores
from app.models import Finding, Risk, Scan

router = APIRouter(tags=["overview"])
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@router.get("/dashboard")
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    focus = db.query(Scan).filter(Scan.status == "completed").order_by(Scan.id.desc()).first()

    scores = framework_scores(db, focus.id) if focus else []
    risks = (
        db.query(Risk)
        .filter(Risk.status.in_(["open", "in_progress", "accepted"]))
        .order_by(Risk.inherent_score.desc())
        .limit(10)
        .all()
    )

    rating_dist = Counter(
        r.rating
        for r in db.query(Risk).filter(Risk.status.in_(["open", "in_progress", "accepted"])).all()
    )
    findings_by_service: Counter = Counter()
    if focus:
        for f in db.query(Finding).filter(
            Finding.scan_id == focus.id, Finding.status == "FAIL", Finding.source == "custom"
        ).all():
            area = {
                "iam": "Identity",
                "s3": "Storage",
                "sg": "Network",
                "vpc": "Network",
                "cloudtrail": "Logging",
                "guardduty": "Logging",
                "ebs": "Encryption",
                "rds": "Encryption",
                "kms": "Encryption",
            }
            prefix = f.check_id.split("_")[0]
            findings_by_service[area.get(prefix, prefix)] += 1

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "latest": focus,
            "scores": scores,
            "top_risks": risks,
            "rating_dist": dict(rating_dist),
            "findings_by_service": dict(findings_by_service),
        },
    )


@router.get("/trends")
def trends(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    scans = (
        db.query(Scan)
        .filter(Scan.status == "completed")
        .order_by(Scan.id.asc())
        .all()
    )
    labels = []
    compliance_series: dict[str, list[float]] = {"CIS": [], "ISO27001": [], "NIST": []}
    open_risks = []
    for scan in scans:
        when = scan.started_at.strftime("%Y-%m-%d") if scan.started_at else ""
        labels.append(f"#{scan.id} {scan.label or ''} {when}".strip())
        score_map = {s.framework: s.score for s in framework_scores(db, scan.id)}
        for fw in compliance_series:
            compliance_series[fw].append(score_map.get(fw, 0))
        still_open = (
            db.query(Finding)
            .filter(Finding.scan_id == scan.id, Finding.status == "FAIL", Finding.source == "custom")
            .count()
        )
        open_risks.append(still_open)

    return templates.TemplateResponse(
        "trends.html",
        {
            "request": request,
            "user": user,
            "labels": labels,
            "compliance_series": compliance_series,
            "open_risks": open_risks,
        },
    )
