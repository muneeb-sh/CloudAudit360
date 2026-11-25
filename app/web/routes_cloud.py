"""Cloud-security views: Shared Responsibility Model and internet Attack Surface."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.assessment import catalog
from app.auth import get_current_user
from app.db import get_db
from app.models import Asset, Finding, Scan

router = APIRouter(tags=["cloud"])
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _focus_scan(db: Session, scan_id: int | None) -> Scan | None:
    q = db.query(Scan).filter(Scan.status == "completed")
    if scan_id:
        return q.filter(Scan.id == scan_id).first()
    return q.order_by(Scan.id.desc()).first()


def _findings(db: Session, scan: Scan | None) -> list[Finding]:
    return db.query(Finding).filter(Finding.scan_id == scan.id).all() if scan else []


@router.get("/responsibility")
def responsibility(request: Request, db: Session = Depends(get_db), scan: int | None = None):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    focus = _focus_scan(db, scan)
    return templates.TemplateResponse(
        "responsibility.html",
        {
            "request": request,
            "user": user,
            "scan": focus,
            "matrix": catalog.responsibility_matrix(_findings(db, focus)),
        },
    )


@router.get("/attack-surface")
def attack_surface(request: Request, db: Session = Depends(get_db), scan: int | None = None):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    focus = _focus_scan(db, scan)
    return templates.TemplateResponse(
        "attack_surface.html",
        {
            "request": request,
            "user": user,
            "scan": focus,
            "surface": catalog.attack_surface(_findings(db, focus)),
            "public_assets": db.query(Asset).filter(Asset.exposure == "public").count(),
        },
    )
