from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from app.auth import user_from_request
from app.config import EVIDENCE_DIR, REPORT_DIR
from app.db import SessionLocal, init_db
from app.seed import ensure_admin, seed_reference

TEMPLATES_DIR = Path(__file__).parent / "web" / "templates"
STATIC_DIR = Path(__file__).parent / "web" / "static"

scheduler = BackgroundScheduler()


def _expire_exceptions_job() -> None:
    from app.grc.register import expire_exceptions

    db = SessionLocal()
    try:
        expire_exceptions(db)
        db.commit()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    init_db()
    db = SessionLocal()
    try:
        seed_reference(db)
        ensure_admin(db)
    finally:
        db.close()
    if not scheduler.running:
        scheduler.add_job(_expire_exceptions_job, "interval", hours=6, id="expire_exceptions")
        scheduler.start()
    yield
    if scheduler.running:
        scheduler.shutdown(wait=False)


app = FastAPI(
    title="CloudAudit360",
    description="Read-only AWS security and compliance auditing.",
    version="1.0.0",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Paths a user with a pending password change may still reach.
_PASSWORD_CHANGE_ALLOWED = ("/login", "/logout", "/change-password", "/static", "/health")


def _needs_password_change(request: Request) -> bool:
    db = SessionLocal()
    try:
        user = user_from_request(request, db)
        return bool(user and user.must_change_password)
    finally:
        db.close()


@app.middleware("http")
async def force_password_change(request: Request, call_next):
    """Until the default password is replaced, only the change-password page is usable."""
    path = request.url.path
    if not path.startswith(_PASSWORD_CHANGE_ALLOWED) and await run_in_threadpool(
        _needs_password_change, request
    ):
        if path.startswith("/api"):
            return JSONResponse({"detail": "Password change required"}, status_code=403)
        return RedirectResponse("/change-password", status_code=303)
    return await call_next(request)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def root():
    return RedirectResponse("/dashboard")


def _register_routers() -> None:
    from app.web import (
        routes_admin,
        routes_api,
        routes_auth,
        routes_controls,
        routes_findings,
        routes_overview,
        routes_reports,
        routes_reviews,
        routes_risks,
        routes_scans,
    )

    app.include_router(routes_auth.router)
    app.include_router(routes_overview.router)
    app.include_router(routes_findings.router)
    app.include_router(routes_controls.router)
    app.include_router(routes_risks.router)
    app.include_router(routes_scans.router)
    app.include_router(routes_reviews.router)
    app.include_router(routes_reports.router)
    app.include_router(routes_admin.router)
    app.include_router(routes_api.router, prefix="/api")


_register_routers()
