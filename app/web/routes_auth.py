from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import (
    SESSION_COOKIE,
    authenticate_user,
    create_session_token,
    get_current_user,
    hash_password,
    verify_password,
    write_audit,
)
from app.config import DEFAULT_ADMIN_PASSWORD, get_settings
from app.db import get_db
from app.seed import admin_has_default_password

router = APIRouter(tags=["auth"])
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
settings = get_settings()

MIN_PASSWORD_LENGTH = 8


def _login_context(request: Request, db: Session, **extra) -> dict:
    return {
        "request": request,
        "user": None,
        "first_run": admin_has_default_password(db),
        "admin_username": settings.admin_username,
        "default_password": DEFAULT_ADMIN_PASSWORD,
        **extra,
    }


@router.get("/login")
def login_page(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse("login.html", _login_context(request, db))


@router.post("/login")
def login_submit(
    request: Request,
    db: Session = Depends(get_db),
    username: str = Form(...),
    password: str = Form(...),
):
    user = authenticate_user(db, username, password)
    if not user:
        return templates.TemplateResponse(
            "login.html",
            _login_context(request, db, error="Invalid credentials"),
            status_code=401,
        )
    token = create_session_token(user.username, user.role)
    write_audit(db, user.username, "login", "user", user.id)
    db.commit()
    target = "/change-password" if user.must_change_password else "/dashboard"
    resp = RedirectResponse(target, status_code=303)
    resp.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        max_age=settings.session_max_age,
    )
    return resp


def _password_problem(user, current: str, new: str, confirm: str) -> str | None:
    if not verify_password(current, user.password_hash):
        return "Current password is incorrect."
    if len(new) < MIN_PASSWORD_LENGTH:
        return f"New password must be at least {MIN_PASSWORD_LENGTH} characters."
    if new != confirm:
        return "New passwords do not match."
    if new == DEFAULT_ADMIN_PASSWORD or new == current:
        return "Choose a new password that is different from the current one."
    return None


@router.get("/change-password")
def change_password_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        "change_password.html",
        {"request": request, "user": user, "min_length": MIN_PASSWORD_LENGTH},
    )


@router.post("/change-password")
def change_password_submit(
    request: Request,
    db: Session = Depends(get_db),
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    problem = _password_problem(user, current_password, new_password, confirm_password)
    if problem:
        return templates.TemplateResponse(
            "change_password.html",
            {"request": request, "user": user, "min_length": MIN_PASSWORD_LENGTH, "error": problem},
            status_code=400,
        )
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    write_audit(db, user.username, "password_change", "user", user.id)
    db.commit()
    return RedirectResponse("/dashboard?msg=Password+changed", status_code=303)


@router.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp
