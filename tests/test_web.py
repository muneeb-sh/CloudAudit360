import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text

from app.config import get_settings
from app.db import Base, SessionLocal, engine, init_db
from app.main import app
from app.models import User
from app.seed import ensure_admin


def _client() -> TestClient:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        ensure_admin(db)
    finally:
        db.close()
    return TestClient(app)


@pytest.fixture
def default_admin(monkeypatch):
    """Fresh database whose admin still has the default admin/admin password."""
    monkeypatch.setattr(get_settings(), "admin_password", "admin")
    return _client


def _admin() -> User:
    db = SessionLocal()
    try:
        return db.query(User).filter(User.username == "admin").one()
    finally:
        db.close()


def test_empty_dashboard_shows_empty_state():
    with _client() as client:
        resp = client.post("/login", data={"username": "admin", "password": "test-password"})
        assert resp.status_code == 200  # followed redirect to /dashboard
        resp = client.get("/dashboard")
        assert resp.status_code == 200
        assert "No scans yet" in resp.text
        assert "python -m app.cli scan" in resp.text


def test_demo_route_is_gone_and_root_goes_to_dashboard():
    with _client() as client:
        assert client.get("/demo", follow_redirects=False).status_code == 404
        resp = client.get("/", follow_redirects=False)
        assert resp.headers["location"] == "/dashboard"


def test_login_page_has_no_default_credentials():
    with _client() as client:
        html = client.get("/login").text
        assert "admin123" not in html
        assert "demo" not in html.lower()
        assert "First launch" not in html  # admin already has a real password


def test_first_launch_hint_shown_while_default_password(default_admin):
    with default_admin() as client:
        assert "First launch" in client.get("/login").text


def test_default_password_forces_change_before_anything_else(default_admin):
    with default_admin() as client:
        resp = client.post(
            "/login", data={"username": "admin", "password": "admin"}, follow_redirects=False
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/change-password"

        for path in ("/dashboard", "/findings", "/admin"):
            resp = client.get(path, follow_redirects=False)
            assert resp.status_code == 303, path
            assert resp.headers["location"] == "/change-password"
        assert client.get("/api/scans").status_code == 403
        assert client.get("/api/scans", auth=("admin", "admin")).status_code == 403
        assert client.get("/change-password").status_code == 200
        assert client.get("/health").status_code == 200


@pytest.mark.parametrize(
    "form, message",
    [
        ({"current_password": "wrong", "new_password": "long-enough-1", "confirm_password": "long-enough-1"},
         "Current password is incorrect"),
        ({"current_password": "admin", "new_password": "short", "confirm_password": "short"},
         "at least 8 characters"),
        ({"current_password": "admin", "new_password": "long-enough-1", "confirm_password": "long-enough-2"},
         "do not match"),
    ],
)
def test_change_password_validation(default_admin, form, message):
    with default_admin() as client:
        client.post("/login", data={"username": "admin", "password": "admin"})
        resp = client.post("/change-password", data=form)
        assert resp.status_code == 400
        assert message in resp.text
        assert _admin().must_change_password is True


def test_change_password_unlocks_dashboard(default_admin):
    with default_admin() as client:
        client.post("/login", data={"username": "admin", "password": "admin"})
        resp = client.post(
            "/change-password",
            data={
                "current_password": "admin",
                "new_password": "a-better-password",
                "confirm_password": "a-better-password",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"].startswith("/dashboard")
        assert _admin().must_change_password is False

        assert client.get("/dashboard").status_code == 200
        assert "First launch" not in client.get("/login").text

        client.get("/logout")
        bad = client.post("/login", data={"username": "admin", "password": "admin"})
        assert bad.status_code == 401
        good = client.post(
            "/login", data={"username": "admin", "password": "a-better-password"},
            follow_redirects=False,
        )
        assert good.headers["location"] == "/dashboard"


def test_app_startup_creates_admin(default_admin):
    Base.metadata.drop_all(bind=engine)
    with TestClient(app):  # lifespan runs init_db + ensure_admin
        pass
    user = _admin()
    assert user.role == "admin"
    assert user.must_change_password is True


def test_init_db_adds_missing_column_to_old_database():
    Base.metadata.drop_all(bind=engine)
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR(64) UNIQUE NOT NULL, "
            "password_hash VARCHAR(255) NOT NULL, role VARCHAR(32) NOT NULL)"
        ))
        conn.execute(text("INSERT INTO users (username, password_hash, role) VALUES ('old', 'x', 'viewer')"))
    init_db()
    assert "must_change_password" in {c["name"] for c in inspect(engine).get_columns("users")}
    db = SessionLocal()
    try:
        assert db.query(User).filter(User.username == "old").one().must_change_password is False
    finally:
        db.close()


@pytest.mark.parametrize("path, text", [
    ("/responsibility", "Shared Responsibility Model"),
    ("/attack-surface", "Internet attack surface"),
])
def test_cloud_pages_render_empty_state(path, text):
    with _client() as client:
        client.post("/login", data={"username": "admin", "password": "test-password"})
        resp = client.get(path)
        assert resp.status_code == 200
        assert text in resp.text
        assert "No scans yet" in resp.text
