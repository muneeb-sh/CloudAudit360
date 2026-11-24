from fastapi.testclient import TestClient

from app.db import Base, SessionLocal, engine
from app.main import app
from app.seed import create_admin


def _client() -> TestClient:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        create_admin(db)
    finally:
        db.close()
    return TestClient(app)


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
