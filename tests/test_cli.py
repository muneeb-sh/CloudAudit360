from click.testing import CliRunner

from app.cli import NO_CREDS_MSG, cli
from app.db import Base, SessionLocal, engine
from app.models import Report, Scan


def test_scan_without_credentials_exits_cleanly():
    result = CliRunner().invoke(cli, ["scan"])
    assert result.exit_code == 1
    assert NO_CREDS_MSG in result.output
    assert "Traceback" not in result.output
    assert not isinstance(result.exception, Exception) or isinstance(result.exception, SystemExit)


def test_scan_with_unknown_profile_exits_cleanly():
    result = CliRunner().invoke(cli, ["scan", "--profile", "does-not-exist"])
    assert result.exit_code == 1
    assert NO_CREDS_MSG in result.output


def test_init_requires_admin_password(monkeypatch):
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "admin_password", "")
    result = CliRunner().invoke(cli, ["init"])
    assert result.exit_code == 1
    assert "ADMIN_PASSWORD is not set" in result.output


def test_report_defaults_to_latest_completed_scan():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        db.add_all([
            Scan(status="completed", label="old"),
            Scan(status="completed", label="new"),
            Scan(status="failed", label="broken"),
        ])
        db.commit()
        latest_id = db.query(Scan).filter(Scan.label == "new").one().id
    finally:
        db.close()

    result = CliRunner().invoke(cli, ["report"])
    assert result.exit_code == 0, result.output
    assert f"Report for scan {latest_id}:" in result.output

    db = SessionLocal()
    try:
        assert db.query(Report).one().scan_id == latest_id
    finally:
        db.close()


def test_report_with_no_scans_is_friendly():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    result = CliRunner().invoke(cli, ["report"])
    assert result.exit_code == 1
    assert "No completed scans yet" in result.output
