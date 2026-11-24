import pytest
from click.testing import CliRunner

from app.auth import verify_password
from app.cli import NO_CREDS_MSG, cli
from app.db import Base, SessionLocal, engine
from app.models import Report, Scan, User


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


def _fresh_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def test_init_creates_default_admin_without_env(monkeypatch):
    from app.config import get_settings

    _fresh_db()
    monkeypatch.setattr(get_settings(), "admin_password", "admin")
    result = CliRunner().invoke(cli, ["init"])
    assert result.exit_code == 0, result.output
    assert "created with password 'admin'" in result.output
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "admin").one()
        assert user.role == "admin"
        assert user.must_change_password is True
        assert verify_password("admin", user.password_hash)
    finally:
        db.close()

    again = CliRunner().invoke(cli, ["init"])
    assert again.exit_code == 0
    assert "already exists" in again.output


def test_init_with_custom_password_does_not_force_change():
    _fresh_db()
    result = CliRunner().invoke(cli, ["init"])
    assert result.exit_code == 0, result.output
    db = SessionLocal()
    try:
        assert db.query(User).filter(User.username == "admin").one().must_change_password is False
    finally:
        db.close()


def test_reset_admin_restores_default_and_forces_change():
    _fresh_db()
    CliRunner().invoke(cli, ["init"])
    result = CliRunner().invoke(cli, ["reset-admin", "--yes"])
    assert result.exit_code == 0, result.output
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "admin").one()
        assert user.must_change_password is True
        assert verify_password("admin", user.password_hash)
    finally:
        db.close()


def test_reset_admin_can_be_cancelled():
    _fresh_db()
    result = CliRunner().invoke(cli, ["reset-admin"], input="n\n")
    assert result.exit_code == 1
    assert "Aborted" in result.output


@pytest.mark.parametrize("args", [[], ["help"], ["--help"], ["-h"]])
def test_help_lists_commands(args):
    result = CliRunner().invoke(cli, args)
    # Bare `cli` prints help too; click >= 8.2 exits 2 for that, older versions exit 0.
    expected = (0, 2) if not args else (0,)
    assert result.exit_code in expected, result.output
    for name in ("serve", "scan", "report", "init", "reset-admin", "help"):
        assert name in result.output
    assert "Quick start" in result.output
    assert "seed" not in result.output.split("Commands:")[1]


def test_help_for_subcommand_shows_options_and_examples():
    result = CliRunner().invoke(cli, ["help", "scan"])
    assert result.exit_code == 0, result.output
    assert "--region" in result.output
    assert "Examples:" in result.output
    assert "python -m app.cli scan --label prod" in result.output


def test_help_for_unknown_command():
    result = CliRunner().invoke(cli, ["help", "nope"])
    assert result.exit_code == 2
    assert "Unknown command 'nope'" in result.output


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
