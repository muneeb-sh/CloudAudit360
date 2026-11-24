"""Test setup: isolated temp database and no real AWS credentials (never touches real data or AWS)."""

import os
import tempfile
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix="cloudaudit360_test_"))
# Must be set before any `app` import: app.db builds its engine at import time.
os.environ["DATABASE_URL"] = f"sqlite:///{(_tmp / 'test.db').as_posix()}"
os.environ["SECRET_KEY"] = "test-secret"
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "test-password"
os.environ["AWS_REGIONS"] = ""
for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
            "AWS_DEFAULT_PROFILE", "AWS_DEFAULT_REGION", "AWS_REGION"):
    os.environ.pop(var, None)
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
os.environ["AWS_CONFIG_FILE"] = str(_tmp / "no-aws-config")
os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(_tmp / "no-aws-credentials")

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_output_dirs(tmp_path, monkeypatch):
    """Keep evidence and report files out of the project folder."""
    monkeypatch.setattr("app.collector.aws_collector.EVIDENCE_DIR", tmp_path / "evidence")
    monkeypatch.setattr("app.reporting.builder.REPORT_DIR", tmp_path / "reports")
