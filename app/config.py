import logging
import secrets
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
EVIDENCE_DIR = BASE_DIR / "evidence"
REPORT_DIR = BASE_DIR / "reports" / "output"
SECRET_KEY_FILE = BASE_DIR / ".secret_key"

# First-run dashboard password. An admin created with it must change it at first sign-in.
DEFAULT_ADMIN_PASSWORD = "admin"


class Settings(BaseSettings):
    """All settings are optional; `.env` is only needed to override the defaults."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = f"sqlite:///{BASE_DIR / 'cloudaudit360.db'}"
    secret_key: str = ""
    admin_username: str = "admin"
    admin_password: str = DEFAULT_ADMIN_PASSWORD
    # AWS credentials come from the standard boto3 chain; these only pick profile/regions.
    aws_profile: str | None = None
    aws_regions: str = ""  # comma separated, e.g. "us-east-1,eu-west-1"
    session_max_age: int = 60 * 60 * 12  # 12 hours


def _persistent_secret_key() -> str:
    """Read the generated secret key, or create it once so sessions survive restarts."""
    try:
        key = SECRET_KEY_FILE.read_text(encoding="utf-8").strip()
        if key:
            return key
    except OSError:
        pass
    key = secrets.token_urlsafe(32)
    try:
        SECRET_KEY_FILE.write_text(key, encoding="utf-8")
    except OSError:
        logging.getLogger(__name__).warning(
            "Could not write %s; using a temporary key (dashboard sessions reset on restart).",
            SECRET_KEY_FILE,
        )
    return key


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if not settings.secret_key:
        settings.secret_key = _persistent_secret_key()
    if not settings.admin_password:
        settings.admin_password = DEFAULT_ADMIN_PASSWORD
    return settings
