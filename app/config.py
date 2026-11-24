import logging
import secrets
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
EVIDENCE_DIR = BASE_DIR / "evidence"
REPORT_DIR = BASE_DIR / "reports" / "output"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = f"sqlite:///{BASE_DIR / 'cloudaudit360.db'}"
    secret_key: str = ""
    admin_username: str = "admin"
    admin_password: str = ""
    # AWS credentials come from the standard boto3 chain; these only pick profile/regions.
    aws_profile: str | None = None
    aws_regions: str = ""  # comma separated, e.g. "us-east-1,eu-west-1"
    session_max_age: int = 60 * 60 * 12  # 12 hours


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if not settings.secret_key:
        logging.getLogger(__name__).warning(
            "SECRET_KEY is not set; using a random key (dashboard sessions reset on restart)."
        )
        settings.secret_key = secrets.token_urlsafe(32)
    return settings
