import os
from dataclasses import dataclass
from pathlib import Path


def secret_env(name: str, default: str = "") -> str:
    path = os.getenv(name + "_FILE")
    return Path(path).read_text().strip() if path else os.getenv(name, default)


@dataclass
class Config:
    database_url: str = "sqlite:///numen.db"
    artifact_root: Path = Path("artifacts")
    secret_key: str = ""
    broker_url: str = "http://runner-broker:8081"
    broker_token: str = ""
    cookie_secure: bool = False
    frontend_root: Path = Path("../frontend/dist")
    monitor_interval_seconds: int | None = None
    test_mode: bool = False
    worker_concurrency: int = 3
    audit_concurrency: int = 3

    @classmethod
    def from_env(cls):
        days = os.getenv("NUMEN_MONITOR_INTERVAL_DAYS")
        return cls(
            database_url=os.getenv("NUMEN_DATABASE_URL", "sqlite:///numen.db"),
            artifact_root=Path(os.getenv("NUMEN_ARTIFACT_ROOT", "artifacts")),
            secret_key=secret_env("NUMEN_SECRET_KEY"),
            broker_url=os.getenv("NUMEN_BROKER_URL", "http://runner-broker:8081"),
            broker_token=secret_env("NUMEN_BROKER_TOKEN"),
            cookie_secure=os.getenv("NUMEN_COOKIE_SECURE", "false").lower() == "true",
            frontend_root=Path(os.getenv("NUMEN_FRONTEND_ROOT", "../frontend/dist")),
            monitor_interval_seconds=int(days) * 86400 if days else None,
            test_mode=os.getenv("NUMEN_TEST_MODE") == "1",
            worker_concurrency=int(os.getenv("NUMEN_WORKER_CONCURRENCY", "3")),
            audit_concurrency=int(os.getenv("NUMEN_AUDIT_CONCURRENCY", "3")),
        )
