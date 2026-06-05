import os
from dataclasses import dataclass
from functools import lru_cache


def _as_bool(value: str | bool | None, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _load_env_file() -> None:
    for candidate in (".env.local", ".env"):
        if not os.path.exists(candidate):
            continue
        with open(candidate, "r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                os.environ.setdefault(key, value)


@dataclass(frozen=True)
class Settings:
    app_name: str
    api_prefix: str
    database_url: str
    mongodb_url: str
    mongodb_db: str
    redis_url: str
    celery_broker_url: str
    celery_result_backend: str
    jwt_secret: str
    jwt_algorithm: str
    access_token_expire_minutes: int
    api_rate_limit_per_minute: int
    misp_url: str
    misp_api_key: str
    misp_live_mode: bool
    misp_verify_ssl: bool
    misp_timeout_seconds: int
    opencti_url: str
    opencti_token: str
    opencti_live_mode: bool
    opencti_verify_ssl: bool
    opencti_timeout_seconds: int
    abuseipdb_api_key: str
    virustotal_api_key: str
    slack_webhook_url: str | None
    discord_webhook_url: str | None
    smtp_host: str
    smtp_port: int
    smtp_from: str
    demo_mode: bool
    embedded_mode: bool
    document_store_path: str
    celery_task_always_eager: bool
    log_level: str
    frontend_api_url: str
    module3_generated_alerts_path: str
    module4_ir_handoff_path: str


@lru_cache
def get_settings() -> Settings:
    _load_env_file()
    return Settings(
        app_name=os.getenv("APP_NAME", "Threat Intelligence Enrichment System"),
        api_prefix=os.getenv("API_PREFIX", "/api"),
        database_url=os.getenv("DATABASE_URL", "sqlite:///./local-threat-intel.db"),
        mongodb_url=os.getenv("MONGODB_URL", "embedded://local"),
        mongodb_db=os.getenv("MONGODB_DB", "threat_intel"),
        redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        celery_broker_url=os.getenv("CELERY_BROKER_URL", "memory://"),
        celery_result_backend=os.getenv("CELERY_RESULT_BACKEND", "cache+memory://"),
        jwt_secret=os.getenv("JWT_SECRET", "local-dev-secret"),
        jwt_algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
        access_token_expire_minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440")),
        api_rate_limit_per_minute=int(os.getenv("API_RATE_LIMIT_PER_MINUTE", "120")),
        misp_url=os.getenv("MISP_URL", "http://misp:8080"),
        misp_api_key=os.getenv("MISP_API_KEY", "demo"),
        misp_live_mode=_as_bool(os.getenv("MISP_LIVE_MODE"), False),
        misp_verify_ssl=_as_bool(os.getenv("MISP_VERIFY_SSL"), False),
        misp_timeout_seconds=int(os.getenv("MISP_TIMEOUT_SECONDS", "10")),
        opencti_url=os.getenv("OPENCTI_URL", "http://opencti:8080"),
        opencti_token=os.getenv("OPENCTI_TOKEN", "demo"),
        opencti_live_mode=_as_bool(os.getenv("OPENCTI_LIVE_MODE"), False),
        opencti_verify_ssl=_as_bool(os.getenv("OPENCTI_VERIFY_SSL"), False),
        opencti_timeout_seconds=int(os.getenv("OPENCTI_TIMEOUT_SECONDS", "10")),
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", "demo"),
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", "demo"),
        slack_webhook_url=os.getenv("SLACK_WEBHOOK_URL") or None,
        discord_webhook_url=os.getenv("DISCORD_WEBHOOK_URL") or None,
        smtp_host=os.getenv("SMTP_HOST", "mailhog"),
        smtp_port=int(os.getenv("SMTP_PORT", "1025")),
        smtp_from=os.getenv("SMTP_FROM", "soc@example.local"),
        demo_mode=_as_bool(os.getenv("DEMO_MODE"), True),
        embedded_mode=_as_bool(os.getenv("EMBEDDED_MODE"), True),
        document_store_path=os.getenv("DOCUMENT_STORE_PATH", "./local-document-store"),
        celery_task_always_eager=_as_bool(os.getenv("CELERY_TASK_ALWAYS_EAGER"), True),
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        frontend_api_url=os.getenv("FRONTEND_API_URL", "http://localhost:8000/api"),
        module3_generated_alerts_path=os.getenv(
            "MODULE3_GENERATED_ALERTS_PATH",
            "../module-3-siem-visualization (2)/module-3-siem-visualization/module-3-siem-visualization/data/generated-alerts.ndjson",
        ),
        module4_ir_handoff_path=os.getenv(
            "MODULE4_IR_HANDOFF_PATH",
            "./output/module4-enriched-alerts-for-ir.ndjson",
        ),
    )


settings = get_settings()
