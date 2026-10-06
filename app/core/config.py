import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.utils.network import normalize_ip


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"
MODELS_DIR = Path("models")
CORS_SEPARATOR = ","
HOST_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,253}[a-z0-9])?$")
SHOP_NAME = re.compile(r"^[a-z][a-z0-9_]{2,31}$")
JWT_SECRET_MIN_LENGTH = 32
TELEGRAM_TOKEN_PATTERN = re.compile(r"^[0-9]{6,12}:[A-Za-z0-9_-]{35}$")
TELEGRAM_CHAT_ID_PATTERN = re.compile(r"^-?[0-9]{5,20}$")
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        validate_default=True,
    )

    logsentinel_model_path: Path = (
        MODELS_DIR / "LogSentinel" / "logsentinel.onnx"
    )
    logsentinel_metadata_path: Path = (
        MODELS_DIR / "LogSentinel" / "metadata.json"
    )

    netguard_model_path: Path = MODELS_DIR / "NetGuard" / "netguard.onnx"
    netguard_metadata_path: Path = MODELS_DIR / "NetGuard" / "metadata.json"
    netguard_preprocess_path: Path = (
        MODELS_DIR / "NetGuard" / "preprocess.json"
    )

    http_payload_model_path: Path = (
        MODELS_DIR / "HTTP_Payload_Sensor" / "webattack_lr.joblib"
    )
    http_payload_metadata_path: Path = (
        MODELS_DIR / "HTTP_Payload_Sensor" / "metadata.json"
    )

    netflow_model_path: Path = (
        MODELS_DIR / "NetflowSensor" / "netflow_lr_model.joblib"
    )
    netflow_scaler_path: Path = (
        MODELS_DIR / "NetflowSensor" / "netflow_lr_scaler.joblib"
    )
    netflow_metadata_path: Path = (
        MODELS_DIR / "NetflowSensor" / "netflow_lr_metadata.json"
    )

    recon_model_path: Path = (
        MODELS_DIR / "Recon_Sensor" / "recon_sensor_xgb.joblib"
    )
    recon_metadata_path: Path = (
        MODELS_DIR / "Recon_Sensor" / "recon_sensor_xgb_metadata.json"
    )

    chroma_persist_dir: Path = Path("data") / "chroma"
    exploitdb_csv_path: Path = (
        Path("data") / "exploitdb" / "files_exploits.csv"
    )
    mitre_bundle_path: Path = Path("data") / "enterprise-attack.json"
    mitre_index_path: Path = Path("data") / "mitre" / "attack_index.json"
    cve_db_path: Path = Path("data") / "cve" / "cve.sqlite3"
    cors_origins: str = "http://localhost:5173" 
    # TODO: agithar.tensorkingdom.com when it is deployed.
    session_ttl_seconds: int = Field(default=3600, gt=0)

    database_url: SecretStr | None = None
    jwt_secret_key: SecretStr | None = None
    access_token_ttl_seconds: int = Field(default=900, gt=0, le=86400)

    log_dir: Path = Path("logs")
    log_level: str = "INFO"
    
    # THREAT INTELLIGENCE API KEYS
    abuseipdb_api_key: SecretStr | None = None
    shodan_api_key: SecretStr | None = None
    nvd_api_key: SecretStr | None = None
    virustotal_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "VIRUSTOTAL_API_KEY",
            "VIRUS_TOTAL_API_KEY"
        ),
    )

    # RAG: embeddings and vector store
    openai_api_key: SecretStr | None = None
    pinecone_api_key: SecretStr | None = None
    pinecone_index_name: str = "agithar-knowledge"
    pinecone_index_host: str | None = None
    embedding_model: str = "text-embedding-3-small"
    embedding_dimension: int = Field(default=1536, gt=0)

    # AGENT: master LLM (Claude API). No sampling settings on purpose:
    # temperature, top_p and top_k are rejected by this model.
    anthropic_api_key: SecretStr | None = None
    agent_model: str = "claude-sonnet-5-5"
    agent_effort: Literal["low", "medium", "high"] = "medium"
    agent_max_tokens: int = Field(default=4096, ge=256, le=32000)
    agent_max_tool_turns: int = Field(default=8, ge=1, le=20)
    # Prompt caching of the system prompt, tools and conversation (Anthropic).
    agent_prompt_cache: bool = True
    # Server-side fallback when the model declines a request (refusal).
    agent_fallbacks: bool = True

    # SECRETARIES: the report writers by OpenAI Responses API. .
    secretary_model: str = "gpt-6-luna"
    secretary_effort: Literal["low", "medium", "high"] = "medium"
    secretary_max_output_tokens: int = Field(default=4096, ge=512, le=16000)

    # DISPATCHER: how escalated cases are run through the agent graph. A case
    # that cannot run (queue full, hourly cap, crash, timeout) still alerts
    # the admin with a pending verdict.
    dispatch_max_concurrent: int = Field(default=2, ge=1, le=8)
    dispatch_queue_limit: int = Field(default=20, ge=1, le=200)
    dispatch_case_timeout_seconds: int = Field(default=300, ge=30, le=1800)
    dispatch_max_cases_per_hour: int = Field(default=30, ge=1, le=1000)
    # Re-run the recent incidents still open when the server starts.
    recover_on_startup: bool = True

    # INGESTION: the nginx log feed on valtoria. Off by default my laptop has
    # no such file . Log-only mode scores and counts but raises no case, so
    # no alert and no LLM cost until the real numbers have been checked.
    ingestion_enabled: bool = False
    ingestion_log_only: bool = True
    nginx_log_path: Path = Path("/var/log/nginx/agithar.access.log")
    ingestion_state_path: Path = Path("data/ingestion/nginx_offset.json")
    # Only these hosts are scored; the other sites on the server are not
    # protected by Agithar. Comma separated.
    ingestion_hosts: str = (
        "maisonroast.tensorkingdom.com,spring-bloom.tensorkingdom.com"
    )
    # Optional clients to skip, for example the server's own address. The
    # owner's home IP is NOT listed here on purpose: it changes.
    ingestion_ignore_ips: str = ""

    # CHAT: the admin's conversation with Agithar (admins only). `shops` maps
    # a short name to its host; they are the only sites the chat tools can
    # ask about, so the model never supplies a host name itself.
    shops: str = (
        "maisonroast=maisonroast.tensorkingdom.com,"
        "florabelle=spring-bloom.tensorkingdom.com"
    )
    chat_max_tool_turns: int = Field(default=4, ge=1, le=10)
    chat_max_output_tokens: int = Field(default=2048, ge=256, le=8000)
    chat_history_messages: int = Field(default=12, ge=0, le=50)
    chat_rate_limit_per_minute: int = Field(default=10, ge=1, le=120)
    chat_log_tail_mb: int = Field(default=4, ge=1, le=32)

    # TELEGRAM ALERTS (bot CyberSoc, @Agithatbot)
    telegram_bot_token: SecretStr | None = None
    telegram_chat_id: str | None = None

    @field_validator("*", mode="after")
    @classmethod
    def resolve_relative_path(cls, value: Any) -> Any:
        if isinstance(value, Path) and not value.is_absolute():
            return (PROJECT_ROOT / value).resolve()
        
        return value

    @field_validator("log_level", mode="after")
    @classmethod
    def normalize_log_level(cls, value: str) -> str:
        
        level = value.upper()
        
        if level not in LOG_LEVELS:
            raise ValueError(f"log_level must be one of {LOG_LEVELS}")
        
        return level

    @field_validator("jwt_secret_key", mode="after")
    @classmethod
    def require_strong_jwt_secret(
        cls, value: SecretStr | None
    ) -> SecretStr | None:

        if value is None or not value.get_secret_value():
            return None

        if len(value.get_secret_value()) < JWT_SECRET_MIN_LENGTH:
            raise ValueError(
                f"jwt_secret_key needs {JWT_SECRET_MIN_LENGTH}+ characters"
            )

        return value

    @field_validator(
        "abuseipdb_api_key",
        "shodan_api_key",
        "nvd_api_key",
        "virustotal_api_key",
        "openai_api_key",
        "anthropic_api_key",
        "pinecone_api_key",
        "telegram_bot_token",
        mode="after",
    )
    @classmethod
    def empty_key_is_unset(
        cls, value: SecretStr | None
    ) -> SecretStr | None:

        if value is None or not value.get_secret_value().strip():
            return None

        return value

    @field_validator("telegram_bot_token", mode="after")
    @classmethod
    def check_telegram_token(
        cls, value: SecretStr | None
    ) -> SecretStr | None:
        # The token goes into a URL path, so only the exact shape is allowed.
        if value is None:
            return None

        if not TELEGRAM_TOKEN_PATTERN.match(value.get_secret_value()):
            raise ValueError("telegram_bot_token has an invalid format")

        return value

    @field_validator("telegram_chat_id", mode="after")
    @classmethod
    def check_telegram_chat_id(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None

        chat_id = value.strip()

        if not TELEGRAM_CHAT_ID_PATTERN.match(chat_id):
            raise ValueError("telegram_chat_id must be a number")

        return chat_id

    @field_validator("pinecone_index_host", mode="after")
    @classmethod
    def check_pinecone_host(cls, value: str | None) -> str | None:
        # The API key is sent to this host, so it must be a Pinecone host.
        if value is None or not value.strip():
            return None

        host = value.strip().rstrip("/")
        hostname = host.removeprefix("https://")

        if not host.startswith("https://") or "/" in hostname:
            raise ValueError("pinecone_index_host must be a bare https host")

        if not hostname.endswith(".pinecone.io"):
            raise ValueError("pinecone_index_host must end in .pinecone.io")

        return host

    @field_validator("cors_origins", mode="after")
    @classmethod
    def reject_wildcard_origin(cls, value: str) -> str:
        
        if "*" in value:
            raise ValueError("wildcard CORS origins are not allowed")
        
        return value

    @field_validator("ingestion_hosts", mode="after")
    @classmethod
    def check_ingestion_hosts(cls, value: str) -> str:
        for host in value.split(CORS_SEPARATOR):
            if host.strip() and not HOST_PATTERN.match(host.strip().lower()):
                raise ValueError("ingestion_hosts has an invalid host name")

        return value

    @field_validator("ingestion_ignore_ips", mode="after")
    @classmethod
    def check_ignore_ips(cls, value: str) -> str:
        for item in value.split(CORS_SEPARATOR):
            if item.strip():
                normalize_ip(item)

        return value

    @field_validator("shops", mode="after")
    @classmethod
    def check_shops(cls, value: str) -> str:
        pairs = [p.strip() for p in value.split(CORS_SEPARATOR) if p.strip()]

        if not pairs:
            raise ValueError("shops needs at least one name=host pair")

        for pair in pairs:
            name, _, host = pair.partition("=")

            if not SHOP_NAME.match(name.strip()):
                raise ValueError("shops has an invalid shop name")

            if not HOST_PATTERN.match(host.strip().lower()):
                raise ValueError("shops has an invalid host name")

        return value

    @property
    def shop_map(self) -> dict[str, str]:
        pairs = [p for p in self.shops.split(CORS_SEPARATOR) if p.strip()]
        result = {}

        for pair in pairs:
            name, _, host = pair.partition("=")
            result[name.strip()] = host.strip().lower()

        return result

    @property
    def ingestion_host_list(self) -> list[str]:
        hosts = [h.strip().lower() for h in self.ingestion_hosts.split(",")]

        return [host for host in hosts if host]

    @property
    def ingestion_ignore_ip_list(self) -> list[str]:
        items = self.ingestion_ignore_ips.split(CORS_SEPARATOR)

        return [normalize_ip(item) for item in items if item.strip()]

    @property
    def cors_origin_list(self) -> list[str]:
        
        origins = []
        
        for origin in self.cors_origins.split(CORS_SEPARATOR):
            
            origin = origin.strip()
            
            if origin:
                origins.append(origin)
                
        return origins



@lru_cache
def get_settings() -> Settings:
    return Settings()
