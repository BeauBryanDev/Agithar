from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"
MODELS_DIR = Path("models")
CORS_SEPARATOR = ","
JWT_SECRET_MIN_LENGTH = 32
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
    virustotal_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "VIRUSTOTAL_API_KEY", "VIRUS_TOTAL_API_KEY"
        ),
    )

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

    @field_validator("abuseipdb_api_key", mode="after")
    @classmethod
    def empty_abuseipdb_key_is_unset(
        cls, value: SecretStr | None
    ) -> SecretStr | None:

        if value is None or not value.get_secret_value().strip():
            return None

        return value
    
    @field_validator("shodan_api_key", mode="after")
    @classmethod
    def empty_shodan_key_is_unset(
        cls, value: SecretStr | None
    ) -> SecretStr | None:

        if value is None or not value.get_secret_value().strip():
            return None
        
        return value
    
    @field_validator("virustotal_api_key", mode="after")
    @classmethod
    def empty_virustotal_key_is_unset(
        cls, value: SecretStr | None
    ) -> SecretStr | None:

        if value is None or not value.get_secret_value().strip():
            return None
        
        return value
    

    @field_validator("cors_origins", mode="after")
    @classmethod
    def reject_wildcard_origin(cls, value: str) -> str:
        
        if "*" in value:
            raise ValueError("wildcard CORS origins are not allowed")
        
        return value

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
