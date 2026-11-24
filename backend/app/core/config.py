from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str | None = None
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    evidence_vault_dir: str = "evidence_vault"
    deployment_mode: str = "LOCAL"
    session_ttl_hours: int = 24
    cookie_secure: bool = False
    rate_limit_enabled: bool = True
    ai_provider_enabled: bool = False
    ai_allow_external_data: bool = False
    ai_provider_url: str | None = None
    ai_api_key: str | None = None
    ai_model: str = "local-deterministic"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
