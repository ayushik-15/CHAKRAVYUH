"""CHAKRAVYUH Arbiter — Application configuration.

Settings are loaded from environment variables and/or a ``.env`` file located
in the project root.  Pydantic ``BaseSettings`` handles validation and type
coercion automatically.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration for the Arbiter service.

    Attributes:
        MERKLE_HOST: Hostname of the Merkle-log service.
        MERKLE_PORT: Port of the Merkle-log service.
        POSTGRES_DSN: Full DSN for the PostgreSQL database.
        JWT_SECRET: Secret key used for signing / verifying JWTs.
        JWT_ALGORITHM: Algorithm used for JWT encoding (default ``HS256``).
        JWT_EXPIRY_MINUTES: Token expiry duration in minutes (default ``60``).
        ARBITER_HOST: Host the Arbiter binds to.
        ARBITER_PORT: Port the Arbiter listens on.
        LLM_PLANE_URL: Base URL of the LLM plane service.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    # ── Merkle-log connection ────────────────────────────────────────────
    MERKLE_HOST: str = "merkle-log"
    MERKLE_PORT: int = 8001

    # ── Database ─────────────────────────────────────────────────────────
    POSTGRES_DSN: str = "postgresql+asyncpg://chakravyuh:chakravyuh@postgres:5432/chakravyuh"

    # ── JWT / Auth ───────────────────────────────────────────────────────
    JWT_SECRET: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_MINUTES: int = 60

    # ── Arbiter binding ──────────────────────────────────────────────────
    ARBITER_HOST: str = "0.0.0.0"
    ARBITER_PORT: int = 8000

    # ── LLM Plane ────────────────────────────────────────────────────────
    LLM_PLANE_URL: str = "http://llm-plane:8080"


settings = Settings()

