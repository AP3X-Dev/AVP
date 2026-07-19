from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AVP_", case_sensitive=False)

    database_url: str = Field("postgresql://avp:avp@localhost:5432/avp", description="Postgres connection string")
    host: str = "0.0.0.0"
    port: int = 8000
    dev_mode: bool = False

    dek_b64: str = ""
    key_version: str = "local-1"

    # Key rotation: JSON map of key_version -> base64 DEK, e.g.
    # {"local-1": "<b64>", "local-2": "<b64>"}. key_version selects which
    # entry encrypts new data; old entries remain available for decryption.
    # dek_b64 (if set) is merged in under key_version for backward compat.
    dek_keyring_b64: str = ""

    # Key provider: "local" (DEKs from env) or "aws_kms" (env holds
    # KMS-wrapped DEKs, unwrapped via KMS Decrypt at startup)
    key_provider: str = "local"
    kms_key_id: str = ""
    kms_wrapped_dek_b64: str = ""
    # JSON map of key_version -> base64 KMS-wrapped DEK (rotation)
    kms_wrapped_keyring_b64: str = ""

    # Security: ephemeral keys are dangerous outside dev
    # In production (dev_mode=False), ephemeral is never allowed
    # In dev mode, ephemeral is only allowed if this is explicitly True
    allow_ephemeral_dek: bool = False

    # Label binding strictness
    # If False (default), secret resolution/proxy require resource label
    # If True, allows fallback to newest secret by service+env when label missing
    allow_label_fallback: bool = False

    # Secret schema validation
    # If True, allows extra fields in secrets not defined in schema
    # If False (default), rejects unknown fields
    allow_extra_secret_fields: bool = False

    openai_base_url: str = "https://api.openai.com/v1"
    anthropic_base_url: str = "https://api.anthropic.com"

    # Rate limiting for proxy calls: "postgres" (survives restarts, works
    # across replicas) or "memory" (per-process token bucket)
    rate_limit_backend: str = "postgres"
    proxy_rate_limit_per_minute: int = 60

    # Admin bootstrap: one-time token for creating first principal
    # When set, POST /admin/bootstrap_principal is enabled
    # Should be removed after initial setup
    admin_bootstrap_token: str = ""


settings = Settings()
