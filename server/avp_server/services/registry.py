from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ..config import settings


class SecretValidationError(Exception):
    """Raised when secret data fails schema validation."""
    def __init__(self, message: str, field: Optional[str] = None):
        self.message = message
        self.field = field
        super().__init__(message)


@dataclass(frozen=True)
class ServiceSpec:
    name: str
    credential_schema: Dict[str, Any]
    env_mapping: Dict[str, str]  # env var key -> credential field
    operations: Dict[str, str]   # operation name -> required scope

    def validate_secret(self, data: Dict[str, Any], allow_extra: bool = False) -> None:
        """Validate secret data against this service's credential schema.

        Args:
            data: Secret data to validate
            allow_extra: If True, allow fields not in schema

        Raises:
            SecretValidationError: If validation fails
        """
        schema = self.credential_schema

        # Check required fields
        for field_name, field_spec in schema.items():
            if field_spec.get("required", False):
                if field_name not in data or data[field_name] is None or data[field_name] == "":
                    raise SecretValidationError(
                        f"missing required field '{field_name}' for {self.name}",
                        field=field_name
                    )

        # Check types for provided fields
        for field_name, value in data.items():
            if field_name in schema:
                expected_type = schema[field_name].get("type", "string")
                if expected_type == "string" and not isinstance(value, str):
                    raise SecretValidationError(
                        f"field '{field_name}' must be a string for {self.name}",
                        field=field_name
                    )
            elif not allow_extra:
                # Field not in schema and extras not allowed
                raise SecretValidationError(
                    f"unknown field '{field_name}' for {self.name}",
                    field=field_name
                )


OPENAI_SPEC = ServiceSpec(
    name="openai",
    credential_schema={
        "api_key": {"type": "string", "required": True},
        "base_url": {"type": "string", "required": False},
        "org_id": {"type": "string", "required": False},
    },
    env_mapping={
        "OPENAI_API_KEY": "api_key",
        "OPENAI_BASE_URL": "base_url",
        "OPENAI_ORG_ID": "org_id",
    },
    operations={
        "chat": "chat"
    }
)

ANTHROPIC_SPEC = ServiceSpec(
    name="anthropic",
    credential_schema={
        "api_key": {"type": "string", "required": True},
        "base_url": {"type": "string", "required": False},
    },
    env_mapping={
        "ANTHROPIC_API_KEY": "api_key",
        "ANTHROPIC_BASE_URL": "base_url",
    },
    operations={
        "messages": "messages"
    }
)

_SERVICE_SPECS: Dict[str, ServiceSpec] = {
    "openai": OPENAI_SPEC,
    "anthropic": ANTHROPIC_SPEC,
}


def get_service_spec(service: str) -> Optional[ServiceSpec]:
    return _SERVICE_SPECS.get(service)


def format_env(service: str, secret_data: Dict[str, Any]) -> Dict[str, str]:
    spec = get_service_spec(service)
    if not spec:
        raise KeyError("unknown_service")
    env: Dict[str, str] = {}
    for env_key, field_name in spec.env_mapping.items():
        val = secret_data.get(field_name)
        if val is None:
            continue
        env[env_key] = str(val)
    # default base url if missing
    if service == "openai" and "OPENAI_BASE_URL" not in env:
        env["OPENAI_BASE_URL"] = settings.openai_base_url
    return env


def operation_allowed(service: str, operation: str, scopes: List[str]) -> bool:
    spec = get_service_spec(service)
    if not spec:
        return False
    required = spec.operations.get(operation)
    if not required:
        return False
    return required in set(scopes)


def list_services() -> List[str]:
    """Return list of registered service names."""
    return list(_SERVICE_SPECS.keys())


def get_service_info(service: str) -> Optional[Dict[str, Any]]:
    """Get service information for discovery endpoint.

    Returns service metadata without exposing internal implementation details.
    """
    spec = get_service_spec(service)
    if not spec:
        return None

    return {
        "name": spec.name,
        "credential_fields": list(spec.credential_schema.keys()),
        "required_fields": [
            k for k, v in spec.credential_schema.items()
            if v.get("required", False)
        ],
        "operations": list(spec.operations.keys()),
        "scopes": list(set(spec.operations.values())),
    }


def get_registry_info() -> Dict[str, Any]:
    """Get full registry information for discovery endpoint."""
    return {
        "services": {
            name: get_service_info(name)
            for name in list_services()
        }
    }
