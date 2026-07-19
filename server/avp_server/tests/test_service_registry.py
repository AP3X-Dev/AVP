"""Tests for service registry (AVP-030, AVP-031)."""
import pytest

from avp_server.services.registry import (
    ServiceSpec,
    SecretValidationError,
    get_service_spec,
    list_services,
    get_service_info,
    get_registry_info,
    OPENAI_SPEC,
    ANTHROPIC_SPEC,
)


class TestSecretValidation:
    """Tests for secret schema validation (AVP-030)."""
    
    def test_valid_openai_secret(self):
        """Test that valid OpenAI secret passes validation."""
        data = {"api_key": "sk-test123", "base_url": "https://api.openai.com/v1"}
        OPENAI_SPEC.validate_secret(data)
    
    def test_missing_required_field_raises(self):
        """Test that missing required field raises error."""
        data = {"base_url": "https://api.openai.com/v1"}  # Missing api_key
        
        with pytest.raises(SecretValidationError) as exc_info:
            OPENAI_SPEC.validate_secret(data)
        
        assert "api_key" in exc_info.value.message
        assert exc_info.value.field == "api_key"
    
    def test_empty_required_field_raises(self):
        """Test that empty required field raises error."""
        data = {"api_key": ""}  # Empty api_key
        
        with pytest.raises(SecretValidationError) as exc_info:
            OPENAI_SPEC.validate_secret(data)
        
        assert "api_key" in exc_info.value.message
    
    def test_extra_field_rejected_by_default(self):
        """Test that extra fields are rejected by default."""
        data = {"api_key": "sk-test", "extra_field": "value"}
        
        with pytest.raises(SecretValidationError) as exc_info:
            OPENAI_SPEC.validate_secret(data)
        
        assert "extra_field" in exc_info.value.message
    
    def test_extra_field_allowed_when_configured(self):
        """Test that extra fields allowed with allow_extra=True."""
        data = {"api_key": "sk-test", "extra_field": "value"}
        
        # Should not raise
        OPENAI_SPEC.validate_secret(data, allow_extra=True)
    
    def test_wrong_type_raises(self):
        """Test that wrong field type raises error."""
        data = {"api_key": 12345}  # Should be string
        
        with pytest.raises(SecretValidationError) as exc_info:
            OPENAI_SPEC.validate_secret(data)
        
        assert "string" in exc_info.value.message
    
    def test_anthropic_spec_validation(self):
        """Test that Anthropic spec validates correctly."""
        data = {"api_key": "sk-ant-test123"}
        ANTHROPIC_SPEC.validate_secret(data)
    
    def test_anthropic_missing_key(self):
        """Test that Anthropic spec requires api_key."""
        data = {"base_url": "https://api.anthropic.com"}
        
        with pytest.raises(SecretValidationError):
            ANTHROPIC_SPEC.validate_secret(data)


class TestServiceRegistry:
    """Tests for service registry discovery (AVP-031)."""
    
    def test_list_services_returns_known_services(self):
        """Test that list_services returns OpenAI and Anthropic."""
        services = list_services()
        
        assert "openai" in services
        assert "anthropic" in services
    
    def test_get_service_spec_returns_spec(self):
        """Test that get_service_spec returns correct spec."""
        spec = get_service_spec("openai")
        
        assert spec is not None
        assert spec.name == "openai"
    
    def test_get_service_spec_unknown_returns_none(self):
        """Test that unknown service returns None."""
        spec = get_service_spec("unknown_service")
        
        assert spec is None
    
    def test_get_service_info_structure(self):
        """Test that service info has expected structure."""
        info = get_service_info("openai")
        
        assert info is not None
        assert "name" in info
        assert "credential_fields" in info
        assert "required_fields" in info
        assert "operations" in info
        assert "scopes" in info
        
        assert info["name"] == "openai"
        assert "api_key" in info["credential_fields"]
        assert "api_key" in info["required_fields"]
        assert "chat" in info["operations"]
    
    def test_get_registry_info_structure(self):
        """Test that registry info has expected structure."""
        info = get_registry_info()
        
        assert "services" in info
        assert "openai" in info["services"]
        assert "anthropic" in info["services"]


class TestServiceSpec:
    """Tests for ServiceSpec dataclass."""
    
    def test_spec_is_immutable(self):
        """Test that ServiceSpec is frozen (immutable)."""
        spec = OPENAI_SPEC
        
        with pytest.raises(AttributeError):
            spec.name = "modified"
    
    def test_spec_has_credential_schema(self):
        """Test that spec has credential schema."""
        assert "api_key" in OPENAI_SPEC.credential_schema
        assert OPENAI_SPEC.credential_schema["api_key"]["required"] is True
    
    def test_spec_has_env_mapping(self):
        """Test that spec has environment variable mapping."""
        assert "OPENAI_API_KEY" in OPENAI_SPEC.env_mapping
        assert OPENAI_SPEC.env_mapping["OPENAI_API_KEY"] == "api_key"
    
    def test_spec_has_operations(self):
        """Test that spec has operations mapping."""
        assert "chat" in OPENAI_SPEC.operations

