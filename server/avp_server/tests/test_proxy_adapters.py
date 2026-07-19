"""Proxy adapter coverage and audit SQL regression tests."""
from avp_server.routes.avp import PROXY_ADAPTERS, STREAM_TARGETS
from avp_server.services.registry import list_services, get_service_spec
from avp_server.services.openai_proxy import openai_chat_target
from avp_server.services.anthropic_proxy import anthropic_messages_target
from avp_server.audit import audit_event


def test_every_registry_operation_has_adapter():
    for service in list_services():
        spec = get_service_spec(service)
        for op in spec.operations:
            assert (service, op) in PROXY_ADAPTERS, f"no proxy adapter for {service}.{op}"


def test_stream_targets_are_subset_of_adapters():
    for key in STREAM_TARGETS:
        assert key in PROXY_ADAPTERS, f"stream target {key} has no non-streaming adapter"


def test_openai_chat_target_builds_auth():
    url, headers = openai_chat_target({"api_key": "sk-test", "org_id": "org-1"})
    assert url.endswith("/chat/completions")
    assert headers["Authorization"] == "Bearer sk-test"
    assert headers["OpenAI-Organization"] == "org-1"


def test_anthropic_messages_target_builds_auth():
    url, headers = anthropic_messages_target({"api_key": "sk-ant"})
    assert url.endswith("/v1/messages")
    assert headers["x-api-key"] == "sk-ant"
    assert "anthropic-version" in headers


def test_targets_reject_missing_api_key():
    assert openai_chat_target({}) is None
    assert anthropic_messages_target({}) is None


class _FakeCursor:
    def __init__(self, captured):
        self.captured = captured

    def execute(self, query, params):
        self.captured["query"] = query
        self.captured["params"] = params

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _FakeConn:
    def __init__(self, captured):
        self.captured = captured

    def cursor(self):
        return _FakeCursor(self.captured)


def test_audit_event_emits_valid_sql_and_serialized_json():
    captured = {}
    audit_event(
        _FakeConn(captured),
        principal_id=1,
        agent_db_id=None,
        session_db_id=None,
        session_id="ses_x",
        event_type="test_event",
        capability={"service": "openai"},
        metadata={"a": 1},
    )
    # Casts in the INSERT column list are a Postgres syntax error
    column_list = captured["query"].split("VALUES")[0]
    assert "::" not in column_list
    # jsonb params must be pre-serialized strings, not raw dicts
    assert isinstance(captured["params"][6], str)   # capability
    assert isinstance(captured["params"][10], str)  # metadata
