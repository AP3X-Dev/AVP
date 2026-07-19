"""Proxy adapter coverage and audit SQL regression tests."""
from avp_server.routes.avp import PROXY_ADAPTERS
from avp_server.services.registry import list_services, get_service_spec
from avp_server.audit import audit_event


def test_every_registry_operation_has_adapter():
    for service in list_services():
        spec = get_service_spec(service)
        for op in spec.operations:
            assert (service, op) in PROXY_ADAPTERS, f"no proxy adapter for {service}.{op}"


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
