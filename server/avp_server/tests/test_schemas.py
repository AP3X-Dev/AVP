"""Drift guard: docs/schemas/ must match the wire models exactly.

If this fails, run: python server/scripts/export_schemas.py
"""
import importlib.util
import json
import os

_SCRIPTS = os.path.join(os.path.dirname(__file__), "..", "..", "scripts")
_SCHEMAS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "docs", "schemas"))


def _load_exporter():
    spec = importlib.util.spec_from_file_location("export_schemas", os.path.join(_SCRIPTS, "export_schemas.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_schemas_on_disk_match_models():
    exporter = _load_exporter()
    for name, model in exporter.MESSAGE_MODELS.items():
        path = os.path.join(_SCHEMAS, f"{name}.schema.json")
        assert os.path.isfile(path), f"missing {path}; run export_schemas.py"
        with open(path, encoding="utf-8") as f:
            on_disk = json.load(f)
        assert on_disk == exporter.schema_for(model), (
            f"docs/schemas/{name}.schema.json drifted from models; run export_schemas.py"
        )


def test_every_message_type_has_a_schema():
    exporter = _load_exporter()
    # Message envelope: every wire model must declare its type literal
    for name, model in exporter.MESSAGE_MODELS.items():
        schema = exporter.schema_for(model)
        assert schema["properties"]["type"]["const"] == name
        assert "avp_version" in schema["properties"]
