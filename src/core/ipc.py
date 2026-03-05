"""IPC JSON Schema validation helpers.

Go tools emit JSON to stdout; Python consumers should validate using jsonschema
and provide clear error messages on failure.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import jsonschema
from jsonschema import ValidationError

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "ipc_protocol.json"


def _load_schema() -> Dict[str, Any]:
    with open(SCHEMA_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def validate_json_against_schema(data: Dict[str, Any]) -> bool:
    """Validate a parsed JSON object against the IPC schema.

    Returns True when valid. Raises jsonschema.ValidationError with a clear
    message when invalid.
    """
    schema = _load_schema()
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: e.path)
    if errors:
        messages = []
        for e in errors:
            # human friendly location
            loc = "->".join(map(str, e.absolute_path)) if e.absolute_path else "<root>"
            messages.append(f"{loc}: {e.message}")
        raise ValidationError("Validation failed: " + "; ".join(messages))
    return True


def validate_subdomain_output(json_data: Dict[str, Any]) -> bool:
    """Validate that json_data matches the subdomain enumerator schema.

    This function narrows the general schema to the subdomain variant by
    checking for required keys and then calling the generic validator.
    """
    if not isinstance(json_data, dict):
        raise ValidationError("Payload must be a JSON object")
    # quick shape check
    required = {"target", "subdomains", "count", "timestamp"}
    if not required.issubset(set(json_data.keys())):
        missing = required - set(json_data.keys())
        raise ValidationError(f"Missing required fields for subdomain output: {', '.join(sorted(missing))}")
    return validate_json_against_schema(json_data)


def validate_port_scan_output(json_data: Dict[str, Any]) -> bool:
    if not isinstance(json_data, dict):
        raise ValidationError("Payload must be a JSON object")
    required = {"target", "open_ports", "scan_time", "timestamp"}
    if not required.issubset(set(json_data.keys())):
        missing = required - set(json_data.keys())
        raise ValidationError(f"Missing required fields for port scan output: {', '.join(sorted(missing))}")
    return validate_json_against_schema(json_data)


def validate_http_probe_output(json_data: Dict[str, Any]) -> bool:
    if not isinstance(json_data, dict):
        raise ValidationError("Payload must be a JSON object")
    required = {"urls", "results", "timestamp"}
    if not required.issubset(set(json_data.keys())):
        missing = required - set(json_data.keys())
        raise ValidationError(f"Missing required fields for http probe output: {', '.join(sorted(missing))}")
    return validate_json_against_schema(json_data)
