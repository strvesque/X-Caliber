import json
from pathlib import Path

import pytest
from jsonschema import ValidationError

from src.core import ipc


SCHEMA_FILE = Path("D:/Akbar-automation/schemas/ipc_protocol.json")


def test_schema_loadable():
    # ensure JSON file is valid JSON
    with open(SCHEMA_FILE, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    assert isinstance(data, dict)


def test_parse_subdomain_json_valid():
    payload = {
        "target": "example.com",
        "subdomains": ["www.example.com", "api.example.com"],
        "count": 2,
        "timestamp": "2021-01-01T12:00:00Z",
    }
    assert ipc.validate_subdomain_output(payload) is True


def test_parse_subdomain_json_invalid_missing_field():
    payload = {
        "target": "example.com",
        "subdomains": ["www.example.com"],
        # missing count
        "timestamp": "2021-01-01T12:00:00Z",
    }
    with pytest.raises(ValidationError):
        ipc.validate_subdomain_output(payload)


def test_port_scan_valid():
    payload = {
        "target": "10.0.0.1",
        "open_ports": [
            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"}
        ],
        "scan_time": 1.23,
        "timestamp": "2021-01-01T12:01:00Z",
    }
    assert ipc.validate_port_scan_output(payload) is True


def test_port_scan_invalid_type():
    payload = {
        "target": "10.0.0.1",
        "open_ports": "not-a-list",
        "scan_time": 0.5,
        "timestamp": "2021-01-01T12:01:00Z",
    }
    with pytest.raises(ValidationError):
        ipc.validate_port_scan_output(payload)


def test_http_probe_valid():
    payload = {
        "urls": ["https://example.com"],
        "results": [
            {"url": "https://example.com", "status_code": 200, "response_time": 0.12}
        ],
        "timestamp": "2021-01-01T12:02:00Z",
    }
    assert ipc.validate_http_probe_output(payload) is True


def test_http_probe_invalid_missing_required():
    payload = {"urls": [], "timestamp": "2021-01-01T12:02:00Z"}
    with pytest.raises(ValidationError):
        ipc.validate_http_probe_output(payload)
