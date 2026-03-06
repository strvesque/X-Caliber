import os
import json
import subprocess
from unittest.mock import patch, MagicMock

import pytest

from src.core.go_tools import (
    run_subdomain_enum,
    run_port_scan,
    run_http_probe,
    GoToolNotFoundError,
    GoToolTimeoutError,
    InvalidJSONError,
)


VALID_SUBDOMAIN = {
    "target": "example.com",
    "subdomains": ["a.example.com", "b.example.com"],
    "count": 2,
    "timestamp": "2026-03-06T10:00:00Z",
}

VALID_PORTSCAN = {
    "target": "192.0.2.1",
    "open_ports": [{"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"}],
    "scan_time": 1.23,
    "timestamp": "2026-03-06T10:00:00Z",
}

VALID_HTTP = {
    "urls": ["https://example.com"],
    "results": [{"url": "https://example.com", "status_code": 200, "response_time": 0.12}],
    "timestamp": "2026-03-06T10:00:00Z",
}


class TestSubdomainEnum:
    @patch("subprocess.run")
    def test_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(VALID_SUBDOMAIN), stderr="")
        path = "./recon_go/xcal-subdomain"
        os.makedirs("recon_go", exist_ok=True)
        with open(path, "w") as f:
            f.write("")

        try:
            res = run_subdomain_enum("example.com", binary_path=path)
            assert res["target"] == "example.com"
            assert res["count"] == 2
        finally:
            os.remove(path)

    def test_binary_not_found(self):
        with pytest.raises(GoToolNotFoundError):
            run_subdomain_enum("example.com", binary_path="/nonexistent/binary")

    @patch("subprocess.run")
    def test_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=[], timeout=1)
        path = "./recon_go/xcal-subdomain"
        os.makedirs("recon_go", exist_ok=True)
        with open(path, "w"):
            pass
        try:
            with pytest.raises(GoToolTimeoutError):
                run_subdomain_enum("example.com", binary_path=path, timeout=1)
        finally:
            os.remove(path)

    @patch("subprocess.run")
    def test_nonzero_exit(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
        path = "./recon_go/xcal-subdomain"
        os.makedirs("recon_go", exist_ok=True)
        with open(path, "w"):
            pass
        try:
            with pytest.raises(Exception):
                run_subdomain_enum("example.com", binary_path=path)
        finally:
            os.remove(path)

    @patch("subprocess.run")
    def test_invalid_json(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="not json", stderr="")
        path = "./recon_go/xcal-subdomain"
        os.makedirs("recon_go", exist_ok=True)
        with open(path, "w"):
            pass
        try:
            with pytest.raises(InvalidJSONError):
                run_subdomain_enum("example.com", binary_path=path)
        finally:
            os.remove(path)

    @patch("subprocess.run")
    def test_schema_mismatch(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps({"foo": "bar"}), stderr="")
        path = "./recon_go/xcal-subdomain"
        os.makedirs("recon_go", exist_ok=True)
        with open(path, "w"):
            pass
        try:
            with pytest.raises(InvalidJSONError):
                run_subdomain_enum("example.com", binary_path=path)
        finally:
            os.remove(path)


class TestPortScan:
    @patch("subprocess.run")
    def test_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(VALID_PORTSCAN), stderr="")
        path = "./recon_go/xcal-portscan"
        os.makedirs("recon_go", exist_ok=True)
        with open(path, "w"):
            pass
        try:
            res = run_port_scan("192.0.2.1", ports="22", binary_path=path)
            assert res["target"] == "192.0.2.1"
            assert len(res["open_ports"]) == 1
        finally:
            os.remove(path)

    def test_binary_not_found(self):
        with pytest.raises(GoToolNotFoundError):
            run_port_scan("127.0.0.1", binary_path="/no/such")

    @patch("subprocess.run")
    def test_invalid_json(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="nope", stderr="")
        path = "./recon_go/xcal-portscan"
        os.makedirs("recon_go", exist_ok=True)
        with open(path, "w"):
            pass
        try:
            with pytest.raises(InvalidJSONError):
                run_port_scan("127.0.0.1", binary_path=path)
        finally:
            os.remove(path)


class TestHTTPProbe:
    @patch("subprocess.run")
    def test_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(VALID_HTTP), stderr="")
        path = "./recon_go/xcal-httpprobe"
        os.makedirs("recon_go", exist_ok=True)
        with open(path, "w"):
            pass
        try:
            res = run_http_probe(["https://example.com"], binary_path=path)
            assert "urls" in res and isinstance(res["urls"], list)
        finally:
            os.remove(path)

    def test_binary_not_found(self):
        with pytest.raises(GoToolNotFoundError):
            run_http_probe(["https://a"], binary_path="/nope")

    @patch("subprocess.run")
    def test_schema_mismatch(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps({"foo": 1}), stderr="")
        path = "./recon_go/xcal-httpprobe"
        os.makedirs("recon_go", exist_ok=True)
        with open(path, "w"):
            pass
        try:
            with pytest.raises(InvalidJSONError):
                run_http_probe(["https://a"], binary_path=path)
        finally:
            os.remove(path)


@pytest.mark.integration
def test_integration_skip_if_missing():
    if not os.path.exists("./recon_go/xcal-subdomain"):
        pytest.skip("Binary not built - skipping integration test")
    res = run_subdomain_enum("example.com", binary_path="./recon_go/xcal-subdomain")
    assert "target" in res
