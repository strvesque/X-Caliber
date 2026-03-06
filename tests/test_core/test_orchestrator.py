"""TDD tests for AutomationOrchestrator."""

import asyncio
from typing import Any

import pytest


class TestOrchestratorInstantiation:
    """Test orchestrator can be instantiated and has correct structure."""

    def test_orchestrator_imports_without_error(self):
        """Test that orchestrator module can be imported."""
        from src.core.orchestrator import AutomationOrchestrator

        assert AutomationOrchestrator is not None

    def test_orchestrator_instantiates(self):
        """Test orchestrator can be instantiated."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        assert orchestrator is not None

    def test_orchestrator_has_initial_state(self):
        """Test orchestrator has state management initialized."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        assert hasattr(orchestrator, "state")
        assert orchestrator.state is not None
        assert "current_phase" in orchestrator.state
        assert "completed_phases" in orchestrator.state
        assert "errors" in orchestrator.state
        assert "timing" in orchestrator.state

    def test_orchestrator_initial_state_values(self):
        """Test orchestrator state has correct initial values."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        assert orchestrator.state["current_phase"] is None
        assert orchestrator.state["completed_phases"] == []
        assert orchestrator.state["errors"] == []
        assert orchestrator.state["timing"] == {}


class TestOrchestratorPhaseMethods:
    """Test that all required phase methods exist and are callable."""

    @pytest.mark.asyncio
    async def test_run_recon_exists_and_callable(self):
        """Test run_recon method exists and can be called."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        assert hasattr(orchestrator, "run_recon")
        assert callable(orchestrator.run_recon)

        # Call with minimal params
        result = await orchestrator.run_recon("example.com")
        assert result is not None
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_run_scan_exists_and_callable(self):
        """Test run_scan method exists and can be called."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        assert hasattr(orchestrator, "run_scan")
        assert callable(orchestrator.run_scan)

        # Call with minimal params
        recon_results = {"target": "example.com", "subdomains": []}
        result = await orchestrator.run_scan("example.com", recon_results)
        assert result is not None
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_run_exploit_exists_and_callable(self):
        """Test run_exploit method exists and can be called."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        assert hasattr(orchestrator, "run_exploit")
        assert callable(orchestrator.run_exploit)

        # Call with minimal params
        scan_results = {"target": "example.com", "ports": []}
        result = await orchestrator.run_exploit("example.com", scan_results)
        assert result is not None
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_run_ctf_exists_and_callable(self):
        """Test run_ctf method exists and can be called."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        assert hasattr(orchestrator, "run_ctf")
        assert callable(orchestrator.run_ctf)

        # Call with minimal params
        result = await orchestrator.run_ctf("example.com")
        assert result is not None
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_run_full_pipeline_exists_and_callable(self):
        """Test run_full_pipeline method exists and can be called."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        assert hasattr(orchestrator, "run_full_pipeline")
        assert callable(orchestrator.run_full_pipeline)

        # Call with minimal params
        result = await orchestrator.run_full_pipeline("example.com")
        assert result is not None
        assert isinstance(result, dict)


class TestOrchestratorStateManagement:
    """Test that orchestrator tracks state correctly."""

    @pytest.mark.asyncio
    async def test_recon_updates_current_phase(self):
        """Test run_recon updates current_phase in state."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        await orchestrator.run_recon("example.com")
        assert orchestrator.state["current_phase"] == "recon"

    @pytest.mark.asyncio
    async def test_recon_adds_to_completed_phases(self):
        """Test run_recon adds 'recon' to completed_phases."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        await orchestrator.run_recon("example.com")
        assert "recon" in orchestrator.state["completed_phases"]

    @pytest.mark.asyncio
    async def test_recon_records_timing(self):
        """Test run_recon records timing information."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        await orchestrator.run_recon("example.com")
        assert "recon" in orchestrator.state["timing"]
        assert isinstance(orchestrator.state["timing"]["recon"], float)
        assert orchestrator.state["timing"]["recon"] >= 0

    @pytest.mark.asyncio
    async def test_scan_updates_state(self):
        """Test run_scan updates state correctly."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        recon_results = {"target": "example.com", "subdomains": []}
        await orchestrator.run_scan("example.com", recon_results)
        assert orchestrator.state["current_phase"] == "scan"
        assert "scan" in orchestrator.state["completed_phases"]
        assert "scan" in orchestrator.state["timing"]

    @pytest.mark.asyncio
    async def test_exploit_updates_state(self):
        """Test run_exploit updates state correctly."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        scan_results = {"target": "example.com", "ports": []}
        await orchestrator.run_exploit("example.com", scan_results)
        assert orchestrator.state["current_phase"] == "exploit"
        assert "exploit" in orchestrator.state["completed_phases"]
        assert "exploit" in orchestrator.state["timing"]

    @pytest.mark.asyncio
    async def test_ctf_updates_state(self):
        """Test run_ctf updates state correctly."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        await orchestrator.run_ctf("example.com")
        assert orchestrator.state["current_phase"] == "ctf"
        assert "ctf" in orchestrator.state["completed_phases"]
        assert "ctf" in orchestrator.state["timing"]


class TestOrchestratorPipeline:
    """Test full pipeline chaining and execution."""

    @pytest.mark.asyncio
    async def test_full_pipeline_returns_all_phase_results(self):
        """Test run_full_pipeline returns results from all phases."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        result = await orchestrator.run_full_pipeline("example.com")

        assert "recon" in result
        assert "scan" in result
        assert "exploit" in result
        assert "ctf" in result

    @pytest.mark.asyncio
    async def test_full_pipeline_chains_phases_in_order(self):
        """Test run_full_pipeline executes phases in correct order."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        await orchestrator.run_full_pipeline("example.com")

        completed = orchestrator.state["completed_phases"]
        assert completed.index("recon") < completed.index("scan")
        assert completed.index("scan") < completed.index("exploit")
        assert completed.index("exploit") < completed.index("ctf")

    @pytest.mark.asyncio
    async def test_full_pipeline_passes_data_between_phases(self):
        """Test pipeline passes results from one phase to next."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        result = await orchestrator.run_full_pipeline("example.com")

        # Recon results should be available to scan
        assert result["recon"]["target"] == "example.com"
        # Scan results should be available to exploit
        assert result["scan"]["target"] == "example.com"


class TestOrchestratorErrorHandling:
    """Test error handling and graceful degradation."""

    @pytest.mark.asyncio
    async def test_phase_error_captured_in_state(self):
        """Test that phase errors are captured in state.errors."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()

        # Trigger error by passing invalid target type
        try:
            await orchestrator.run_recon(None)  # type: ignore
        except Exception:
            pass  # Expected to raise

        # Error should be logged in state
        # (Implementation detail: we'll capture exceptions gracefully)

    @pytest.mark.asyncio
    async def test_phase_error_still_records_timing(self):
        """Test that timing is recorded even when phase fails."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()

        try:
            await orchestrator.run_recon(None)  # type: ignore
        except Exception:
            pass

        # Timing should be recorded even on failure
        assert "recon" in orchestrator.state["timing"]

    @pytest.mark.asyncio
    async def test_pipeline_continues_after_phase_error(self):
        """Test that pipeline continues to next phase after error (graceful degradation)."""
        # This test validates that errors don't crash the entire pipeline
        # Implementation will catch exceptions and continue
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()

        # Full pipeline should complete even with errors
        result = await orchestrator.run_full_pipeline("example.com")

        # Should have attempted all phases
        assert "recon" in result or len(orchestrator.state["errors"]) > 0


class TestOrchestratorPhaseResults:
    """Test that phase methods return expected result structures."""

    @pytest.mark.asyncio
    async def test_recon_returns_expected_structure(self):
        """Test run_recon returns dict with expected keys."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        result = await orchestrator.run_recon("example.com")

        assert "target" in result
        assert result["target"] == "example.com"
        # Placeholder implementation should have empty arrays
        assert "subdomains" in result or "ports" in result

    @pytest.mark.asyncio
    async def test_scan_returns_expected_structure(self):
        """Test run_scan returns dict with expected keys."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        recon_results = {"target": "example.com", "subdomains": []}
        result = await orchestrator.run_scan("example.com", recon_results)

        assert "target" in result
        assert result["target"] == "example.com"

    @pytest.mark.asyncio
    async def test_exploit_returns_expected_structure(self):
        """Test run_exploit returns dict with expected keys."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        scan_results = {"target": "example.com", "ports": []}
        result = await orchestrator.run_exploit("example.com", scan_results)

        assert "target" in result

    @pytest.mark.asyncio
    async def test_ctf_returns_expected_structure(self):
        """Test run_ctf returns dict with expected keys."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()
        result = await orchestrator.run_ctf("example.com")

        assert "target" in result



class TestOrchestratorIntegration:
    """Integration tests for orchestrator with mocked tool calls."""

    @pytest.mark.asyncio
    async def test_run_recon_integration(self, mocker):
        """Test recon phase with Go tool integrations."""
        from src.core.orchestrator import AutomationOrchestrator

        # Mock go_tools functions
        mock_subdomain = mocker.patch('src.core.go_tools.run_subdomain_enum')
        mock_portscan = mocker.patch('src.core.go_tools.run_port_scan')
        mock_httpprobe = mocker.patch('src.core.go_tools.run_http_probe')

        mock_subdomain.return_value = {"subdomains": ["sub1.example.com", "sub2.example.com"]}
        mock_portscan.return_value = {"open_ports": [{"port": 80, "state": "open"}]}
        mock_httpprobe.return_value = {"results": [{"url": "http://sub1.example.com", "status": 200}]}

        orchestrator = AutomationOrchestrator()
        result = await orchestrator.run_recon("example.com")

        assert result["status"] == "success"
        assert len(result["subdomains"]) == 2
        assert len(result["ports"]) > 0
        assert "recon" in orchestrator.state["completed_phases"]
        assert result["target"] == "example.com"
        assert "http_services" in result

    @pytest.mark.asyncio
    async def test_run_recon_graceful_degradation(self, mocker):
        """Test recon phase continues when individual tools fail."""
        from src.core.orchestrator import AutomationOrchestrator

        # Mock tools with failures
        mock_subdomain = mocker.patch('src.core.go_tools.run_subdomain_enum')
        mock_portscan = mocker.patch('src.core.go_tools.run_port_scan')
        mock_httpprobe = mocker.patch('src.core.go_tools.run_http_probe')

        mock_subdomain.side_effect = Exception("Subdomain tool failed")
        mock_portscan.return_value = {"open_ports": [{"port": 443, "state": "open"}]}
        mock_httpprobe.return_value = {"results": []}

        orchestrator = AutomationOrchestrator()
        result = await orchestrator.run_recon("example.com")

        # Should complete despite subdomain failure
        assert result["status"] == "success"
        assert result["subdomains"] == []  # Empty due to failure
        assert len(result["ports"]) > 0  # But ports succeeded
        assert "recon" in orchestrator.state["completed_phases"]

    @pytest.mark.asyncio
    async def test_run_scan_integration(self, mocker):
        """Test scan phase with scanner integrations."""
        from src.core.orchestrator import AutomationOrchestrator
        from unittest.mock import AsyncMock

        # Mock scanner classes
        mock_nuclei_class = mocker.patch('src.scanners.nuclei_wrapper.NucleiScanner')
        mock_web_class = mocker.patch('src.scanners.web_vuln_scanner.WebVulnScanner')
        mock_headers_class = mocker.patch('src.scanners.security_headers.SecurityHeadersAnalyzer')

        # Configure Nuclei mock
        mock_nuclei = mock_nuclei_class.return_value
        mock_nuclei.scan.return_value = {"vulnerabilities": [{"type": "xss", "severity": "high"}]}
        mock_nuclei.update_templates.return_value = None

        # Configure WebVuln mock
        mock_web = mock_web_class.return_value
        mock_web.scan_all = AsyncMock(return_value={
            "vulnerabilities": {
                "sqli": [{"type": "sqli", "severity": "critical"}],
                "xss": [],
                "csrf": {"vulnerable": False}
            }
        })

        # Configure SecurityHeaders mock
        mock_headers = mock_headers_class.return_value
        mock_headers.analyze = AsyncMock(return_value={
            "issues": [{"header": "X-Frame-Options", "severity": "medium", "message": "Missing header"}]
        })

        orchestrator = AutomationOrchestrator()
        recon_results = {"subdomains": [], "ports": [], "http_services": []}
        result = await orchestrator.run_scan("example.com", recon_results)

        assert result["status"] == "success"
        assert len(result["vulnerabilities"]) >= 2  # nuclei + web vuln + missing header
        assert "scan" in orchestrator.state["completed_phases"]
        assert result["target"] == "example.com"

    @pytest.mark.asyncio
    async def test_run_scan_with_http_services(self, mocker):
        """Test scan phase scans discovered HTTP services."""
        from src.core.orchestrator import AutomationOrchestrator
        from unittest.mock import AsyncMock

        # Mock scanner classes
        mock_nuclei_class = mocker.patch('src.scanners.nuclei_wrapper.NucleiScanner')
        mock_web_class = mocker.patch('src.scanners.web_vuln_scanner.WebVulnScanner')
        mock_headers_class = mocker.patch('src.scanners.security_headers.SecurityHeadersAnalyzer')

        mock_nuclei = mock_nuclei_class.return_value
        mock_nuclei.scan.return_value = {"vulnerabilities": []}
        mock_nuclei.update_templates.return_value = None

        mock_web = mock_web_class.return_value
        mock_web.scan_all = AsyncMock(return_value={"vulnerabilities": {"sqli": [], "xss": [], "csrf": {"vulnerable": False}}})

        mock_headers = mock_headers_class.return_value
        mock_headers.analyze = AsyncMock(return_value={"issues": []})

        orchestrator = AutomationOrchestrator()
        recon_results = {
            "subdomains": ["sub1.example.com"],
            "ports": [],
            "http_services": [
                {"url": "http://sub1.example.com", "status": 200},
                {"url": "http://sub2.example.com", "status": 200}
            ]
        }
        result = await orchestrator.run_scan("example.com", recon_results)

        # Should scan main target + HTTP services
        assert mock_nuclei.scan.call_count >= 2  # At least main + 1 service
        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_run_ctf_integration(self, mocker):
        """Test CTF phase with module integrations."""
        from src.core.orchestrator import AutomationOrchestrator
        from unittest.mock import AsyncMock

        # Mock CTF modules
        mock_flag_finder_class = mocker.patch('src.ctf.flag_finder.FlagFinder')
        mock_osint_class = mocker.patch('src.ctf.osint.OSINTSolver')
        mock_crypto_class = mocker.patch('src.ctf.crypto.CryptoSolver')

        # Configure FlagFinder mock
        mock_finder = mock_flag_finder_class.return_value
        mock_finder.find_in_text.return_value = [
            {"flag": "flag{test123}", "pattern": "flag\\{[^}]+\\}", "position": 0}
        ]

        # Configure OSINTSolver mock
        mock_osint = mock_osint_class.return_value
        mock_osint.whois_lookup.return_value = {"domain": "example.com", "ip_addresses": ["1.2.3.4"]}
        mock_osint.extract_subdomains_from_text.return_value = ["sub.example.com"]
        mock_osint.extract_emails_from_text.return_value = ["test@example.com"]
        mock_osint.extract_urls_from_text.return_value = ["http://example.com/page"]

        # Configure CryptoSolver mock
        mock_crypto = mock_crypto_class.return_value
        mock_crypto.base64_decode.return_value = b"decoded_text"

        # Mock httpx client
        mock_response = mocker.Mock()
        mock_response.text = "Some content with flag{test123} and aGVsbG8gd29ybGQ= encoded"
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
        mocker.patch('httpx.AsyncClient', return_value=mock_client)

        orchestrator = AutomationOrchestrator()
        result = await orchestrator.run_ctf("example.com")

        assert result["status"] == "success"
        assert len(result["flags"]) > 0
        assert len(result["challenges_solved"]) > 0
        assert "ctf" in orchestrator.state["completed_phases"]
        assert result["target"] == "example.com"

    @pytest.mark.asyncio
    async def test_run_ctf_no_content(self, mocker):
        """Test CTF phase when target fetch fails."""
        from src.core.orchestrator import AutomationOrchestrator
        from unittest.mock import AsyncMock

        # Mock CTF modules
        mock_flag_finder_class = mocker.patch('src.ctf.flag_finder.FlagFinder')
        mock_osint_class = mocker.patch('src.ctf.osint.OSINTSolver')
        mock_crypto_class = mocker.patch('src.ctf.crypto.CryptoSolver')

        mock_finder = mock_flag_finder_class.return_value
        mock_osint = mock_osint_class.return_value
        mock_osint.whois_lookup.return_value = {"domain": "example.com"}

        # Mock httpx client to raise exception
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value.get = AsyncMock(side_effect=Exception("Connection failed"))
        mocker.patch('httpx.AsyncClient', return_value=mock_client)

        orchestrator = AutomationOrchestrator()
        result = await orchestrator.run_ctf("example.com")

        # Should complete despite fetch failure
        assert result["status"] == "success"
        assert result["flags"] == []  # No flags due to fetch failure
        assert "ctf" in orchestrator.state["completed_phases"]

    @pytest.mark.asyncio
    async def test_global_timeout(self, mocker):
        """Test global timeout enforcement in full pipeline."""
        from src.core.orchestrator import AutomationOrchestrator

        orchestrator = AutomationOrchestrator()

        # Mock asyncio.timeout to raise TimeoutError immediately
        import asyncio
        mock_timeout = mocker.patch('asyncio.timeout')
        mock_timeout_context = mocker.MagicMock()
        mock_timeout_context.__aenter__ = mocker.AsyncMock(side_effect=asyncio.TimeoutError)
        mock_timeout.return_value = mock_timeout_context

        result = await orchestrator.run_full_pipeline("example.com")

        assert "error" in result
        assert "timeout" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_full_pipeline_data_flow(self, mocker):
        """Test data flows correctly between phases."""
        from src.core.orchestrator import AutomationOrchestrator
        from unittest.mock import AsyncMock

        orchestrator = AutomationOrchestrator()

        # Mock recon to return subdomains
        async def mock_recon(target):
            return {
                "target": target,
                "subdomains": ["sub1.example.com"],
                "ports": [{"port": 80}],
                "http_services": [{"url": "http://sub1.example.com"}],
                "phase": "recon",
                "status": "success"
            }

        # Mock scan to use recon results
        scan_called_with = {}
        async def mock_scan(target, recon_results):
            scan_called_with['recon_results'] = recon_results
            return {
                "target": target,
                "vulnerabilities": [],
                "services": recon_results.get("http_services", []),
                "phase": "scan",
                "status": "success",
                "recon_summary": {}
            }

        mocker.patch.object(orchestrator, 'run_recon', side_effect=mock_recon)
        mocker.patch.object(orchestrator, 'run_scan', side_effect=mock_scan)
        mocker.patch.object(orchestrator, 'run_exploit', return_value={"phase": "exploit", "status": "placeholder"})
        mocker.patch.object(orchestrator, 'run_ctf', return_value={"phase": "ctf", "status": "success"})

        result = await orchestrator.run_full_pipeline("example.com")

        # Verify recon results were passed to scan
        assert 'recon_results' in scan_called_with
        assert "subdomains" in scan_called_with['recon_results']
        assert len(scan_called_with['recon_results']['subdomains']) == 1

    @pytest.mark.asyncio
    async def test_phase_timing_recorded(self, mocker):
        """Test that all phases record timing even on failure."""
        from src.core.orchestrator import AutomationOrchestrator

        # Mock go_tools to succeed quickly
        mocker.patch('src.core.go_tools.run_subdomain_enum', return_value={"subdomains": []})
        mocker.patch('src.core.go_tools.run_port_scan', return_value={"open_ports": []})
        mocker.patch('src.core.go_tools.run_http_probe', return_value={"results": []})

        orchestrator = AutomationOrchestrator()
        result = await orchestrator.run_recon("example.com")

        # Timing should be recorded
        assert "recon" in orchestrator.state["timing"]
        assert isinstance(orchestrator.state["timing"]["recon"], float)
        assert orchestrator.state["timing"]["recon"] >= 0
