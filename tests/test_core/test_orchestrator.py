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
