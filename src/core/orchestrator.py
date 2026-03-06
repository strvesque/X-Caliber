"""Core orchestration engine for automation phases."""

from __future__ import annotations


import asyncio
import logging
import re
import time
from typing import Any, Dict, List, cast

import httpx

logger = logging.getLogger("x_caliber.orchestrator")


class AutomationOrchestrator:
    """Orchestrates automation phases: recon → scan → exploit → ctf → report.

    Manages async execution, state tracking, error handling, and timing for all phases.
    Each phase can be run independently or chained through run_full_pipeline.

    State Management:
        - current_phase: Name of currently executing phase
        - completed_phases: List of successfully completed phases
        - errors: List of errors encountered during execution
        - timing: Dict mapping phase names to execution duration (seconds)

    Example:
        orchestrator = AutomationOrchestrator()
        results = await orchestrator.run_full_pipeline("example.com")
        # Results contains data from all phases: recon, scan, exploit, ctf
    """

    def __init__(self) -> None:
        """Initialize orchestrator with empty state."""
        self.state: Dict[str, Any] = {
            "current_phase": None,
            "completed_phases": [],
            "errors": [],
            "timing": {},
        }
        logger.info("AutomationOrchestrator initialized")

    async def run_recon(self, target: str) -> Dict[str, Any]:
        """Run reconnaissance phase.

        Integrates Wave 2 Go tools:
        - Subdomain enumeration (xcal-subdomain)
        - Port scanning (xcal-portscan)
        - HTTP probing (xcal-httpprobe)

        Args:
            target: Target domain or IP address

        Returns:
            Dict containing recon results:
                - target: Target identifier
                - subdomains: List of discovered subdomains
                - ports: List of open ports
                - http_services: List of HTTP services

        Raises:
            Exception: If recon phase fails critically
        """
        self.state["current_phase"] = "recon"
        start_time = time.time()
        logger.info(f"Starting recon phase for {target}")

        try:
            from src.core.go_tools import run_subdomain_enum, run_port_scan, run_http_probe

            # Subdomain enumeration
            subdomains = []
            try:
                subdomain_result = run_subdomain_enum(target, timeout=300)
                subdomains = subdomain_result.get("subdomains", [])
                logger.info(f"Discovered {len(subdomains)} subdomains")
            except Exception as e:
                logger.warning(f"Subdomain enumeration failed: {e}")

            # Port scanning (scan main target + first 5 subdomains)
            targets_to_scan = [target] + subdomains[:5]
            all_open_ports = []
            for scan_target in targets_to_scan:
                try:
                    port_result = run_port_scan(scan_target, ports="1-1000", timeout=300)
                    all_open_ports.extend(port_result.get("open_ports", []))
                except Exception as e:
                    logger.warning(f"Port scan failed for {scan_target}: {e}")

            # HTTP probing (probe all discovered subdomains)
            http_targets = []
            if subdomains:
                try:
                    # Prepare URLs for http prober (add http:// prefix)
                    probe_urls = [f"http://{sub}" for sub in subdomains[:10]]
                    http_result = run_http_probe(probe_urls, timeout=300)
                    http_targets = http_result.get("results", [])
                except Exception as e:
                    logger.warning(f"HTTP probing failed: {e}")

            result = {
                "target": target,
                "subdomains": subdomains,
                "ports": all_open_ports,
                "http_services": http_targets,
                "phase": "recon",
                "status": "success",
            }

            self.state["completed_phases"].append("recon")
            logger.info(f"Recon phase completed for {target}")
            return result

        except Exception as e:
            error_detail = {"phase": "recon", "error": str(e), "target": target}
            self.state["errors"].append(error_detail)
            logger.error(f"Recon phase failed for {target}: {e}")
            raise

        finally:
            duration = time.time() - start_time
            self.state["timing"]["recon"] = duration
            logger.debug(f"Recon phase duration: {duration:.2f}s")
    async def run_scan(self, target: str, recon_results: Dict[str, Any]) -> Dict[str, Any]:
        """Run vulnerability scanning phase.

        Integrates Wave 3 scanners:
        - Nuclei vulnerability scanner
        - Custom web vulnerability scanner (SQLi/XSS/CSRF)
        - Security headers analyzer

        Args:
            target: Target domain or IP address
            recon_results: Output from run_recon() containing subdomains/ports

        Returns:
            Dict containing scan results:
                - target: Target identifier
                - vulnerabilities: List of discovered vulnerabilities
                - services: Detected services

        Raises:
            Exception: If scan phase fails critically
        """
        self.state["current_phase"] = "scan"
        start_time = time.time()
        logger.info(f"Starting scan phase for {target}")

        try:
            from src.scanners.nuclei_wrapper import NucleiScanner
            from src.scanners.web_vuln_scanner import WebVulnScanner
            from src.scanners.security_headers import SecurityHeadersAnalyzer

            vulnerabilities = []

            # Build list of targets to scan (main target + discovered HTTP services)
            targets_to_scan = [target]
            http_services = recon_results.get("http_services", [])
            if http_services:
                targets_to_scan.extend([svc.get("url") for svc in http_services[:5] if svc.get("url")])

            # Nuclei scan
            for scan_target in targets_to_scan:
                try:
                    nuclei = NucleiScanner()
                    nuclei.update_templates()  # Auto-update if stale
                    nuclei_results = nuclei.scan(scan_target, severity=["critical", "high", "medium"])
                    nuclei_vulns = cast(List[Any], nuclei_results.get("vulnerabilities", []))
                    vulnerabilities.extend(nuclei_vulns)
                except Exception as e:
                    logger.warning(f"Nuclei scan failed for {scan_target}: {e}")

            # Custom web vulnerability scanner
            for scan_target in targets_to_scan:
                try:
                    web_scanner = WebVulnScanner()
                    web_results = await web_scanner.scan_all(scan_target)
                    # Flatten the vulnerabilities dict structure
                    web_vulns = web_results.get("vulnerabilities", {})
                    vulnerabilities.extend(web_vulns.get("sqli", []))
                    vulnerabilities.extend(web_vulns.get("xss", []))
                    csrf = web_vulns.get("csrf", {})
                    if csrf.get("vulnerable"):
                        vulnerabilities.append({
                            "type": "csrf",
                            "severity": csrf.get("severity", "medium"),
                            "target": scan_target,
                            "forms_without_csrf": csrf.get("forms_without_csrf", [])
                        })
                except Exception as e:
                    logger.warning(f"Web vuln scan failed for {scan_target}: {e}")

            # Security headers analysis
            for scan_target in targets_to_scan:
                try:
                    headers_analyzer = SecurityHeadersAnalyzer()
                    headers_results = await headers_analyzer.analyze(scan_target)
                    # Convert missing headers to vulnerabilities
                    for issue in headers_results.get("issues", []):
                        vulnerabilities.append({
                            "type": "missing_security_header",
                            "severity": issue.get("severity", "low"),
                            "header": issue.get("header"),
                            "message": issue.get("message"),
                            "target": scan_target
                        })
                except Exception as e:
                    logger.warning(f"Security headers analysis failed for {scan_target}: {e}")

            result = {
                "target": target,
                "vulnerabilities": vulnerabilities,
                "services": recon_results.get("http_services", []),
                "phase": "scan",
                "status": "success",
                "recon_summary": {
                    "subdomains_scanned": len(recon_results.get("subdomains", [])),
                    "ports_scanned": len(recon_results.get("ports", [])),
                },
            }

            self.state["completed_phases"].append("scan")
            logger.info(f"Scan phase completed for {target}: {len(vulnerabilities)} vulnerabilities found")
            return result

        except Exception as e:
            error_detail = {"phase": "scan", "error": str(e), "target": target}
            self.state["errors"].append(error_detail)
            logger.error(f"Scan phase failed for {target}: {e}")
            raise

        finally:
            duration = time.time() - start_time
            self.state["timing"]["scan"] = duration
            logger.debug(f"Scan phase duration: {duration:.2f}s")
    async def run_exploit(
        self, target: str, scan_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Run exploitation phase.

        Placeholder implementation for Wave 1. Wave 2 will integrate:
        - Metasploit integration
        - Custom exploit scripts
        - Credential stuffing
        - Privilege escalation

        Args:
            target: Target domain or IP address
            scan_results: Output from run_scan() containing vulnerabilities

        Returns:
            Dict containing exploit results:
                - target: Target identifier
                - successful_exploits: List of successful exploits
                - shells: Active shell sessions

        Raises:
            Exception: If exploit phase fails critically
        """
        self.state["current_phase"] = "exploit"
        start_time = time.time()
        logger.info(f"Starting exploit phase for {target}")

        try:
            # Placeholder for Wave 1 - actual implementation in Wave 2
            # Future: Use scan_results to target specific vulnerabilities
            result = {
                "target": target,
                "successful_exploits": [],
                "shells": [],
                "phase": "exploit",
                "status": "placeholder",
                "scan_summary": {
                    "vulnerabilities_tested": len(
                        scan_results.get("vulnerabilities", [])
                    ),
                },
            }

            self.state["completed_phases"].append("exploit")
            logger.info(f"Exploit phase completed for {target}")
            return result

        except Exception as e:
            error_detail = {"phase": "exploit", "error": str(e), "target": target}
            self.state["errors"].append(error_detail)
            logger.error(f"Exploit phase failed for {target}: {e}")
            raise

        finally:
            duration = time.time() - start_time
            self.state["timing"]["exploit"] = duration
            logger.debug(f"Exploit phase duration: {duration:.2f}s")

    async def run_ctf(self, target: str) -> Dict[str, Any]:
        """Run CTF-specific automation phase.

        Integrates Wave 5 CTF modules:
        - Flag pattern detection
        - Crypto challenge solvers
        - OSINT gathering

        Args:
            target: Target challenge or server

        Returns:
            Dict containing CTF results:
                - target: Target identifier
                - flags: Discovered flags
                - challenges_solved: List of solved challenges

        Raises:
            Exception: If CTF phase fails critically
        """
        self.state["current_phase"] = "ctf"
        start_time = time.time()
        logger.info(f"Starting CTF phase for {target}")

        try:
            from src.ctf.crypto import CryptoSolver
            from src.ctf.osint import OSINTSolver
            from src.ctf.flag_finder import FlagFinder

            flags = []
            challenges_solved = []

            # Fetch target content for flag detection
            content = ""
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.get(f"http://{target}")
                    content = response.text

                    # Flag detection
                    finder = FlagFinder()
                    found_flags = finder.find_in_text(content)
                    flags.extend(found_flags)
                    logger.info(f"Found {len(found_flags)} flags in {target}")
            except Exception as e:
                logger.warning(f"Failed to fetch target content: {e}")

            # OSINT gathering
            try:
                osint = OSINTSolver()
                whois_data = osint.whois_lookup(target)
                subdomains = osint.extract_subdomains_from_text(content, target) if content else []
                emails = osint.extract_emails_from_text(content) if content else []
                urls = osint.extract_urls_from_text(content) if content else []
                challenges_solved.append({
                    "type": "osint",
                    "data": {
                        "whois": whois_data,
                        "subdomains": subdomains,
                        "emails": emails,
                        "urls": urls
                    }
                })
            except Exception as e:
                logger.warning(f"OSINT gathering failed: {e}")

            # Crypto challenges (if encoded strings found in content)
            if content:
                try:
                    crypto = CryptoSolver()
                    # Try common encodings on any base64-like strings
                    b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
                    matches = re.findall(b64_pattern, content)
                    for match in matches[:5]:  # Limit to first 5 matches
                        try:
                            decoded = crypto.base64_decode(match)
                            if decoded:
                                challenges_solved.append({
                                    "type": "crypto_base64",
                                    "input": match[:50],
                                    "output": decoded.decode('utf-8', errors='ignore')[:100]
                                })
                        except:
                            pass
                except Exception as e:
                    logger.warning(f"Crypto solving failed: {e}")

            result = {
                "target": target,
                "flags": flags,
                "challenges_solved": challenges_solved,
                "phase": "ctf",
                "status": "success",
            }

            self.state["completed_phases"].append("ctf")
            logger.info(f"CTF phase completed for {target}: {len(flags)} flags found")
            return result

        except Exception as e:
            error_detail = {"phase": "ctf", "error": str(e), "target": target}
            self.state["errors"].append(error_detail)
            logger.error(f"CTF phase failed for {target}: {e}")
            raise

        finally:
            duration = time.time() - start_time
            self.state["timing"]["ctf"] = duration
            logger.debug(f"CTF phase duration: {duration:.2f}s")
    async def run_full_pipeline(self, target: str) -> Dict[str, Any]:
        """Run complete automation pipeline: recon → scan → exploit → ctf.

        Chains all phases sequentially, passing results between phases.
        Implements graceful degradation - errors in one phase don't crash pipeline.
        Enforces global 10-minute (600s) timeout.

        Args:
            target: Target domain, IP, or challenge identifier

        Returns:
            Dict containing results from all phases:
                - recon: Recon phase results
                - scan: Scan phase results
                - exploit: Exploit phase results
                - ctf: CTF phase results
                - state: Final orchestrator state (timing, errors, etc.)

        Example:
            orchestrator = AutomationOrchestrator()
            results = await orchestrator.run_full_pipeline("example.com")
            print(f"Completed phases: {results['state']['completed_phases']}")
            print(f"Total time: {sum(results['state']['timing'].values())}s")
        """
        logger.info(f"Starting full automation pipeline for {target}")
        results: Dict[str, Any] = {}

        try:
            # Enforce global 10-minute timeout
            async with asyncio.timeout(600):  # 600 seconds = 10 minutes
                # Phase 1: Reconnaissance
                try:
                    results["recon"] = await self.run_recon(target)
                except Exception as e:
                    logger.warning(f"Recon phase failed, continuing pipeline: {e}")
                    results["recon"] = {"error": str(e), "phase": "recon", "status": "failed"}

                # Phase 2: Scanning
                try:
                    recon_data = results.get("recon", {})
                    results["scan"] = await self.run_scan(target, recon_data)
                except Exception as e:
                    logger.warning(f"Scan phase failed, continuing pipeline: {e}")
                    results["scan"] = {"error": str(e), "phase": "scan", "status": "failed"}

                # Phase 3: Exploitation
                try:
                    scan_data = results.get("scan", {})
                    results["exploit"] = await self.run_exploit(target, scan_data)
                except Exception as e:
                    logger.warning(f"Exploit phase failed, continuing pipeline: {e}")
                    results["exploit"] = {
                        "error": str(e),
                        "phase": "exploit",
                        "status": "failed",
                    }

                # Phase 4: CTF Automation
                try:
                    results["ctf"] = await self.run_ctf(target)
                except Exception as e:
                    logger.warning(f"CTF phase failed, continuing pipeline: {e}")
                    results["ctf"] = {"error": str(e), "phase": "ctf", "status": "failed"}

        except asyncio.TimeoutError:
            logger.error(f"Pipeline timeout (600s) exceeded for {target}")
            results["error"] = "Global timeout exceeded (10 minutes)"
            results["state"] = self.state.copy()
            return results

        # Attach final state to results
        results["state"] = self.state.copy()

        total_time = sum(self.state["timing"].values())
        logger.info(
            f"Full pipeline completed for {target} in {total_time:.2f}s " +
            f"({len(self.state['completed_phases'])}/{4} phases successful)"
        )

        return results

