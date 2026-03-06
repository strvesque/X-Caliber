"""Tests for CTF OSINT Module."""
import pytest
from src.ctf.osint import OSINTSolver


class TestWHOISLookup:
    def test_whois_structure(self):
        """Test WHOIS result structure."""
        solver = OSINTSolver()
        result = solver.whois_lookup("example.com")
        
        assert "domain" in result
        assert "ip_addresses" in result
        assert "timestamp" in result
        assert result["domain"] == "example.com"
    
    def test_whois_invalid_domain(self):
        """Test WHOIS with invalid domain."""
        solver = OSINTSolver()
        result = solver.whois_lookup("this-domain-definitely-does-not-exist-12345.com")
        
        assert "errors" in result
        # Should have error for DNS lookup failure


class TestSubdomainExtraction:
    def test_extract_subdomains_basic(self):
        solver = OSINTSolver()
        text = "Found subdomains: www.example.com, api.example.com, mail.example.com"
        subdomains = solver.extract_subdomains_from_text(text, "example.com")
        
        assert "www.example.com" in subdomains
        assert "api.example.com" in subdomains
        assert "mail.example.com" in subdomains
    
    def test_extract_subdomains_nested(self):
        solver = OSINTSolver()
        text = "Check out api.staging.example.com"
        subdomains = solver.extract_subdomains_from_text(text, "example.com")
        
        assert "api.staging.example.com" in subdomains
    
    def test_extract_subdomains_case_insensitive(self):
        solver = OSINTSolver()
        text = "WWW.EXAMPLE.COM and www.example.com"
        subdomains = solver.extract_subdomains_from_text(text, "example.com")
        
        # Should deduplicate (both lowercase)
        assert len([s for s in subdomains if s == "www.example.com"]) == 1
    
    def test_extract_subdomains_no_matches(self):
        solver = OSINTSolver()
        text = "No subdomains here, just example.org"
        subdomains = solver.extract_subdomains_from_text(text, "example.com")
        
        assert len(subdomains) == 0


class TestEmailExtraction:
    def test_extract_emails_basic(self):
        solver = OSINTSolver()
        text = "Contact us at admin@example.com or support@example.org"
        emails = solver.extract_emails_from_text(text)
        
        assert "admin@example.com" in emails
        assert "support@example.org" in emails
    
    def test_extract_emails_various_formats(self):
        solver = OSINTSolver()
        text = "user.name+tag@sub.domain.com"
        emails = solver.extract_emails_from_text(text)
        
        assert "user.name+tag@sub.domain.com" in emails
    
    def test_extract_emails_none_found(self):
        solver = OSINTSolver()
        text = "No emails in this text"
        emails = solver.extract_emails_from_text(text)
        
        assert len(emails) == 0


class TestURLExtraction:
    def test_extract_urls_http_and_https(self):
        solver = OSINTSolver()
        text = "Visit https://example.com and http://test.org"
        urls = solver.extract_urls_from_text(text)
        
        assert "https://example.com" in urls
        assert "http://test.org" in urls
    
    def test_extract_urls_with_paths(self):
        solver = OSINTSolver()
        text = "API: https://api.example.com/v1/users?id=123"
        urls = solver.extract_urls_from_text(text)
        
        assert "https://api.example.com/v1/users?id=123" in urls
    
    def test_extract_urls_none_found(self):
        solver = OSINTSolver()
        text = "Just plain text without URLs"
        urls = solver.extract_urls_from_text(text)
        
        assert len(urls) == 0


class TestIPExtraction:
    def test_extract_ips_basic(self):
        solver = OSINTSolver()
        text = "Server IPs: 192.168.1.1, 10.0.0.1, 8.8.8.8"
        ips = solver.extract_ip_addresses(text)
        
        assert "192.168.1.1" in ips
        assert "10.0.0.1" in ips
        assert "8.8.8.8" in ips
    
    def test_extract_ips_validates_ranges(self):
        solver = OSINTSolver()
        text = "Invalid: 999.999.999.999, Valid: 127.0.0.1"
        ips = solver.extract_ip_addresses(text)
        
        assert "127.0.0.1" in ips
        assert "999.999.999.999" not in ips
    
    def test_extract_ips_none_found(self):
        solver = OSINTSolver()
        text = "No IP addresses here"
        ips = solver.extract_ip_addresses(text)
        
        assert len(ips) == 0


class TestCertificateAnalysis:
    def test_analyze_cert_extracts_cn(self):
        solver = OSINTSolver()
        cert_text = "Subject: CN=example.com, O=Example Org"
        result = solver.analyze_certificate_info(cert_text)
        
        assert result["common_name"] == "example.com"
        assert result["organization"] == "Example Org"
    
    def test_analyze_cert_extracts_san(self):
        solver = OSINTSolver()
        cert_text = "Subject Alternative Name: DNS:www.example.com, DNS:api.example.com"
        result = solver.analyze_certificate_info(cert_text)
        
        assert "www.example.com" in result["subject_alt_names"]
        assert "api.example.com" in result["subject_alt_names"]
    
    def test_analyze_cert_extracts_emails(self):
        solver = OSINTSolver()
        cert_text = "Contact: admin@example.com"
        result = solver.analyze_certificate_info(cert_text)
        
        assert "admin@example.com" in result["emails"]
    
    def test_analyze_cert_aggregates_domains(self):
        solver = OSINTSolver()
        cert_text = "CN=example.com, SANs: www.example.com, Also: api.example.org"
        result = solver.analyze_certificate_info(cert_text)
        
        # Should collect all valid domains
        assert "example.com" in result["domains"]
        assert "www.example.com" in result["domains"]


class TestDomainValidation:
    def test_is_valid_domain_accepts_valid(self):
        solver = OSINTSolver()
        assert solver._is_valid_domain("example.com")
        assert solver._is_valid_domain("sub.example.com")
        assert solver._is_valid_domain("a.b.c.example.org")
    
    def test_is_valid_domain_rejects_invalid(self):
        solver = OSINTSolver()
        assert not solver._is_valid_domain("")
        assert not solver._is_valid_domain("not-a-domain")
        assert not solver._is_valid_domain(".example.com")
        assert not solver._is_valid_domain("example.")
