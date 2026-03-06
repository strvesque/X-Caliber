"""CTF OSINT Module for information gathering."""
import re
import socket
from typing import Dict, Any, List
from datetime import datetime, timezone


class OSINTSolver:
    """Solver for CTF OSINT challenges."""
    
    def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """
        Simple WHOIS information gathering.
        
        Note: This is a basic implementation. For production, use python-whois library.
        Returns basic DNS and domain info.
        """
        result = {
            "domain": domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip_addresses": [],
            "mx_records": [],
            "errors": []
        }
        
        try:
            # Get IP addresses
            try:
                ip_list = socket.gethostbyname_ex(domain)
                result["ip_addresses"] = list(set(ip_list[2]))
            except socket.gaierror as e:
                result["errors"].append(f"DNS lookup failed: {str(e)}")
            
            # Basic domain validation
            if self._is_valid_domain(domain):
                result["valid_domain"] = True
                result["tld"] = domain.split('.')[-1] if '.' in domain else None
            else:
                result["valid_domain"] = False
                
        except Exception as e:
            result["errors"].append(f"WHOIS lookup error: {str(e)}")
        
        return result
    
    def extract_subdomains_from_text(self, text: str, base_domain: str) -> List[str]:
        """
        Extract subdomains of base_domain from text.
        
        Args:
            text: Text to search for subdomains
            base_domain: Base domain (e.g., "example.com")
        
        Returns:
            List of unique subdomains found
        """
        # Escape dots in domain for regex
        escaped_domain = base_domain.replace('.', r'\.')
        
        # Pattern: subdomain.base_domain
        # Subdomain can contain alphanumeric, hyphens, and nested dots
        pattern = r'\b([a-zA-Z0-9][-a-zA-Z0-9.]*\.' + escaped_domain + r')\b'
        
        matches = re.findall(pattern, text, re.IGNORECASE)
        
        # Deduplicate and sort
        subdomains = sorted(set(s.lower() for s in matches))
        
        return subdomains
    
    def extract_emails_from_text(self, text: str) -> List[str]:
        """
        Extract email addresses from text.
        
        Returns:
            List of unique email addresses found
        """
        # Email regex pattern
        pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        
        matches = re.findall(pattern, text)
        
        # Deduplicate and sort
        emails = sorted(set(e.lower() for e in matches))
        
        return emails
    
    def extract_urls_from_text(self, text: str) -> List[str]:
        """
        Extract URLs from text.
        
        Returns:
            List of unique URLs found
        """
        # URL regex pattern (http/https)
        pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        
        matches = re.findall(pattern, text)
        
        # Deduplicate
        urls = sorted(set(matches))
        
        return urls
    
    def extract_ip_addresses(self, text: str) -> List[str]:
        """
        Extract IPv4 addresses from text.
        
        Returns:
            List of unique IP addresses found
        """
        # IPv4 pattern
        pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        
        matches = re.findall(pattern, text)
        
        # Validate and deduplicate
        valid_ips = []
        for ip in matches:
            octets = ip.split('.')
            if all(0 <= int(octet) <= 255 for octet in octets):
                valid_ips.append(ip)
        
        return sorted(set(valid_ips))
    
    def analyze_certificate_info(self, cert_text: str) -> Dict[str, Any]:
        """
        Extract information from certificate text.
        
        Args:
            cert_text: Certificate content (PEM or text representation)
        
        Returns:
            Dict with extracted certificate information
        """
        result = {
            "common_name": None,
            "organization": None,
            "subject_alt_names": [],
            "issuer": None,
            "serial_number": None,
            "emails": [],
            "domains": []
        }
        
        # Extract CN (Common Name)
        cn_match = re.search(r'CN\s*=\s*([^,\n]+)', cert_text, re.IGNORECASE)
        if cn_match:
            result["common_name"] = cn_match.group(1).strip()
        
        # Extract O (Organization)
        o_match = re.search(r'\bO\s*=\s*([^,\n]+)', cert_text, re.IGNORECASE)
        if o_match:
            result["organization"] = o_match.group(1).strip()
        
        # Extract Subject Alternative Names
        san_match = re.search(r'Subject Alternative Name[:\s]+([^\n]+)', cert_text, re.IGNORECASE)
        if san_match:
            san_text = san_match.group(1)
            # Extract DNS names from SAN
            dns_names = re.findall(r'DNS:([^,\s]+)', san_text)
            result["subject_alt_names"] = dns_names
        
        # Extract emails
        result["emails"] = self.extract_emails_from_text(cert_text)
        
        # Extract domains (from CN, SAN, and general text)
        all_domains = []
        if result["common_name"]:
            all_domains.append(result["common_name"])
        all_domains.extend(result["subject_alt_names"])
        
        # Also find domain-like patterns in text
        domain_pattern = r'\b[a-z0-9][-a-z0-9.]*\.[a-z]{2,}\b'
        found_domains = re.findall(domain_pattern, cert_text, re.IGNORECASE)
        all_domains.extend(found_domains)
        
        result["domains"] = sorted(set(d.lower() for d in all_domains if self._is_valid_domain(d)))
        
        return result
    
    def _is_valid_domain(self, domain: str) -> bool:
        """
        Validate if string is a valid domain name.
        
        Returns:
            True if valid domain, False otherwise
        """
        # Basic validation
        if not domain or len(domain) > 253:
            return False
        
        # Check for valid characters and structure
        pattern = r'^[a-z0-9][-a-z0-9.]*\.[a-z]{2,}$'
        return bool(re.match(pattern, domain, re.IGNORECASE))
