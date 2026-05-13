"""
Target Parser for AI-Pentester
Parses and expands target specifications (URL, domain, wildcard).
"""

import re
import requests
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Optional

class TargetParser:
    """
    Parse various target input formats and expand to concrete URLs.
    
    Supported formats:
    - URL: http://example.com
    - Domain: example.com
    - Wildcard: *.example.com
    """
    
    def __init__(self, config=None):
        self.config = config or {}
        self.default_protocols = ["https", "http"]
        self.subdomain_sources = [
            "crt.sh",  # Certificate Transparency logs
        ]
    
    def parse(self, target_spec: str) -> Dict:
        """
        Parse target specification and return target info.
        
        Returns:
            {
                "type": "url" | "domain" | "wildcard",
                "original": original input,
                "targets": list of concrete URLs,
                "base_domain": the root domain
            }
        """
        target_spec = target_spec.strip()
        
        # Wildcard target: *.example.com
        if target_spec.startswith("*."):
            return self._parse_wildcard(target_spec)
        
        # Full URL: http(s)://example.com/path
        if target_spec.startswith(("http://", "https://")):
            return self._parse_url(target_spec)
        
        # Domain only: example.com
        return self._parse_domain(target_spec)
    
    def _parse_url(self, url: str) -> Dict:
        """Parse a full URL."""
        parsed = urlparse(url)
        return {
            "type": "url",
            "original": url,
            "targets": [url],
            "base_domain": parsed.netloc,
            "protocol": parsed.scheme
        }
    
    def _parse_domain(self, domain: str) -> Dict:
        """Parse a domain and expand to URLs."""
        # Remove any path components
        domain = domain.split("/")[0]
        
        # Try both protocols
        targets = []
        for protocol in self.default_protocols:
            url = f"{protocol}://{domain}"
            if self._is_reachable(url):
                targets.append(url)
                break
        
        if not targets:
            # Default to https if nothing is reachable
            targets = [f"https://{domain}"]
        
        return {
            "type": "domain",
            "original": domain,
            "targets": targets,
            "base_domain": domain,
            "protocol": urlparse(targets[0]).scheme if targets else "https"
        }
    
    def _parse_wildcard(self, wildcard: str) -> Dict:
        """Parse wildcard and enumerate subdomains."""
        # Extract base domain from *.example.com
        base_domain = wildcard[2:]  # Remove "*."
        
        # Enumerate subdomains
        subdomains = self._enumerate_subdomains(base_domain)
        
        # Build target URLs
        targets = []
        for subdomain in subdomains:
            for protocol in self.default_protocols:
                url = f"{protocol}://{subdomain}"
                if self._is_reachable(url):
                    targets.append(url)
                    break
        
        # Always include the base domain
        base_url = f"https://{base_domain}"
        if base_url not in targets:
            targets.insert(0, base_url)
        
        return {
            "type": "wildcard",
            "original": wildcard,
            "targets": targets,
            "base_domain": base_domain,
            "subdomains_found": len(subdomains)
        }
    
    def _enumerate_subdomains(self, domain: str) -> List[str]:
        """
        Enumerate subdomains using certificate transparency logs.
        """
        subdomains = set()
        subdomains.add(domain)  # Always include base domain
        
        # crt.sh API
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    # Handle wildcard entries and multiple names
                    for sub in name.split("\n"):
                        sub = sub.strip()
                        if sub and not sub.startswith("*"):
                            subdomains.add(sub.lower())
        except Exception as _e:
            import logging; logging.getLogger(__name__).debug(f'[target_parser] subdomain parse error: {_e}')
        
        # Common subdomain wordlist (fallback)
        common_subs = [
            "www", "api", "app", "admin", "dev", "staging",
            "test", "beta", "mail", "login", "portal", "secure"
        ]
        
        for sub in common_subs:
            subdomains.add(f"{sub}.{domain}")
        
        return list(subdomains)[:50]  # Limit to 50 subdomains
    
    def _is_reachable(self, url: str, timeout: int = 5) -> bool:
        """Check if URL is reachable."""
        try:
            response = requests.head(url, timeout=timeout, allow_redirects=True)
            return response.status_code < 500
        except Exception as _e:
            return False
    
    def expand_targets(self, target_spec: str) -> List[str]:
        """
        Convenience method to get list of target URLs.
        """
        result = self.parse(target_spec)
        return result["targets"]


def parse_target(target_spec: str) -> Dict:
    """Convenience function for parsing targets."""
    parser = TargetParser()
    return parser.parse(target_spec)
