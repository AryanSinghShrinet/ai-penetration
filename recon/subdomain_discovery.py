"""
Subdomain Discovery Engine
===========================
Discovers subdomains via:
  - DNS brute-force with a wordlist
  - Certificate Transparency logs (crt.sh)
  - Common subdomain patterns
  - Reverse DNS lookups

This was MISSING from the original project. Real bug bounty work starts here.
"""

import socket
import requests
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Optional
from urllib.parse import urlparse
from dataclasses import dataclass, asdict


# Common subdomain wordlist (top patterns found in real bug bounty)
COMMON_SUBDOMAINS = [
    "www", "api", "admin", "mail", "dev", "staging", "test", "beta",
    "app", "mobile", "portal", "dashboard", "login", "auth", "oauth",
    "static", "cdn", "media", "assets", "images", "files", "upload",
    "download", "docs", "help", "support", "status", "monitor",
    "v1", "v2", "v3", "api-v1", "api-v2", "internal", "intranet",
    "vpn", "remote", "secure", "ssl", "cloud", "aws", "azure",
    "git", "gitlab", "github", "jenkins", "ci", "cd", "build",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "smtp", "mx", "ns1", "ns2", "ftp", "sftp", "backup",
    "shop", "store", "checkout", "payment", "billing", "invoice",
    "report", "analytics", "stats", "metrics", "grafana", "kibana",
    "sandbox", "qa", "uat", "preview", "demo", "legacy",

]


def _load_subdomain_wordlist() -> list:
    """
    Return the best available subdomain wordlist.

    Priority:
      1. data/wordlists/subdomains.txt  (built from SecLists by build_payload_db.py)
         SecLists subdomains-top1million-5000.txt has 5000 real subdomain prefixes
         discovered across bug bounty programmes.
      2. COMMON_SUBDOMAINS fallback (~40 built-in entries)
    """
    from pathlib import Path as _Path
    wl = _Path(__file__).parent.parent / 'data' / 'wordlists' / 'subdomains.txt'
    if wl.exists():
        try:
            lines = [l.strip() for l in wl.read_text(encoding='utf-8', errors='replace').splitlines()
                     if l.strip() and not l.strip().startswith('#')]
            if lines:
                return lines
        except Exception as _e:
            import logging; logging.getLogger(__name__).debug(f'[subdomain_discovery] wordlist read error: {_e}')
    return COMMON_SUBDOMAINS


@dataclass
class Subdomain:
    """Represents a discovered subdomain with metadata."""
    hostname: str
    ip_address: str
    source: str          # dns_brute, crt_sh, reverse_dns
    is_live: bool
    status_code: Optional[int] = None
    server_header: Optional[str] = None
    technologies: List[str] = None

    def __post_init__(self):
        if self.technologies is None:
            self.technologies = []

    def to_dict(self) -> Dict:
        return asdict(self)


class SubdomainDiscovery:
    """
    Multi-source subdomain enumeration engine.

    Bug bounty significance: Many critical vulnerabilities live on forgotten
    subdomains — dev/staging/internal services with weaker security than prod.
    """

    def __init__(self, domain: str, threads: int = 20, timeout: int = 5):
        self.domain = self._clean_domain(domain)
        self.threads = threads
        self.timeout = timeout
        self._found: Dict[str, Subdomain] = {}
        self._lock = threading.Lock()

    def _clean_domain(self, domain: str) -> str:
        """Strip scheme and path, return bare domain."""
        parsed = urlparse(domain if "://" in domain else f"https://{domain}")
        return parsed.netloc or parsed.path.split("/")[0]

    # -------------------------------------------------------------------------
    # Source 1: Certificate Transparency (crt.sh)
    # -------------------------------------------------------------------------

    def enumerate_crt_sh(self, logger=None) -> List[str]:
        """
        Query crt.sh for Certificate Transparency log entries.
        This finds subdomains that have had TLS certificates issued.
        No network scanning — purely passive OSINT.
        """
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                entries = resp.json()
                for entry in entries:
                    name = entry.get("name_value", "")
                    # Handle wildcard and multi-domain certs
                    for part in name.split("\n"):
                        part = part.strip().lstrip("*.")
                        if part.endswith(self.domain) and part != self.domain:
                            subdomains.add(part.lower())
            if logger:
                logger.info(f"[recon] crt.sh found {len(subdomains)} subdomains for {self.domain}")
        except Exception as e:
            if logger:
                logger.warning(f"[recon] crt.sh query failed: {e}")
        return list(subdomains)

    # -------------------------------------------------------------------------
    # Source 2: DNS Brute-Force
    # -------------------------------------------------------------------------

    def _resolve_subdomain(self, subdomain: str) -> Optional[str]:
        """Attempt to resolve a subdomain. Returns IP or None."""
        hostname = f"{subdomain}.{self.domain}"
        try:
            ip = socket.gethostbyname(hostname)
            return ip
        except socket.gaierror:
            return None

    def dns_bruteforce(self, wordlist: Optional[List[str]] = None, logger=None) -> List[str]:
        """
        Brute-force subdomains via DNS resolution.
        Uses threading for speed. Safe — only DNS queries, no HTTP yet.
        """
        words = wordlist or _load_subdomain_wordlist()
        discovered = []

        def check(word):
            ip = self._resolve_subdomain(word)
            if ip:
                return f"{word}.{self.domain}", ip
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check, w): w for w in words}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    hostname, ip = result
                    discovered.append(hostname)
                    with self._lock:
                        self._found[hostname] = Subdomain(
                            hostname=hostname,
                            ip_address=ip,
                            source="dns_brute",
                            is_live=False  # HTTP check done later
                        )

        if logger:
            logger.info(f"[recon] DNS brute-force resolved {len(discovered)} subdomains")
        return discovered

    # -------------------------------------------------------------------------
    # Source 3: HTTP Liveness + Technology Detection
    # -------------------------------------------------------------------------

    def _check_liveness(self, hostname: str) -> Dict:
        """Check if a hostname is serving HTTP/HTTPS and detect basic tech."""
        result = {"live": False, "status_code": None, "server": None, "technologies": []}
        for scheme in ["https", "http"]:
            try:
                resp = requests.get(
                    f"{scheme}://{hostname}",
                    timeout=self.timeout,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; BugBounty-Recon/1.0)"}
                )
                result["live"] = True
                result["status_code"] = resp.status_code
                result["server"] = resp.headers.get("Server", "")
                result["technologies"] = self._detect_technologies(resp)
                break
            except Exception as _e:
                continue
        return result

    def _detect_technologies(self, response) -> List[str]:
        """Detect server technologies from response headers and body."""
        techs = []
        headers = response.headers

        # Server fingerprinting
        server = headers.get("Server", "").lower()
        for tech in ["nginx", "apache", "iis", "cloudflare", "caddy", "lighttpd"]:
            if tech in server:
                techs.append(tech)

        # Framework detection via headers
        if headers.get("X-Powered-By"):
            techs.append(headers["X-Powered-By"])
        if headers.get("X-Generator"):
            techs.append(headers["X-Generator"])

        # Body-based detection
        body = response.text[:2000].lower()
        tech_signatures = {
            "wordpress": ["wp-content", "wp-includes"],
            "drupal": ["drupal.js", "sites/default"],
            "joomla": ["joomla", "/components/com_"],
            "laravel": ["laravel_session"],
            "django": ["csrfmiddlewaretoken"],
            "rails": ["rails_ujs", "_rails-"],
            "react": ["react-dom", "__REACT_"],
            "angular": ["ng-version", "angular"],
            "vue": ["__vue__", "data-v-"],
        }
        for tech, patterns in tech_signatures.items():
            if any(p in body for p in patterns):
                techs.append(tech)

        return list(set(techs))

    def check_all_live(self, logger=None) -> None:
        """Run HTTP liveness checks on all discovered subdomains."""
        if not self._found:
            return

        def check(hostname):
            return hostname, self._check_liveness(hostname)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check, h): h for h in self._found}
            for future in as_completed(futures):
                hostname, liveness = future.result()
                with self._lock:
                    if hostname in self._found:
                        sub = self._found[hostname]
                        sub.is_live = liveness["live"]
                        sub.status_code = liveness["status_code"]
                        sub.server_header = liveness["server"]
                        sub.technologies = liveness["technologies"]

        live_count = sum(1 for s in self._found.values() if s.is_live)
        if logger:
            logger.info(f"[recon] {live_count}/{len(self._found)} subdomains are live")

    # -------------------------------------------------------------------------
    # Main Entry Point
    # -------------------------------------------------------------------------

    def run(self, logger=None, skip_brute: bool = False) -> List[Dict]:
        """
        Run full subdomain discovery pipeline.

        Pipeline:
          1. Passive: crt.sh CT log query
          2. Active: DNS brute-force (skip with skip_brute=True for passive-only)
          3. HTTP liveness + technology detection

        Returns list of Subdomain dicts sorted by: live first, then alphabetical.
        """
        if logger:
            logger.info(f"[recon] Starting subdomain discovery for: {self.domain}")

        # Step 1: Certificate Transparency
        ct_subs = self.enumerate_crt_sh(logger=logger)
        for hostname in ct_subs:
            ip = self._resolve_subdomain(hostname.replace(f".{self.domain}", ""))
            if hostname not in self._found:
                self._found[hostname] = Subdomain(
                    hostname=hostname,
                    ip_address=ip or "unresolved",
                    source="crt_sh",
                    is_live=False
                )

        # Step 2: DNS Brute-Force
        if not skip_brute:
            self.dns_bruteforce(logger=logger)

        # Step 3: HTTP Liveness Checks
        self.check_all_live(logger=logger)

        results = sorted(
            [s.to_dict() for s in self._found.values()],
            key=lambda x: (not x["is_live"], x["hostname"])
        )

        if logger:
            logger.info(
                f"[recon] Subdomain discovery complete: "
                f"{len(results)} found, "
                f"{sum(1 for r in results if r['is_live'])} live"
            )

        return results

    def get_live_urls(self) -> List[str]:
        """Return list of live subdomain URLs for crawling."""
        urls = []
        for sub in self._found.values():
            if sub.is_live:
                scheme = "https"
                urls.append(f"{scheme}://{sub.hostname}")
        return urls


def discover_subdomains(target: str, logger=None, threads: int = 20) -> List[Dict]:
    """Convenience wrapper for subdomain discovery."""
    engine = SubdomainDiscovery(target, threads=threads)
    return engine.run(logger=logger)
