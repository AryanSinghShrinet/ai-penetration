"""
Endpoint Discovery
===================
Wordlist-based discovery of hidden/undocumented endpoints.

Complements crawler.py (which follows links) by actively probing
for paths that aren't linked from the application.

Key techniques:
  1. Directory/path brute-force from wordlist
  2. Common backup/debug file discovery
  3. API versioning discovery (/v1, /v2, /v3...)
  4. HTTP method enumeration on discovered endpoints
  5. Response code analysis (200, 301, 403 → interesting; 404 → skip)
"""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Set
from urllib.parse import urljoin, urlparse

import requests


# ---------------------------------------------------------------------------
# Discovery Wordlists
# ---------------------------------------------------------------------------

COMMON_PATHS = [
    # API endpoints
    "api", "api/v1", "api/v2", "api/v3", "rest", "graphql",
    "api/users", "api/user", "api/admin", "api/config",

    # Admin panels
    "admin", "administrator", "admin/login", "admin/dashboard",
    "wp-admin", "cms", "manage", "management", "panel",
    "backend", "control", "controlpanel", "cpanel",

    # Authentication
    "login", "signin", "logout", "signup", "register",
    "auth", "authenticate", "oauth", "token", "sso",
    "forgot-password", "reset-password", "verify",

    # Common app paths
    "dashboard", "profile", "account", "settings", "preferences",
    "users", "user", "members", "member", "customers",
    "orders", "order", "cart", "checkout", "payment",

    # Files/uploads
    "upload", "uploads", "files", "file", "media",
    "images", "assets", "static", "download", "attachment",

    # Dev/debug endpoints
    "debug", "test", "dev", "development", "staging",
    "status", "health", "ping", "version", "info",
    "phpinfo.php", "info.php", "test.php",
    ".env", "config.php", "config.yaml", "config.json",
    ".git/config", ".git/HEAD", "robots.txt", "sitemap.xml",
    "swagger.json", "openapi.json", "api-docs",

    # Backup/legacy files
    "backup", "old", "bak", "temp", "tmp",
    "index.php.bak", "index.bak", "config.bak",

    # Common API patterns
    "v1", "v2", "v3", "api/health", "api/status",
    "api/docs", "api/swagger", "api/openapi",
]

# ---------------------------------------------------------------------------
# Dataset-aware wordlist loader
# ---------------------------------------------------------------------------

def _load_wordlist() -> List[str]:
    """
    Return the best available path wordlist.

    Priority:
      1. data/wordlists/web_paths.txt  (built by core/build_payload_db.py from SecLists)
      2. COMMON_PATHS fallback         (built-in ~60 paths)

    SecLists raft-large-directories.txt has 62,000+ real paths found in
    bug bounty programs — massively better discovery coverage than the
    built-in list.
    """
    from pathlib import Path as _Path
    wordlist_file = _Path(__file__).parent.parent / "data" / "wordlists" / "web_paths.txt"
    if wordlist_file.exists():
        try:
            lines = [
                l.strip() for l in
                wordlist_file.read_text(encoding="utf-8", errors="replace").splitlines()
                if l.strip() and not l.strip().startswith("#")
            ]
            if lines:
                return lines
        except Exception as _e:
            import logging; logging.getLogger(__name__).debug(f'[endpoint_discovery] wordlist read error: {_e}')
    return COMMON_PATHS


# Interesting response codes (not 404)
INTERESTING_STATUS_CODES = {200, 201, 204, 301, 302, 307, 401, 403, 405, 500, 503}


@dataclass
class DiscoveredEndpoint:
    """An endpoint found during active discovery."""
    url: str
    path: str
    status_code: int
    content_length: int
    content_type: str
    redirect_location: str
    is_interesting: bool
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


class EndpointDiscovery:
    """
    Active endpoint discovery via path brute-forcing.

    Discovers endpoints that aren't linked from the application —
    the hidden admin panels, debug endpoints, and legacy paths.
    """

    def __init__(
        self,
        session: requests.Session,
        threads: int = 20,
        timeout: int = 8,
    ):
        self.session = session
        self.threads = threads
        self.timeout = timeout
        self._discovered: List[DiscoveredEndpoint] = []
        self._seen_signatures: Set[str] = set()

    def _probe_path(self, base_url: str, path: str) -> Optional[DiscoveredEndpoint]:
        """Probe a single path and return result if interesting."""
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,  # Don't follow — record the redirect
                headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}
            )

            status = resp.status_code

            if status not in INTERESTING_STATUS_CODES:
                return None

            content_length = len(resp.content)
            content_type = resp.headers.get("Content-Type", "").split(";")[0].strip()
            redirect_location = resp.headers.get("Location", "")

            # Deduplicate by (status, length) to avoid identical error pages
            sig = f"{status}:{content_length}"
            if sig in self._seen_signatures and status == 404:
                return None
            if len(self._seen_signatures) < 5:
                self._seen_signatures.add(sig)

            notes = []
            is_interesting = status != 404

            # Flag highly interesting findings
            if status == 200:
                notes.append("accessible")
                is_interesting = True
            if status in (401, 403):
                notes.append("auth_protected")
                is_interesting = True  # 403 = exists but blocked
            if status == 500:
                notes.append("server_error")
                is_interesting = True
            if "json" in content_type:
                notes.append("json_response")
            if path.endswith((".env", ".git/config", "config.php")):
                notes.append("sensitive_file")
                is_interesting = True

            return DiscoveredEndpoint(
                url=url,
                path=path,
                status_code=status,
                content_length=content_length,
                content_type=content_type,
                redirect_location=redirect_location,
                is_interesting=is_interesting,
                notes=notes,
            )

        except requests.exceptions.ConnectionError:
            return None
        except Exception as _e:
            return None

    def discover(
        self,
        base_url: str,
        wordlist: Optional[List[str]] = None,
        logger=None,
    ) -> List[Dict]:
        """
        Run endpoint discovery against base_url.

        Returns list of interesting endpoint dicts, sorted by status code.
        """
        paths = wordlist or _load_wordlist()

        if logger:
            logger.info(f"[discovery] Starting endpoint discovery on {base_url} ({len(paths)} paths)")

        results = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._probe_path, base_url, path): path
                for path in paths
            }
            for future in as_completed(futures):
                endpoint = future.result()
                if endpoint and endpoint.is_interesting:
                    results.append(endpoint)
                    self._discovered.append(endpoint)
                    if logger:
                        logger.info(
                            f"[discovery] [{endpoint.status_code}] {endpoint.path} "
                            f"({', '.join(endpoint.notes)})"
                        )

        # Sort: 200s first, then 403s, then redirects, then errors
        priority = {200: 0, 201: 0, 204: 0, 403: 1, 401: 1, 301: 2, 302: 2, 500: 3}
        results.sort(key=lambda e: priority.get(e.status_code, 5))

        if logger:
            logger.info(
                f"[discovery] Found {len(results)} interesting paths "
                f"({sum(1 for r in results if r.status_code == 200)} accessible)"
            )

        return [r.to_dict() for r in results]

    def discover_api_versions(self, base_url: str, logger=None) -> List[Dict]:
        """Discover API versioning patterns (/v1, /v2, /api/v1, etc.)."""
        version_paths = [
            f"api/v{i}" for i in range(1, 6)
        ] + [
            f"v{i}" for i in range(1, 6)
        ] + [
            f"api/v{i}/users" for i in range(1, 4)
        ]
        return self.discover(base_url, wordlist=version_paths, logger=logger)


def discover_endpoints(
    base_url: str,
    session: requests.Session,
    logger=None,
    threads: int = 20,
) -> List[Dict]:
    """Convenience function for endpoint discovery."""
    engine = EndpointDiscovery(session=session, threads=threads)
    return engine.discover(base_url, logger=logger)
