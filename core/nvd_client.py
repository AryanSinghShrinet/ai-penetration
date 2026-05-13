"""
NVD (National Vulnerability Database) API v2.0 Client

Features:
- Fetches CVEs from NVD with pagination
- Exponential backoff retry on failures
- Rate limiting (respects NVD guidelines)
- Comprehensive error logging
- Supports API key for higher rate limits
"""

import requests
import time
import logging
import random
from dataclasses import dataclass
from typing import List, Dict, Optional, Any, Generator
from datetime import datetime, timedelta
from pathlib import Path

from core.vuln_database import CVERecord, VulnDatabase


# Configure logging
logger = logging.getLogger("nvd_client")

# Also log to file for persistent error tracking
_log_dir = Path(__file__).parent.parent / "data" / "logs"
_log_dir.mkdir(parents=True, exist_ok=True)
_file_handler = logging.FileHandler(_log_dir / "nvd_api_errors.log")
_file_handler.setLevel(logging.WARNING)
_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(_file_handler)


@dataclass
class NVDError:
    """Represents an NVD API error."""
    error_type: str
    message: str
    status_code: Optional[int]
    url: str
    timestamp: str
    retry_count: int
    
    def to_dict(self) -> Dict:
        return {
            "error_type": self.error_type,
            "message": self.message,
            "status_code": self.status_code,
            "url": self.url,
            "timestamp": self.timestamp,
            "retry_count": self.retry_count
        }


class NVDClient:
    """
    NVD API v2.0 client for fetching CVE data.
    
    Rate Limits:
    - Without API key: 5 requests per 30 seconds (~6 sec delay)
    - With API key: 50 requests per 30 seconds (~0.6 sec delay)
    """
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Retry configuration
    MAX_RETRIES = 5
    INITIAL_BACKOFF = 1.0  # seconds
    MAX_BACKOFF = 60.0  # seconds
    BACKOFF_MULTIPLIER = 2.0
    
    # Rate limiting
    DEFAULT_DELAY = 6.0  # seconds between requests without API key
    API_KEY_DELAY = 0.6  # seconds between requests with API key
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize NVD client.
        
        Args:
            api_key: Optional NVD API key for higher rate limits.
                     Get one at https://nvd.nist.gov/developers/request-an-api-key
        """
        self.api_key = api_key
        self.session = requests.Session()
        
        if api_key:
            self.session.headers["apiKey"] = api_key
            self.request_delay = self.API_KEY_DELAY
            logger.info("NVD client initialized with API key")
        else:
            self.request_delay = self.DEFAULT_DELAY
            logger.info("NVD client initialized without API key (rate limited)")
        
        self.session.headers["User-Agent"] = "AI-Pentester/1.0"
        
        # Track errors for debugging
        self.recent_errors: List[NVDError] = []
        self._last_request_time = 0.0
    
    def _wait_for_rate_limit(self):
        """Wait to respect rate limits."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.request_delay:
            sleep_time = self.request_delay - elapsed
            logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)
        self._last_request_time = time.time()
    
    def _make_request(self, url: str, params: Dict = None) -> Optional[Dict]:
        """
        Make an API request with exponential backoff retry.
        
        Args:
            url: API endpoint URL
            params: Query parameters
            
        Returns:
            JSON response dict or None on failure
        """
        params = params or {}
        
        for attempt in range(self.MAX_RETRIES):
            try:
                self._wait_for_rate_limit()
                
                response = self.session.get(url, params=params, timeout=30)
                
                # Check for rate limiting
                if response.status_code == 403:
                    error = self._log_error(
                        "RATE_LIMITED",
                        "NVD API rate limit exceeded. Consider using an API key.",
                        response.status_code,
                        url,
                        attempt
                    )
                    # Increase delay and retry
                    backoff = self._calculate_backoff(attempt)
                    logger.warning(f"Rate limited, backing off {backoff:.1f}s")
                    time.sleep(backoff)
                    continue
                
                # Check for server errors (5xx)
                if response.status_code >= 500:
                    error = self._log_error(
                        "SERVER_ERROR",
                        f"NVD API server error: {response.status_code}",
                        response.status_code,
                        url,
                        attempt
                    )
                    backoff = self._calculate_backoff(attempt)
                    logger.warning(f"Server error, retrying in {backoff:.1f}s")
                    time.sleep(backoff)
                    continue
                
                # Check for client errors (4xx except 403)
                if response.status_code >= 400:
                    error = self._log_error(
                        "CLIENT_ERROR",
                        f"NVD API client error: {response.status_code} - {response.text[:200]}",
                        response.status_code,
                        url,
                        attempt
                    )
                    # Don't retry client errors except rate limits
                    return None
                
                # Success!
                return response.json()
                
            except requests.exceptions.Timeout as e:
                error = self._log_error(
                    "TIMEOUT",
                    f"Request timed out: {str(e)}",
                    None,
                    url,
                    attempt
                )
                backoff = self._calculate_backoff(attempt)
                logger.warning(f"Timeout, retrying in {backoff:.1f}s")
                time.sleep(backoff)
                
            except requests.exceptions.ConnectionError as e:
                error = self._log_error(
                    "CONNECTION_ERROR",
                    f"Connection failed: {str(e)}",
                    None,
                    url,
                    attempt
                )
                backoff = self._calculate_backoff(attempt)
                logger.warning(f"Connection error, retrying in {backoff:.1f}s")
                time.sleep(backoff)
                
            except requests.exceptions.RequestException as e:
                error = self._log_error(
                    "REQUEST_ERROR",
                    f"Request failed: {str(e)}",
                    None,
                    url,
                    attempt
                )
                backoff = self._calculate_backoff(attempt)
                time.sleep(backoff)
                
            except ValueError as e:
                error = self._log_error(
                    "JSON_ERROR",
                    f"Failed to parse JSON response: {str(e)}",
                    None,
                    url,
                    attempt
                )
                # JSON errors might be server issue, retry
                backoff = self._calculate_backoff(attempt)
                time.sleep(backoff)
        
        # All retries exhausted
        self._log_error(
            "MAX_RETRIES_EXHAUSTED",
            f"Failed after {self.MAX_RETRIES} attempts",
            None,
            url,
            self.MAX_RETRIES
        )
        return None
    
    def _calculate_backoff(self, attempt: int) -> float:
        """Calculate exponential backoff with jitter."""
        backoff = min(
            self.INITIAL_BACKOFF * (self.BACKOFF_MULTIPLIER ** attempt),
            self.MAX_BACKOFF
        )
        # Add jitter (±25%)
        jitter = backoff * 0.25 * (random.random() * 2 - 1)
        return backoff + jitter
    
    def _log_error(
        self,
        error_type: str,
        message: str,
        status_code: Optional[int],
        url: str,
        retry_count: int
    ) -> NVDError:
        """Log an error and store it for debugging."""
        error = NVDError(
            error_type=error_type,
            message=message,
            status_code=status_code,
            url=url,
            timestamp=datetime.utcnow().isoformat(),
            retry_count=retry_count
        )
        
        # Log to file
        logger.warning(f"NVD API Error: {error_type} - {message} (URL: {url})")
        
        # Keep recent errors in memory
        self.recent_errors.append(error)
        if len(self.recent_errors) > 100:
            self.recent_errors = self.recent_errors[-100:]
        
        return error
    
    def get_recent_errors(self) -> List[Dict]:
        """Get list of recent API errors for debugging."""
        return [e.to_dict() for e in self.recent_errors]
    
    # =========================================================================
    # CVE Fetching Methods
    # =========================================================================
    
    def fetch_cve(self, cve_id: str) -> Optional[CVERecord]:
        """
        Fetch a single CVE by ID.
        
        Args:
            cve_id: CVE ID (e.g., "CVE-2021-44228")
            
        Returns:
            CVERecord or None if not found
        """
        url = self.BASE_URL
        params = {"cveId": cve_id.upper()}
        
        data = self._make_request(url, params)
        if not data:
            return None
        
        vulnerabilities = data.get("vulnerabilities", [])
        if vulnerabilities:
            return self._parse_cve(vulnerabilities[0].get("cve", {}))
        return None
    
    def fetch_cves(
        self,
        keyword: str = None,
        cpe_name: str = None,
        cvss_v3_severity: str = None,
        pub_start_date: str = None,
        pub_end_date: str = None,
        mod_start_date: str = None,
        mod_end_date: str = None,
        results_per_page: int = 100,
        max_results: int = None
    ) -> Generator[CVERecord, None, None]:
        """
        Fetch CVEs with filters. Uses pagination.
        
        Args:
            keyword: Keyword search in CVE descriptions
            cpe_name: CPE match string
            cvss_v3_severity: LOW, MEDIUM, HIGH, or CRITICAL
            pub_start_date: ISO format date (YYYY-MM-DD)
            pub_end_date: ISO format date (YYYY-MM-DD)
            mod_start_date: Modified start date
            mod_end_date: Modified end date
            results_per_page: Results per API call (max 2000)
            max_results: Maximum total results to fetch
            
        Yields:
            CVERecord objects
        """
        params = {"resultsPerPage": min(results_per_page, 2000)}
        
        if keyword:
            params["keywordSearch"] = keyword
        if cpe_name:
            params["cpeName"] = cpe_name
        if cvss_v3_severity:
            params["cvssV3Severity"] = cvss_v3_severity.upper()
        
        # Date parameters need time component
        if pub_start_date:
            params["pubStartDate"] = f"{pub_start_date}T00:00:00.000"
        if pub_end_date:
            params["pubEndDate"] = f"{pub_end_date}T23:59:59.999"
        if mod_start_date:
            params["lastModStartDate"] = f"{mod_start_date}T00:00:00.000"
        if mod_end_date:
            params["lastModEndDate"] = f"{mod_end_date}T23:59:59.999"
        
        start_index = 0
        total_fetched = 0
        
        while True:
            params["startIndex"] = start_index
            
            logger.info(f"Fetching CVEs: startIndex={start_index}")
            data = self._make_request(self.BASE_URL, params)
            
            if not data:
                logger.error("Failed to fetch CVEs, stopping pagination")
                break
            
            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])
            
            if not vulnerabilities:
                break
            
            for vuln in vulnerabilities:
                cve = self._parse_cve(vuln.get("cve", {}))
                if cve:
                    yield cve
                    total_fetched += 1
                    
                    if max_results and total_fetched >= max_results:
                        return
            
            start_index += len(vulnerabilities)
            
            if start_index >= total_results:
                break
            
            logger.info(f"Progress: {start_index}/{total_results} CVEs")
    
    def fetch_recent_cves(self, days: int = 7, max_results: int = 500) -> Generator[CVERecord, None, None]:
        """
        Fetch CVEs published or modified in the last N days.
        
        Args:
            days: Number of days to look back
            max_results: Maximum results to fetch
            
        Yields:
            CVERecord objects
        """
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # NVD API requires max 120 days range
        if days > 120:
            days = 120
            start_date = end_date - timedelta(days=days)
            logger.warning(f"Date range limited to 120 days per NVD API requirements")
        
        yield from self.fetch_cves(
            mod_start_date=start_date.strftime("%Y-%m-%d"),
            mod_end_date=end_date.strftime("%Y-%m-%d"),
            max_results=max_results
        )
    
    def fetch_critical_cves(self, max_results: int = 200) -> Generator[CVERecord, None, None]:
        """Fetch critical severity CVEs (CVSS >= 9.0)."""
        yield from self.fetch_cves(
            cvss_v3_severity="CRITICAL",
            max_results=max_results
        )
    
    def _parse_cve(self, cve_data: Dict) -> Optional[CVERecord]:
        """Parse NVD CVE JSON into CVERecord."""
        try:
            cve_id = cve_data.get("id", "")
            if not cve_id:
                return None
            
            # Get description (prefer English)
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Parse CVSS v3
            cvss_v3_score = None
            cvss_v3_vector = None
            metrics = cve_data.get("metrics", {})
            
            # Try cvssMetricV31 first, then V30
            for v3_key in ["cvssMetricV31", "cvssMetricV30"]:
                v3_data = metrics.get(v3_key, [])
                if v3_data:
                    cvss = v3_data[0].get("cvssData", {})
                    cvss_v3_score = cvss.get("baseScore")
                    cvss_v3_vector = cvss.get("vectorString")
                    break
            
            # Parse CVSS v2 (fallback)
            cvss_v2_score = None
            cvss_v2_vector = None
            v2_data = metrics.get("cvssMetricV2", [])
            if v2_data:
                cvss = v2_data[0].get("cvssData", {})
                cvss_v2_score = cvss.get("baseScore")
                cvss_v2_vector = cvss.get("vectorString")
            
            # Parse dates
            published = cve_data.get("published", "")
            modified = cve_data.get("lastModified", "")
            
            # Parse CWEs
            cwe_ids = []
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    cwe = desc.get("value", "")
                    if cwe.startswith("CWE-"):
                        cwe_ids.append(cwe)
            
            # Parse affected products (CPEs)
            affected_products = []
            configurations = cve_data.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe in node.get("cpeMatch", []):
                        if cpe.get("vulnerable", False):
                            affected_products.append(cpe.get("criteria", ""))
            
            # Parse references
            references = []
            for ref in cve_data.get("references", []):
                url = ref.get("url", "")
                if url:
                    references.append(url)
            
            return CVERecord(
                id=cve_id,
                description=description,
                cvss_v3_score=cvss_v3_score,
                cvss_v3_vector=cvss_v3_vector,
                cvss_v2_score=cvss_v2_score,
                cvss_v2_vector=cvss_v2_vector,
                published_date=published[:10] if published else None,
                modified_date=modified[:10] if modified else None,
                cwe_ids=cwe_ids,
                affected_products=affected_products,
                references=references[:10],  # Limit references
                source="nvd"
            )
            
        except Exception as e:
            logger.error(f"Failed to parse CVE data: {e}")
            return None
    
    # =========================================================================
    # Database Sync
    # =========================================================================
    
    def sync_to_database(
        self,
        db: VulnDatabase,
        incremental: bool = True,
        days: int = 30,
        max_results: int = 5000
    ) -> Dict[str, int]:
        """
        Sync CVEs from NVD to local database.
        
        Args:
            db: VulnDatabase instance
            incremental: If True, only fetch CVEs modified since last sync
            days: Number of days to look back if not incremental
            max_results: Maximum CVEs to sync
            
        Returns:
            Dict with sync statistics
        """
        stats = {"fetched": 0, "inserted": 0, "errors": 0}
        
        if incremental:
            last_sync = db.get_last_sync("nvd")
            if last_sync:
                # Fetch CVEs modified since last sync
                days_since = (datetime.utcnow() - last_sync).days + 1
                days = min(days_since, 120)  # NVD limit
                logger.info(f"Incremental sync: fetching CVEs from last {days} days")
            else:
                logger.info("No previous sync found, doing initial sync")
        
        batch = []
        batch_size = 100
        
        try:
            for cve in self.fetch_recent_cves(days=days, max_results=max_results):
                stats["fetched"] += 1
                batch.append(cve)
                
                if len(batch) >= batch_size:
                    inserted = db.bulk_upsert_cves(batch)
                    stats["inserted"] += inserted
                    stats["errors"] += len(batch) - inserted
                    batch = []
                    
                    logger.info(f"Synced {stats['fetched']} CVEs...")
            
            # Insert remaining batch
            if batch:
                inserted = db.bulk_upsert_cves(batch)
                stats["inserted"] += inserted
                stats["errors"] += len(batch) - inserted
            
            # Update last sync time
            db.set_last_sync("nvd")
            
            logger.info(f"NVD sync complete: {stats}")
            
        except Exception as e:
            logger.error(f"Sync failed: {e}")
            stats["errors"] += 1
        
        return stats


# Convenience function
def get_nvd_client(api_key: str = None) -> NVDClient:
    """Get an NVD client instance."""
    return NVDClient(api_key)


if __name__ == "__main__":
    # Test the NVD client
    logging.basicConfig(level=logging.INFO)
    
    client = NVDClient()
    
    # Test fetching a single CVE
    print("Fetching CVE-2021-44228 (Log4Shell)...")
    cve = client.fetch_cve("CVE-2021-44228")
    if cve:
        print(f"  ID: {cve.id}")
        print(f"  Description: {cve.description[:100]}...")
        print(f"  CVSS v3: {cve.cvss_v3_score}")
        print(f"  CVSS v2: {cve.cvss_v2_score}")
        print(f"  Severity: {cve.severity.value}")
    else:
        print("  Failed to fetch CVE")
    
    # Show any errors
    errors = client.get_recent_errors()
    if errors:
        print(f"\nRecent errors: {len(errors)}")
        for err in errors[-3:]:
            print(f"  - {err['error_type']}: {err['message']}")
    
    print("\nNVD client test complete!")
