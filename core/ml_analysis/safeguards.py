import os
import time
import yaml
from pathlib import Path
from urllib.parse import urlparse

# B-05 FIX: Load authorized domains from scope.yaml at runtime
_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "scope.yaml"

def _load_scope_domains():
    """Load allowed domains from config/scope.yaml."""
    try:
        with open(_CONFIG_PATH, "r") as f:
            scope = yaml.safe_load(f)
        domains = scope.get("allowed", {}).get("domains", [])
        return domains
    except Exception as _e:
        # Fallback to safe defaults if config is unavailable
        return ["127.0.0.1", "localhost"]


class EthicalSafeguards:
    def __init__(self):
        # B-05 FIX: Load domains from scope.yaml instead of hardcoding
        self.scope_domains = _load_scope_domains()
        self.rate_limits = {}
    
    def check_authorization(self, target):
        """Ensure you have authorization before scanning a target.
        
        Logic:
        - If scope.yaml contains '*' as a domain → allow everything (wildcard).
        - Otherwise check if the target domain is in the authorized list.
        """
        domain = urlparse(target).netloc.split(':')[0]

        # B-05 FIX: If scope uses wildcard, honour it (consistent with scope.yaml intent)
        if "*" in self.scope_domains:
            return True

        # Check against scope domains list
        for auth_domain in self.scope_domains:
            if domain == auth_domain or domain.endswith("." + auth_domain):
                return True

        return False
    
    def enforce_rate_limits(self, target):
        """Prevent DoS/DDoS"""
        if target in self.rate_limits:
            last_request = self.rate_limits[target]
            if time.time() - last_request < 1:  # 1 second between requests
                time.sleep(1)
        
        self.rate_limits[target] = time.time()
