import os
import yaml
from urllib.parse import urlparse
from pathlib import Path

SCOPE_PATH = Path("config/scope.yaml")

_scope_cache = None
_scope_mtime = 0

def load_scope():
    global _scope_cache, _scope_mtime
    try:
        current_mtime = os.path.getmtime(SCOPE_PATH)
    except OSError:
        current_mtime = 0

    if _scope_cache is None or current_mtime > _scope_mtime:
        with open(SCOPE_PATH, "r") as f:
            _scope_cache = yaml.safe_load(f)
        _scope_mtime = current_mtime
        
    return _scope_cache

def is_domain_allowed(hostname, scope):
    allowed_domains = scope["allowed"]["domains"]
    allow_sub = scope["allowed"].get("allow_subdomains", False)

    # Wildcard allows all domains
    if "*" in allowed_domains:
        return True

    for domain in allowed_domains:
        if hostname == domain:
            return True
        if allow_sub and hostname.endswith("." + domain):
            return True
    return False

def is_protocol_allowed(scheme, scope):
    return scheme in scope["allowed"].get("allowed_protocols", [])

def is_path_blocked(path, scope):
    for blocked_path in scope.get("blocked", {}).get("paths", []):
        if path.startswith(blocked_path):
            return True
    return False

def is_url_in_scope(url, logger=None):
    scope = load_scope()
    parsed = urlparse(url)

    if not is_protocol_allowed(parsed.scheme, scope):
        if logger:
            logger.warning(f"Out of scope protocol: {parsed.scheme}")
        return False

    if not is_domain_allowed(parsed.hostname, scope):
        if logger:
            logger.warning(f"Out of scope domain: {parsed.hostname}")
        return False

    if is_path_blocked(parsed.path, scope):
        if logger:
            logger.warning(f"Blocked path by scope: {parsed.path}")
        return False

    return True
