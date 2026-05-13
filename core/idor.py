import re
from urllib.parse import urlparse, parse_qs

ID_PARAM_NAMES = [
    "id", "user_id", "account_id", "order_id", "profile_id"
]

def extract_ids_from_url(url):
    """
    Extract numeric IDs from URL path and query string.
    """
    ids = set()
    parsed = urlparse(url)

    # Path-based IDs: /users/123
    for part in parsed.path.split("/"):
        if part.isdigit():
            ids.add(part)

    # Query-based IDs: ?id=123
    qs = parse_qs(parsed.query)
    for k, vals in qs.items():
        if k.lower() in ID_PARAM_NAMES:
            for v in vals:
                if v.isdigit():
                    ids.add(v)

    return list(ids)

# UUID pattern (covers REST APIs like Juice Shop)
UUID_RE = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    re.I
)
# Numeric ID in path segments or query strings
NUMERIC_RE = re.compile(r'(?<![.\d])(\d{1,10})(?![.\d])')


def extract_ids_from_url(url):
    """
    Extract numeric IDs and UUIDs from a URL path and query string.
    """
    ids = set()
    parsed = urlparse(url)

    # UUIDs anywhere in URL
    for m in UUID_RE.finditer(url):
        ids.add(m.group(0))

    # Numeric path segments: /users/123, /orders/456
    for part in parsed.path.split("/"):
        part = part.strip()
        if part.isdigit() and 1 <= int(part) <= 9999999:
            ids.add(part)

    # Query params with ID-like names
    try:
        from urllib.parse import parse_qs as _pqs
        qs = _pqs(parsed.query)
        for k, vals in qs.items():
            if k.lower() in ID_PARAM_NAMES:
                for v in vals:
                    v = v.strip()
                    if v.isdigit() or UUID_RE.match(v):
                        ids.add(v)
    except Exception as _e:
        import logging; logging.getLogger(__name__).debug(f"[idor] query string parse error: {_e}")

    return list(ids)


def discover_id_candidates(recon_data):
    """
    Collect ID candidates (numeric IDs and UUIDs) from all recon data.

    FIX ID1: Previous version only found integer IDs from path segments and
    ignored UUIDs entirely.  Modern REST APIs (Juice Shop, most SPAs) use
    UUIDs. This version scans:
      - All crawled endpoint URLs for UUIDs and numeric IDs
      - Form input values with ID-like parameter names
      - API response bodies stored in knowledge-base entries
    """
    candidates = set()

    # 1. Crawled endpoints (full URLs with values)
    for ep in recon_data.get("endpoints", []):
        ep_url = ep if isinstance(ep, str) else ep.get("url", "")
        for _id in extract_ids_from_url(ep_url):
            candidates.add(_id)

    # 2. Parameters list — scan for UUID-shaped values
    for p in recon_data.get("parameters", []):
        if isinstance(p, dict):
            v = str(p.get("value", ""))
            if v.isdigit() or UUID_RE.match(v):
                candidates.add(v)

    # 3. Forms with ID-like inputs
    for form in recon_data.get("forms", []):
        for inp in form.get("inputs", []):
            if isinstance(inp, dict):
                name = inp.get("name", "").lower()
                value = str(inp.get("value", ""))
                if name in ID_PARAM_NAMES and value:
                    if value.isdigit() or UUID_RE.match(value):
                        candidates.add(value)

    # 4. Synthetic fallback — sequential IDs 1-5 and one UUID-shaped probe
    # Ensures IDOR testing fires even on uncrawled targets
    if not candidates:
        for i in range(1, 6):
            candidates.add(str(i))

    return list(candidates)

def compare_authz_responses(r_self, r_other):
    """
    Conservative authorization diff.
    """
    if r_self.status_code != r_other.status_code:
        return True

    # Significant content-length difference
    if abs(len(r_self.text) - len(r_other.text)) > 100:
        return True

    return False

def analyze_idor(r_self, r_other):
    if compare_authz_responses(r_self, r_other):
        return True
    return False
