"""
Web Crawler for AI-Pentester
Performs depth-limited crawling with scope enforcement.

EXTENDED: Now includes JavaScript extraction and fingerprint deduplication
for enhanced attack surface discovery and infinite loop prevention.
"""

import re
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque
from typing import Set, Dict, List


class Crawler:
    """
    BFS web crawler with depth limiting and scope enforcement.
    
    Enhanced with:
    - JavaScript endpoint extraction (fetch, XHR, API patterns)
    - Fingerprint-based deduplication (method, url, params, content_type)
    - Infinite loop prevention via fingerprint tracking
    """
    
    # Patterns to extract endpoints from JavaScript (FIX C — expanded for SPAs)
    JS_PATTERNS = {
        'api_endpoints':     r'["\x60\']/(api|v\d+|rest|graphql|gql|rpc|service|services|endpoint)/[^"\x60\'\s]{2,}["\x60\']',
        'fetch_calls':       r'fetch\s*\(\s*["\x60\']([^"\x60\'\s]{3,})["\x60\']',
        'xhr_open':          r'\.open\s*\(\s*["\x60\'][A-Z]+["\x60\']\s*,\s*["\x60\']([^"\x60\'\s]{3,})["\x60\']',
        'ajax_url':          r'\$\.(?:ajax|get|post|put|delete|patch)\s*\(\s*["\x60\']([^"\x60\'\s]{3,})["\x60\']',
        'axios_url':         r'axios\s*(?:\.\s*(?:get|post|put|delete|patch|request))?\s*\(\s*["\x60\']([^"\x60\'\s]{3,})["\x60\']',
        'angular_http':      r'this\.http\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\x60\']([^"\x60\'\s]{3,})["\x60\']',
        'react_router_path': r'path\s*:\s*["\x60\'](/[^"\x60\'\s*?]{1,})["\x60\']',
        'vue_router':        r'(?:path|component)\s*:\s*["\x60\'](/[^"\x60\'\s]{2,})["\x60\']',
        'express_routes':    r'(?:router|app)\s*\.\s*(?:get|post|put|delete|patch|use|all)\s*\(\s*["\x60\']([^"\x60\'\s]{2,})["\x60\']',
        'template_literals': r'`(/(?:api|v\d+|rest|graphql|user|auth|admin)[^`\s]{0,})`',
        'api_constants':     r'(?:API|ENDPOINT|URL|PATH|ROUTE)_?\w*\s*[=:]\s*["\x60\'](/[^"\x60\'\s]{2,})["\x60\']',
        'hardcoded_paths':   r'["\x60\'](/[\w\-]+/[\w\-/.]{2,})["\x60\']',
        'websocket':         r'new\s+WebSocket\s*\(\s*["\x60\']([^"\x60\'\s]+)["\x60\']',
    }
    
    # Maximum queue size to prevent memory exhaustion
    MAX_QUEUE_SIZE = 10000
    
    def __init__(self, base_url, max_depth=3, max_pages=100):
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited = set()
        self.endpoints = []
        self.parameters = set()
        self.forms = []
        
        # NEW: Fingerprint tracking for deduplication
        self._fingerprints: Set[str] = set()
        
        # NEW: JavaScript-discovered endpoints
        self.js_endpoints: Set[str] = set()
        
        # NEW: HTTP method discovery per endpoint
        self.endpoint_methods: Dict[str, List[str]] = {}
        
        # NEW: Statistics
        self.stats = {
            'pages_crawled': 0,
            'js_endpoints_found': 0,
            'duplicates_skipped': 0,
            'methods_discovered': 0,
        }
    
    def _compute_fingerprint(self, method: str, url: str, content_type: str = "") -> str:
        """
        Compute a fingerprint for deduplication.
        
        Fingerprint formula: hash(method + normalized_url + sorted_param_names + content_type)
        """
        parsed = urlparse(url)
        # Normalize URL (scheme + netloc + path, no query)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Get sorted parameter names
        params = parse_qs(parsed.query)
        param_names = sorted(params.keys())
        
        # Build fingerprint string
        fp_string = f"{method.upper()}|{normalized}|{','.join(param_names)}|{content_type}"
        
        return hashlib.md5(fp_string.encode()).hexdigest()
    
    def _is_duplicate(self, method: str, url: str, content_type: str = "") -> bool:
        """Check if this request is a duplicate based on fingerprint."""
        fp = self._compute_fingerprint(method, url, content_type)
        
        if fp in self._fingerprints:
            self.stats['duplicates_skipped'] += 1
            return True
        
        self._fingerprints.add(fp)
        return False
    
    def _discover_allowed_methods(self, session, url: str, logger) -> List[str]:
        """
        Discover allowed HTTP methods for an endpoint.
        
        Uses OPTIONS request first, then falls back to probing common methods.
        Returns list of allowed methods.
        """
        allowed = []
        
        # Standard HTTP methods to probe
        METHODS_TO_PROBE = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        
        try:
            # Try OPTIONS request first (proper way)
            options_resp = session.options(url, timeout=5)
            
            # Check Allow header
            allow_header = options_resp.headers.get("Allow", "")
            if allow_header:
                allowed = [m.strip().upper() for m in allow_header.split(",")]
                logger.debug(f"[crawler] OPTIONS {url} -> Allow: {allowed}")
                return allowed
            
            # Check Access-Control-Allow-Methods for CORS
            cors_methods = options_resp.headers.get("Access-Control-Allow-Methods", "")
            if cors_methods:
                allowed = [m.strip().upper() for m in cors_methods.split(",")]
                logger.debug(f"[crawler] OPTIONS {url} -> CORS methods: {allowed}")
                return allowed
                
        except Exception as _e:
            pass  # OPTIONS not supported, fall through to probing
        
        # Fallback: Probe common methods (safe probing, not sending bodies)
        for method in METHODS_TO_PROBE:
            try:
                if method == "GET":
                    resp = session.get(url, timeout=3)
                elif method == "HEAD":
                    resp = session.head(url, timeout=3)
                elif method == "OPTIONS":
                    resp = session.options(url, timeout=3)
                elif method == "POST":
                    # Empty POST is generally safe
                    resp = session.post(url, data={}, timeout=3)
                elif method in ["PUT", "PATCH", "DELETE"]:
                    # For dangerous methods, only check if 405 is returned
                    # Use a request that should fail safely
                    resp = session.request(method, url, timeout=3)
                else:
                    continue
                
                # If not 405 Method Not Allowed, method is likely supported
                if resp.status_code != 405:
                    allowed.append(method)
                    
            except Exception as _e:
                pass  # Method failed, skip
        
        if allowed:
            logger.debug(f"[crawler] Probed {url} -> methods: {allowed}")
        
        return allowed

    
    def crawl(self, session, logger, scope_checker=None):
        """
        Perform BFS crawl starting from base_url.
        
        Args:
            session: requests.Session to use
            logger: Logger instance
            scope_checker: Optional function to check if URL is in scope
        
        Returns:
            dict with endpoints, parameters, forms, js_endpoints
        """
        queue = deque([(self.base_url, 0)])
        
        while queue and len(self.visited) < self.max_pages:
            # Guard against queue growing too large (infinite loop prevention)
            if len(queue) > self.MAX_QUEUE_SIZE:
                logger.warning(f"[crawler] Queue size exceeded {self.MAX_QUEUE_SIZE}, truncating")
                break
            
            url, depth = queue.popleft()
            
            # Skip if already visited or too deep
            if url in self.visited or depth > self.max_depth:
                continue
            
            # Scope check
            if scope_checker and not scope_checker(url, logger):
                logger.debug(f"[crawler] Skipping out-of-scope: {url}")
                continue
            
            # NEW: Fingerprint deduplication check
            if self._is_duplicate("GET", url):
                logger.debug(f"[crawler] Skipping duplicate fingerprint: {url}")
                continue
            
            self.visited.add(url)
            self.stats['pages_crawled'] += 1
            logger.info(f"[crawler] Crawling ({depth}/{self.max_depth}): {url}")
            
            try:
                response = session.get(url, timeout=10)

                if response.status_code != 200:
                    continue

                is_js_file = url.lower().split("?")[0].endswith(".js")

                if not is_js_file:
                    links = self._extract_links(response.text, url)
                    for link in links:
                        if link not in self.visited:
                            queue.append((link, depth + 1))

                # FIX CRW1: Parse JS bundle files directly for API routes
                js_links = self._extract_js_endpoints(response.text, url)
                for js_link in js_links:
                    if js_link not in self.visited:
                        self.js_endpoints.add(js_link)
                        if js_link.lower().split("?")[0].endswith(".js") or \
                           any(p in js_link for p in ["/api/", "/rest/", "/v1/", "/v2/"]):
                            queue.append((js_link, depth + 1))

                self._extract_params(url)

                if not is_js_file:
                    forms = self._extract_forms(response.text, url)
                    self.forms.extend(forms)

                self.endpoints.append({
                    "url": url,
                    "status": response.status_code,
                    "depth": depth,
                    "methods": ["GET"]
                })

                if any(pattern in url.lower() for pattern in ['/api/', '/v1/', '/v2/', '/rest/', '/graphql']):
                    allowed_methods = self._discover_allowed_methods(session, url, logger)
                    if allowed_methods:
                        self.endpoint_methods[url] = allowed_methods
                        self.endpoints[-1]["methods"] = allowed_methods
                        self.stats['methods_discovered'] += len(allowed_methods)
                
            except Exception as e:
                logger.debug(f"[crawler] Error crawling {url}: {e}")
        
        self.stats['js_endpoints_found'] = len(self.js_endpoints)
        logger.info(f"[crawler] Completed. Found {len(self.endpoints)} endpoints, "
                   f"{len(self.js_endpoints)} JS endpoints, "
                   f"{self.stats['methods_discovered']} methods discovered, "
                   f"skipped {self.stats['duplicates_skipped']} duplicates")
        
        return {
            "endpoints": [e["url"] for e in self.endpoints],
            "endpoint_details": self.endpoints,  # Include full details with methods
            "parameters": list(self.parameters),
            "forms": self.forms,
            "js_endpoints": list(self.js_endpoints),
            "endpoint_methods": self.endpoint_methods,  # URL -> allowed methods
            "stats": self.stats,
        }
    
    def _extract_js_endpoints(self, html: str, base_url: str) -> Set[str]:
        """
        Extract API endpoints and routes from JavaScript source.

        FIX C: Handles React/Vue/Angular SPAs properly:
        - Parses React Router path: definitions
        - Parses Vue Router routes array
        - Parses Angular loadChildren routes
        - Extracts API paths from fetch/axios/XHR calls
        - Handles webpack chunk manifests
        - Filters out non-URL strings (class names, colors, versions, etc.)
        """
        endpoints = set()

        # Get JS source — either the whole file or inline <script> blocks
        is_js_file = base_url.lower().split("?")[0].rstrip("/").endswith(
            (".js", ".mjs", ".jsx", ".ts", ".tsx", ".cjs", ".esm")
        )
        if is_js_file:
            all_js = html
        else:
            scripts = re.findall(r"<script[^>]*>(.*?)</script>", html, re.S | re.I)
            all_js = "\n".join(scripts) + html

        # Strings we know are not API endpoints
        _SKIP_EXTENSIONS = {
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
            ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
            ".map", ".min.js",
        }
        _SKIP_PREFIXES = (
            "//", "#", "data:", "javascript:", "blob:", "mailto:", "tel:",
        )
        _SKIP_PATTERNS = re.compile(
            r"^(?:"
            r"[0-9a-f]{6,}|"           # hex color or hash
            r"v\d+\.\d+|"             # version string
            r"[A-Z][a-z]+(?:[A-Z][a-z]+)+|"  # CamelCase class name
            r"\w+\.\w+\.\w+|"       # dotted namespaces
            r"[^/]+"                    # no slash at all = not a path
            r")$"
        )

        parsed_base = urlparse(base_url)

        def _is_valid_endpoint(url: str) -> bool:
            if not url or len(url) < 2:
                return False
            if url.startswith(_SKIP_PREFIXES):
                return False
            low = url.lower()
            if any(low.endswith(ext) for ext in _SKIP_EXTENSIONS):
                return False
            # Must look like a path or full URL
            if not (url.startswith("/") or url.startswith("http")):
                return False
            # Skip obvious non-paths
            if _SKIP_PATTERNS.match(url.lstrip("/")):
                return False
            return True

        for pattern_name, pattern in self.JS_PATTERNS.items():
            try:
                for match in re.finditer(pattern, all_js, re.I | re.M):
                    try:
                        # group(1) if capturing group exists, else group(0)
                        raw = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                        raw = raw.strip("\'\"` ")

                        if not _is_valid_endpoint(raw):
                            continue

                        # WebSocket protocol normalisation
                        if pattern_name == "websocket":
                            raw = raw.replace("wss://", "https://").replace("ws://", "http://")

                        # Resolve relative paths against base URL
                        if raw.startswith("http"):
                            full_url = raw
                        else:
                            full_url = urljoin(base_url, raw)

                        parsed = urlparse(full_url)

                        # Only keep same-domain endpoints
                        if parsed.netloc and parsed.netloc != self.base_domain:
                            continue

                        # Normalise — strip query/fragment for dedup
                        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        if clean and len(clean) > 10:
                            endpoints.add(clean)

                    except Exception as _e:
                        continue
            except Exception as _e:
                continue

        # ── Extra pass: extract string literals that look like API routes ──
        # Webpack bundles use patterns like: n.p+"chunk-name" or "/api/"+e
        # Grab any quoted string starting with /api, /v1, /v2, /rest, /graphql
        for m in re.finditer(r"""["'`](/(?:api|v\d+|rest|graphql|gql|auth|user|admin|account|data|service)[^"'`\s]{0,100})["'`]""", all_js):
            raw = m.group(1).rstrip("/")
            if raw and len(raw) >= 4:
                full = urljoin(base_url, raw)
                parsed = urlparse(full)
                if not parsed.netloc or parsed.netloc == self.base_domain:
                    endpoints.add(f"{parsed_base.scheme}://{self.base_domain}{parsed.path}")

        return endpoints
    def _extract_links(self, html, base_url):
        """Extract all links from HTML."""
        links = set()
        
        # Find href and src attributes
        patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, html, re.I):
                link = match.group(1)
                
                # Skip non-http links
                if link.startswith(('javascript:', 'mailto:', 'tel:', '#', 'data:')):
                    continue
                
                # Resolve relative URLs
                full_url = urljoin(base_url, link)
                
                # Only include same-domain links
                if urlparse(full_url).netloc == self.base_domain:
                    # Remove fragment
                    full_url = full_url.split('#')[0]
                    if full_url:
                        links.add(full_url)
        
        return links
    
    def _extract_params(self, url):
        """Extract query parameters from URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param_name in params.keys():
            self.parameters.add(param_name)
    
    def _extract_forms(self, html, base_url):
        """Extract form information from HTML."""
        forms = []
        
        form_pattern = r'<form[^>]*>(.*?)</form>'
        for form_match in re.finditer(form_pattern, html, re.I | re.S):
            form_html = form_match.group(0)
            
            # Get action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
            action = action_match.group(1) if action_match else ""
            action = urljoin(base_url, action)
            
            # Get method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)
            method = method_match.group(1).upper() if method_match else "GET"
            
            # Get inputs
            inputs = []
            input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
            for input_match in re.finditer(input_pattern, form_html, re.I):
                input_name = input_match.group(1)
                inputs.append(input_name)
                self.parameters.add(input_name)
            
            # Get textareas
            textarea_pattern = r'<textarea[^>]*name=["\']([^"\']+)["\']'
            for ta_match in re.finditer(textarea_pattern, form_html, re.I):
                ta_name = ta_match.group(1)
                inputs.append(ta_name)
                self.parameters.add(ta_name)
            
            # Get selects
            select_pattern = r'<select[^>]*name=["\']([^"\']+)["\']'
            for sel_match in re.finditer(select_pattern, form_html, re.I):
                sel_name = sel_match.group(1)
                inputs.append(sel_name)
                self.parameters.add(sel_name)
            
            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs
            })
        
        return forms
    
    def get_all_endpoints(self) -> List[str]:
        """Get all discovered endpoints including JS-discovered ones."""
        all_eps = set(e["url"] for e in self.endpoints)
        all_eps.update(self.js_endpoints)
        return list(all_eps)


def crawl_target(target, session, logger, scope_checker=None, max_depth=3, max_pages=100):
    """
    Convenience function to crawl a target.
    """
    crawler = Crawler(target, max_depth=max_depth, max_pages=max_pages)
    return crawler.crawl(session, logger, scope_checker)
