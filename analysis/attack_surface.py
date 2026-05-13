"""
Attack Surface Normalization - Structured injection point modeling

This module converts raw reconnaissance data into structured attack primitives,
identifying injection points with their context, encoding, and reflection behavior.
"""

import re
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Literal, Set
from urllib.parse import urlparse, parse_qs


@dataclass
class InjectionPoint:
    """
    Represents a potential injection point in the application.
    
    This is the core primitive for attack surface analysis.
    Each injection point has context about where and how it can be attacked.
    """
    name: str
    location: Literal["query", "body", "header", "cookie"]
    data_type_guess: str  # string, number, enum, object, file
    context: str  # html, js, sql, os, path, json, xml
    reflection_behavior: str  # reflected, not_reflected, unknown, encoded
    encoding: str  # none, url, unicode, double, html, base64
    
    # Additional metadata
    endpoint: str = ""
    method: str = "GET"
    original_value: str = ""
    is_hidden: bool = False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return asdict(self)
    
    @property
    def risk_score(self) -> int:
        """
        Calculate a risk score for this injection point.
        Higher = more likely to be vulnerable.
        """
        score = 0
        
        # Context-based scoring
        context_scores = {
            "sql": 10,
            "os": 10,
            "path": 8,
            "html": 7,
            "js": 7,
            "json": 5,
            "xml": 6,
        }
        score += context_scores.get(self.context, 3)
        
        # Reflection behavior scoring
        if self.reflection_behavior == "reflected":
            score += 5
        elif self.reflection_behavior == "unknown":
            score += 2
        
        # Data type scoring
        if self.data_type_guess in ["string", "number"]:
            score += 3
        
        # Location scoring
        location_scores = {
            "query": 4,
            "body": 5,
            "header": 3,
            "cookie": 3,
        }
        score += location_scores.get(self.location, 2)
        
        return score


class AttackSurfaceNormalizer:
    """
    Converts raw reconnaissance data into structured injection points.
    
    This normalizer analyzes:
    - URL query parameters
    - Form body parameters
    - Headers (select interesting ones)
    - Cookies
    - Hidden form fields
    
    And produces a list of InjectionPoint objects ready for scanning.
    """
    
    # Headers worth testing for injection
    INTERESTING_HEADERS = [
        "User-Agent",
        "Referer",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Original-URL",
        "X-Rewrite-URL",
        "Origin",
        "Accept-Language",
    ]
    
    # Patterns to detect data types
    DATA_TYPE_PATTERNS = {
        "number": r"^\d+$",
        "uuid": r"^[a-f0-9\-]{36}$",
        "email": r"^[\w\.\-]+@[\w\.\-]+$",
        "url": r"^https?://",
        "path": r"^[/\\]",
        "json": r"^\{.*\}$",
        "base64": r"^[A-Za-z0-9+/]+=*$",
    }
    
    # Context detection patterns
    CONTEXT_PATTERNS = {
        "sql": [r"id$", r"_id$", r"user", r"select", r"where", r"order", r"sort", r"filter"],
        "path": [r"file", r"path", r"dir", r"folder", r"document", r"template", r"include"],
        "os": [r"cmd", r"exec", r"run", r"command", r"shell", r"ping", r"host"],
        "url": [r"url", r"uri", r"link", r"redirect", r"next", r"return", r"goto", r"callback"],
    }
    
    def __init__(self):
        self._injection_points: List[InjectionPoint] = []
        self._seen_params: Set[str] = set()
    
    def normalize(self, endpoint: str, recon_data: Dict) -> List[InjectionPoint]:
        """
        Normalize reconnaissance data into injection points.
        
        Args:
            endpoint: Target URL
            recon_data: Reconnaissance data dict or ReconProfile object
        
        Returns:
            List of InjectionPoint objects
        """
        self._injection_points = []
        self._seen_params = set()
        
        # Handle ReconProfile object
        if hasattr(recon_data, 'to_dict'):
            recon_data = recon_data.to_dict()
        
        # NEW: Get endpoint_methods mapping for multi-method support
        endpoint_methods = recon_data.get("endpoint_methods", {})
        
        # Extract from URL query parameters
        self._extract_query_params(endpoint)
        
        # Extract from discovered parameters
        for param in recon_data.get("parameters", []):
            # If endpoint has multiple methods, create injection point for each
            methods = endpoint_methods.get(endpoint, ["GET"])
            for method in methods:
                self._add_param(
                    name=param,
                    location="query" if method == "GET" else "body",
                    endpoint=endpoint,
                    method=method,
                    context=self._infer_context(param)
                )
        
        # Extract from forms
        for form in recon_data.get("forms", []):
            form_endpoint = form.get("action", endpoint)
            method = form.get("method", "GET").upper()
            location = "body" if method == "POST" else "query"
            
            for input_name in form.get("inputs", []):
                self._add_param(
                    name=input_name,
                    location=location,
                    endpoint=form_endpoint,
                    method=method,
                    context=self._infer_context(input_name)
                )
        
        # NEW: Create injection points for API endpoints with discovered methods
        for ep_url, methods in endpoint_methods.items():
            for method in methods:
                if method in ["POST", "PUT", "PATCH", "DELETE"]:
                    # Create generic body injection point for modifying methods
                    self._add_param(
                        name="<body>",
                        location="body",
                        endpoint=ep_url,
                        method=method,
                        context="json"  # API endpoints typically use JSON
                    )
        
        # Extract from hidden elements
        for hidden in recon_data.get("hidden_elements", []):
            if hidden.get("type") == "hidden_input":
                self._add_param(
                    name=hidden.get("name", ""),
                    location="body",
                    endpoint=endpoint,
                    original_value=hidden.get("value", ""),
                    is_hidden=True,
                    context=self._infer_context(hidden.get("name", ""))
                )
        
        # Extract from cookies
        for cookie in recon_data.get("cookies", []):
            self._add_param(
                name=cookie,
                location="cookie",
                endpoint=endpoint,
                context="generic"
            )
        
        # Add interesting headers as potential injection points
        self._add_header_points(endpoint)
        
        # Sort by risk score (highest first)
        self._injection_points.sort(key=lambda x: x.risk_score, reverse=True)
        
        return self._injection_points
    
    def _extract_query_params(self, url: str) -> None:
        """Extract parameters from URL query string."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for name, values in params.items():
            original = values[0] if values else ""
            self._add_param(
                name=name,
                location="query",
                endpoint=url,
                original_value=original,
                context=self._infer_context(name)
            )
    
    def _add_param(
        self,
        name: str,
        location: str,
        endpoint: str,
        method: str = "GET",
        original_value: str = "",
        is_hidden: bool = False,
        context: str = "generic"
    ) -> None:
        """Add a parameter as an injection point if not seen."""
        if not name:
            return
        
        # Deduplicate
        key = f"{endpoint}|{name}|{location}"
        if key in self._seen_params:
            return
        self._seen_params.add(key)
        
        # Infer data type from name and value
        data_type = self._infer_data_type(name, original_value)
        
        # Create injection point
        point = InjectionPoint(
            name=name,
            location=location,
            data_type_guess=data_type,
            context=context,
            reflection_behavior="unknown",  # Will be determined later
            encoding="none",
            endpoint=endpoint,
            method=method,
            original_value=original_value,
            is_hidden=is_hidden
        )
        
        self._injection_points.append(point)
    
    def _add_header_points(self, endpoint: str) -> None:
        """Add interesting headers as injection points."""
        for header in self.INTERESTING_HEADERS:
            key = f"{endpoint}|{header}|header"
            if key not in self._seen_params:
                self._seen_params.add(key)
                self._injection_points.append(InjectionPoint(
                    name=header,
                    location="header",
                    data_type_guess="string",
                    context="generic",
                    reflection_behavior="unknown",
                    encoding="none",
                    endpoint=endpoint,
                    method="GET"
                ))
    
    def _infer_data_type(self, name: str, value: str) -> str:
        """Infer the data type of a parameter."""
        if not value:
            # Infer from name
            if any(x in name.lower() for x in ["id", "num", "count", "page", "limit"]):
                return "number"
            if "file" in name.lower() or "upload" in name.lower():
                return "file"
            return "string"
        
        # Infer from value
        for dtype, pattern in self.DATA_TYPE_PATTERNS.items():
            if re.match(pattern, value, re.I):
                return dtype
        
        return "string"
    
    def _infer_context(self, name: str) -> str:
        """Infer the context where this parameter is used."""
        name_lower = name.lower()
        
        for context, patterns in self.CONTEXT_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, name_lower):
                    return context
        
        return "generic"
    
    def get_injectable_params(
        self,
        location: Optional[str] = None,
        context: Optional[str] = None
    ) -> List[InjectionPoint]:
        """
        Get injection points filtered by criteria.
        
        Args:
            location: Filter by location (query, body, header, cookie)
            context: Filter by context (sql, html, js, etc.)
        
        Returns:
            Filtered list of injection points
        """
        result = self._injection_points
        
        if location:
            result = [p for p in result if p.location == location]
        
        if context:
            result = [p for p in result if p.context == context]
        
        return result
    
    def update_reflection_behavior(
        self,
        param_name: str,
        endpoint: str,
        behavior: str,
        encoding: str = "none"
    ) -> None:
        """
        Update reflection behavior after testing.
        
        Called by passive scanner to update injection point metadata.
        """
        for point in self._injection_points:
            if point.name == param_name and point.endpoint == endpoint:
                point.reflection_behavior = behavior
                point.encoding = encoding
                break
    
    def to_dict(self) -> Dict:
        """Export all injection points as a dictionary."""
        return {
            "count": len(self._injection_points),
            "by_location": {
                loc: len([p for p in self._injection_points if p.location == loc])
                for loc in ["query", "body", "header", "cookie"]
            },
            "by_context": {
                ctx: len([p for p in self._injection_points if p.context == ctx])
                for ctx in ["sql", "path", "os", "url", "html", "js", "generic"]
            },
            "points": [p.to_dict() for p in self._injection_points]
        }
