"""
Comprehensive Training Dataset for ML-Based Vulnerability Detection

This module provides:
1. Extended vulnerability patterns from multiple sources
2. HTTP response patterns for training
3. Payload-response mappings
4. Conversion of real scan results to training data
5. Data augmentation and balancing

Data Sources:
- CVE/NVD (via API)
- OWASP vulnerability patterns
- Real-world vulnerability signatures
- HTTP response patterns
"""

import json
import re
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from datetime import datetime
import random


@dataclass
class TrainingExample:
    """Single training example for the ML model."""
    id: str
    description: str
    response_body: str = ""
    response_status: int = 200
    response_headers: Dict[str, str] = field(default_factory=dict)
    vuln_type: str = ""
    payload_used: str = ""
    is_vulnerable: int = 0  # 0 = secure, 1 = vulnerable
    confidence: float = 1.0
    source: str = "synthetic"  # synthetic, nvd, scan_result, manual
    cvss_score: float = 0.0
    timestamp: str = ""


class TrainingDataset:
    """
    Comprehensive training dataset for vulnerability detection.
    
    Aggregates data from:
    - CVE/NVD database
    - OWASP patterns
    - Synthetic vulnerability responses
    - Real scan results
    """
    
    def __init__(self, data_dir: str = "data/ml_training"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.examples: List[TrainingExample] = []
        self._load_existing_data()
    
    def _load_existing_data(self):
        """Load existing training data from disk."""
        data_file = self.data_dir / "training_data.json"
        if data_file.exists():
            try:
                with open(data_file, "r") as f:
                    data = json.load(f)
                    for item in data:
                        self.examples.append(TrainingExample(**item))
                print(f"[ML] Loaded {len(self.examples)} existing training examples")
            except Exception as e:
                print(f"[ML] Error loading training data: {e}")
    
    def save(self):
        """Save training data to disk."""
        data_file = self.data_dir / "training_data.json"
        data = []
        for ex in self.examples:
            data.append({
                "id": ex.id,
                "description": ex.description,
                "response_body": ex.response_body[:1000],  # Truncate for storage
                "response_status": ex.response_status,
                "response_headers": ex.response_headers,
                "vuln_type": ex.vuln_type,
                "payload_used": ex.payload_used,
                "is_vulnerable": ex.is_vulnerable,
                "confidence": ex.confidence,
                "source": ex.source,
                "cvss_score": ex.cvss_score,
                "timestamp": ex.timestamp
            })
        
        with open(data_file, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[ML] Saved {len(data)} training examples")
    
    def add_example(self, example: TrainingExample):
        """Add a new training example."""
        example.id = hashlib.md5(f"{example.description}{example.response_body}".encode()).hexdigest()[:12]
        example.timestamp = datetime.now().isoformat()
        self.examples.append(example)
    
    def add_from_scan_result(self, 
                             vuln_type: str,
                             endpoint: str,
                             payload: str,
                             response_status: int,
                             response_body: str,
                             response_headers: Dict[str, str],
                             is_vulnerable: bool,
                             confidence: float = 0.8):
        """Add training data from a scan result."""
        example = TrainingExample(
            id="",
            description=f"{vuln_type} test on {endpoint} with payload: {payload[:50]}",
            response_body=response_body[:5000],
            response_status=response_status,
            response_headers=response_headers,
            vuln_type=vuln_type,
            payload_used=payload,
            is_vulnerable=1 if is_vulnerable else 0,
            confidence=confidence,
            source="scan_result",
            cvss_score=7.0 if is_vulnerable else 0.0
        )
        self.add_example(example)
    
    def get_all(self) -> List[TrainingExample]:
        """Get all training examples."""
        return self.examples
    
    def get_by_type(self, vuln_type: str) -> List[TrainingExample]:
        """Get examples for a specific vulnerability type."""
        return [ex for ex in self.examples if ex.vuln_type.lower() == vuln_type.lower()]
    
    def get_vulnerable_examples(self) -> List[TrainingExample]:
        """Get all vulnerable examples."""
        return [ex for ex in self.examples if ex.is_vulnerable == 1]
    
    def get_secure_examples(self) -> List[TrainingExample]:
        """Get all secure examples."""
        return [ex for ex in self.examples if ex.is_vulnerable == 0]
    
    def get_stats(self) -> Dict:
        """Get dataset statistics."""
        vulnerable = len(self.get_vulnerable_examples())
        secure = len(self.get_secure_examples())
        by_type = {}
        for ex in self.examples:
            if ex.vuln_type:
                by_type[ex.vuln_type] = by_type.get(ex.vuln_type, 0) + 1
        
        return {
            "total": len(self.examples),
            "vulnerable": vulnerable,
            "secure": secure,
            "balance_ratio": vulnerable / max(secure, 1),
            "by_type": by_type,
            "sources": list(set(ex.source for ex in self.examples))
        }
    
    def build_initial_dataset(self):
        """Build the initial training dataset with synthetic patterns."""
        print("[ML] Building initial training dataset...")
        
        # Add SQL injection patterns
        self._add_sqli_patterns()
        
        # Add XSS patterns
        self._add_xss_patterns()
        
        # Add SSRF patterns
        self._add_ssrf_patterns()
        
        # Add XXE patterns
        self._add_xxe_patterns()
        
        # Add LDAP patterns
        self._add_ldap_patterns()
        
        # Add command injection patterns
        self._add_cmd_patterns()
        
        # Add file upload patterns
        self._add_upload_patterns()
        
        # Add auth bypass patterns
        self._add_auth_patterns()
        
        # Add secure response patterns
        self._add_secure_patterns()
        
        self.save()
        print(f"[ML] Initial dataset built: {len(self.examples)} examples")
        return self.get_stats()
    
    def _add_sqli_patterns(self):
        """Add SQL injection training patterns."""
        # Vulnerable responses
        vulnerable_patterns = [
            ("You have an error in your SQL syntax", "SQLi error-based"),
            ("mysql_fetch_array", "SQLi PHP error"),
            ("ORA-01756", "SQLi Oracle error"),
            ("PostgreSQL query failed", "SQLi PostgreSQL error"),
            ("Warning: SQLite3", "SQLi SQLite error"),
            ("Microsoft SQL Native Client", "SQLi MSSQL error"),
            ("ODBC Microsoft Access Driver", "SQLi Access error"),
            ("unclosed quotation mark after the character string", "SQLi syntax error"),
            ("quoted string not properly terminated", "SQLi quote error"),
            ("supplied argument is not a valid MySQL", "SQLi MySQL error"),
        ]
        
        for body, desc in vulnerable_patterns:
            self.add_example(TrainingExample(
                id="",
                description=f"SQL Injection: {desc}",
                response_body=f"<html>Error: {body}</html>",
                vuln_type="sqli",
                is_vulnerable=1,
                cvss_score=9.0,
                source="synthetic"
            ))
        
        # Time-based blind SQLi (detected by delay)
        self.add_example(TrainingExample(
            id="",
            description="SQL Injection: Time-based blind (5 second delay)",
            response_body="<html>Normal response</html>",
            vuln_type="sqli",
            is_vulnerable=1,
            cvss_score=8.5,
            source="synthetic",
            payload_used="'; WAITFOR DELAY '0:0:5'--"
        ))
    
    def _add_xss_patterns(self):
        """Add XSS training patterns."""
        # Reflected XSS
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
            "'-alert(1)-'",
        ]
        
        for payload in xss_payloads:
            # Vulnerable - payload reflected
            self.add_example(TrainingExample(
                id="",
                description=f"XSS: Reflected payload in response",
                response_body=f"<html>Search results for: {payload}</html>",
                vuln_type="xss",
                payload_used=payload,
                is_vulnerable=1,
                cvss_score=6.5,
                source="synthetic"
            ))
            
            # Secure - payload encoded
            encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
            self.add_example(TrainingExample(
                id="",
                description=f"XSS: Payload properly encoded",
                response_body=f"<html>Search results for: {encoded}</html>",
                vuln_type="xss",
                payload_used=payload,
                is_vulnerable=0,
                cvss_score=0.0,
                source="synthetic"
            ))
    
    def _add_ssrf_patterns(self):
        """Add SSRF training patterns."""
        # Vulnerable responses
        ssrf_indicators = [
            ("ami-id", "AWS metadata exposed"),
            ("instance-id", "Cloud metadata leaked"),
            ("root:x:0:0", "/etc/passwd accessed via SSRF"),
            ("localhost:8080", "Internal service accessed"),
            ("127.0.0.1", "Loopback accessed"),
            ("169.254.169.254", "Metadata endpoint accessed"),
        ]
        
        for indicator, desc in ssrf_indicators:
            self.add_example(TrainingExample(
                id="",
                description=f"SSRF: {desc}",
                response_body=f"Response: {indicator}",
                vuln_type="ssrf",
                is_vulnerable=1,
                cvss_score=9.0,
                source="synthetic"
            ))
    
    def _add_xxe_patterns(self):
        """Add XXE training patterns."""
        # Vulnerable responses
        xxe_patterns = [
            ("root:x:0:0:root", "File disclosure via XXE"),
            ("[extensions]", "win.ini disclosed"),
            ("<!DOCTYPE", "XXE in response"),
            ("ENTITY", "DTD entity in response"),
        ]
        
        for pattern, desc in xxe_patterns:
            self.add_example(TrainingExample(
                id="",
                description=f"XXE: {desc}",
                response_body=f"<?xml version='1.0'?>{pattern}",
                vuln_type="xxe",
                is_vulnerable=1,
                cvss_score=8.5,
                source="synthetic"
            ))
    
    def _add_ldap_patterns(self):
        """Add LDAP injection patterns."""
        ldap_errors = [
            "Invalid DN syntax",
            "LDAP error",
            "ldap_search",
            "ldap_bind",
            "No such object",
        ]
        
        for error in ldap_errors:
            self.add_example(TrainingExample(
                id="",
                description=f"LDAP Injection: Error disclosure",
                response_body=f"Error: {error}",
                vuln_type="ldap_injection",
                is_vulnerable=1,
                cvss_score=7.5,
                source="synthetic"
            ))
    
    def _add_cmd_patterns(self):
        """Add command injection patterns."""
        cmd_indicators = [
            ("uid=0(root)", "Command execution - id output"),
            ("root:x:0:0", "Command execution - /etc/passwd"),
            ("Windows IP Configuration", "Command execution - ipconfig"),
            ("Directory of C:", "Command execution - dir"),
            ("total 0\ndrwx", "Command execution - ls -la"),
        ]
        
        for indicator, desc in cmd_indicators:
            self.add_example(TrainingExample(
                id="",
                description=f"Command Injection: {desc}",
                response_body=indicator,
                vuln_type="cmd_injection",
                is_vulnerable=1,
                cvss_score=9.5,
                source="synthetic"
            ))
    
    def _add_upload_patterns(self):
        """Add file upload vulnerability patterns."""
        # Vulnerable uploads
        upload_vulns = [
            ("File uploaded successfully: shell.php", "PHP shell uploaded"),
            ("Stored at: /uploads/webshell.jsp", "JSP shell uploaded"),
            ("File saved to: /var/www/html/cmd.aspx", "ASPX shell uploaded"),
        ]
        
        for response, desc in upload_vulns:
            self.add_example(TrainingExample(
                id="",
                description=f"File Upload: {desc}",
                response_body=response,
                vuln_type="file_upload",
                is_vulnerable=1,
                cvss_score=9.0,
                source="synthetic"
            ))
    
    def _add_auth_patterns(self):
        """Add authentication bypass patterns."""
        auth_bypasses = [
            ("Welcome, admin", "Admin access without auth"),
            ("isAdmin: true", "Admin flag exposed"),
            ("role: administrator", "Privilege escalation"),
            ("session created", "Auth bypass session"),
        ]
        
        for indicator, desc in auth_bypasses:
            self.add_example(TrainingExample(
                id="",
                description=f"Auth Bypass: {desc}",
                response_body=f'{{"status": "success", "{indicator}"}}',
                vuln_type="auth_bypass",
                is_vulnerable=1,
                cvss_score=9.0,
                source="synthetic"
            ))
    
    def _add_secure_patterns(self):
        """Add secure/normal response patterns."""
        secure_patterns = [
            ("200", {}, "Welcome to our website", "Normal homepage"),
            ("200", {}, '{"error": "Invalid input"}', "Input validation working"),
            ("403", {}, "Access denied", "Authorization working"),
            ("401", {"WWW-Authenticate": "Bearer"}, "Unauthorized", "Auth required"),
            ("400", {}, "Bad request", "Request validation"),
            ("404", {}, "Page not found", "Normal 404"),
            ("302", {"Location": "/login"}, "", "Redirect to login"),
            ("200", {"Content-Type": "application/json"}, '{"status": "ok"}', "API success"),
            ("200", {}, "<html><body>Search results: 0 items</body></html>", "Empty search"),
            ("200", {"X-Content-Type-Options": "nosniff"}, "Protected", "Security headers"),
        ]
        
        for status, headers, body, desc in secure_patterns:
            self.add_example(TrainingExample(
                id="",
                description=f"Secure: {desc}",
                response_body=body,
                response_status=int(status),
                response_headers=headers,
                vuln_type="",
                is_vulnerable=0,
                cvss_score=0.0,
                source="synthetic"
            ))
        
        # Add more secure patterns with various status codes
        for _ in range(50):
            self.add_example(TrainingExample(
                id="",
                description=f"Secure: Normal operation #{random.randint(1, 1000)}",
                response_body=f"<html><body>Page content {random.randint(1, 100)}</body></html>",
                response_status=200,
                vuln_type="",
                is_vulnerable=0,
                cvss_score=0.0,
                source="synthetic"
            ))


# =============================================================================
# HTTP RESPONSE FEATURE EXTRACTOR
# =============================================================================

class ResponseFeatureExtractor:
    """
    Extract features from HTTP responses for ML training.
    """
    
    # Security-related keywords
    VULN_KEYWORDS = [
        # SQLi
        "sql", "syntax", "query", "mysql", "postgresql", "oracle", "sqlite", "mssql",
        "odbc", "jdbc", "database", "select", "from", "where", "union",
        # XSS
        "script", "alert", "onerror", "onload", "javascript", "onclick",
        # Command injection
        "uid=", "root:", "bin/bash", "command", "exec", "system", "shell",
        # Path traversal
        "../", "..\\", "/etc/", "passwd", "shadow", "win.ini",
        # XXE
        "<!entity", "<!doctype", "xmlns", "xml",
        # Errors
        "error", "exception", "warning", "fatal", "failed", "invalid",
        "undefined", "null", "stack trace", "traceback",
    ]
    
    SECURE_KEYWORDS = [
        "success", "ok", "valid", "authorized", "welcome",
        "logout", "session", "secure", "encrypted", "protected"
    ]
    
    def extract_features(self, 
                         status_code: int,
                         headers: Dict[str, str],
                         body: str,
                         payload: str = "") -> Dict:
        """
        Extract features from an HTTP response.
        
        Returns:
            Dict of features for ML model
        """
        body_lower = body.lower()
        
        features = {
            # Status code features
            "status_code": status_code,
            "is_error_status": 1 if status_code >= 400 else 0,
            "is_redirect": 1 if 300 <= status_code < 400 else 0,
            "is_success": 1 if 200 <= status_code < 300 else 0,
            
            # Body features
            "body_length": len(body),
            "body_has_html": 1 if "<html" in body_lower else 0,
            "body_has_json": 1 if body.strip().startswith("{") else 0,
            "body_has_xml": 1 if body.strip().startswith("<?xml") else 0,
            
            # Vulnerability keyword counts
            "vuln_keyword_count": sum(1 for kw in self.VULN_KEYWORDS if kw in body_lower),
            "secure_keyword_count": sum(1 for kw in self.SECURE_KEYWORDS if kw in body_lower),
            
            # Specific vulnerability indicators
            "has_sql_error": 1 if any(kw in body_lower for kw in ["sql", "syntax", "query", "mysql"]) else 0,
            "has_script_tag": 1 if "<script" in body_lower else 0,
            "has_path_traversal": 1 if "../" in body or "..\\" in body else 0,
            "has_cmd_output": 1 if "uid=" in body_lower or "root:" in body_lower else 0,
            "has_xml_entity": 1 if "<!entity" in body_lower or "<!doctype" in body_lower else 0,
            
            # Payload reflection
            "payload_reflected": 1 if payload and payload.lower() in body_lower else 0,
            "payload_length": len(payload) if payload else 0,
            
            # Header features
            "has_security_headers": 1 if any(h.lower().startswith("x-") for h in headers.keys()) else 0,
            "has_csp": 1 if "content-security-policy" in [h.lower() for h in headers.keys()] else 0,
            
            # Error indicators
            "has_error_message": 1 if any(kw in body_lower for kw in ["error", "exception", "warning", "failed"]) else 0,
            "has_stack_trace": 1 if "traceback" in body_lower or "stack trace" in body_lower else 0,
        }
        
        return features
    
    def features_to_vector(self, features: Dict) -> List[float]:
        """Convert features dict to a numeric vector."""
        # Define consistent ordering for feature vector
        feature_order = [
            "status_code", "is_error_status", "is_redirect", "is_success",
            "body_length", "body_has_html", "body_has_json", "body_has_xml",
            "vuln_keyword_count", "secure_keyword_count",
            "has_sql_error", "has_script_tag", "has_path_traversal",
            "has_cmd_output", "has_xml_entity", "payload_reflected",
            "payload_length", "has_security_headers", "has_csp",
            "has_error_message", "has_stack_trace"
        ]
        
        vector = []
        for key in feature_order:
            value = features.get(key, 0)
            # Normalize some values
            if key == "status_code":
                value = value / 600.0  # Normalize status code
            elif key == "body_length":
                value = min(value / 10000.0, 1.0)  # Normalize body length
            elif key == "payload_length":
                value = min(value / 200.0, 1.0)
            elif key == "vuln_keyword_count":
                value = min(value / 10.0, 1.0)
            elif key == "secure_keyword_count":
                value = min(value / 5.0, 1.0)
            vector.append(float(value))
        
        return vector


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def get_training_dataset(data_dir: str = "data/ml_training") -> TrainingDataset:
    """Get the training dataset instance."""
    return TrainingDataset(data_dir)


def build_initial_dataset(data_dir: str = "data/ml_training") -> Dict:
    """Build the initial training dataset."""
    dataset = TrainingDataset(data_dir)
    return dataset.build_initial_dataset()


def add_scan_result_to_training(
    vuln_type: str,
    endpoint: str,
    payload: str,
    status: int,
    body: str,
    headers: Dict,
    is_vulnerable: bool,
    data_dir: str = "data/ml_training"
):
    """Add a scan result to the training dataset."""
    dataset = TrainingDataset(data_dir)
    dataset.add_from_scan_result(
        vuln_type=vuln_type,
        endpoint=endpoint,
        payload=payload,
        response_status=status,
        response_body=body,
        response_headers=headers,
        is_vulnerable=is_vulnerable
    )
    dataset.save()


if __name__ == "__main__":
    # Build initial dataset
    dataset = TrainingDataset()
    stats = dataset.build_initial_dataset()
    print("\nDataset Statistics:")
    print(f"  Total: {stats['total']}")
    print(f"  Vulnerable: {stats['vulnerable']}")
    print(f"  Secure: {stats['secure']}")
    print(f"  By Type: {stats['by_type']}")
