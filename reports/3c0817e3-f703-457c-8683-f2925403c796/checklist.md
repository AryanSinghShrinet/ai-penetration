# Vulnerability Checklist


## CRITICAL Severity

- ☐ **SQL Injection** (`sqli`)
  - Reasons: Parameter: pid, Parameter: q, Parameter: amp;pageCriteria
- ☐ **Unrestricted File Upload** (`file_upload`)
  - Reasons: Default check
- ☐ **Command Injection** (`cmd_injection`)
  - Reasons: Default check
- ☐ **Authentication Bypass** (`auth_bypass`)
  - Reasons: Default check

## HIGH Severity

- ☐ **Cross-Site Scripting** (`xss`)
  - Reasons: Parameter: q, Form: search, Default check
- ☐ **Insecure Direct Object Reference** (`idor`)
  - Reasons: Parameter: sid, Parameter: pid, Default check
- ☐ **Local File Inclusion** (`lfi`)
  - Reasons: Endpoint pattern, Parameter: amp;pageCriteria, Default check
- ☐ **Server-Side Request Forgery** (`ssrf`)
  - Reasons: Technology: node.js, Default check
- ☐ **Path Traversal** (`path_traversal`)
  - Reasons: Default check
- ☐ **Business Logic Flaw** (`business_logic`)
  - Reasons: Default check
- ☐ **NoSQL Injection** (`nosql_injection`)
  - Reasons: Technology: node.js
- ☐ **LDAP Injection** (`ldap_injection`)
  - Reasons: Form: search

## MEDIUM Severity

- ☐ **CORS Misconfiguration** (`cors`)
  - Reasons: Default check
- ☐ **Open Redirect** (`open_redirect`)
  - Reasons: Default check
- ☐ **Cross-Site Request Forgery** (`csrf`)
  - Reasons: Default check
- ☐ **Brute Force** (`brute_force`)
  - Reasons: Default check
- ☐ **Information Disclosure** (`information_disclosure`)
  - Reasons: Default check
- ☐ **Prototype_Pollution** (`prototype_pollution`)
  - Reasons: Technology: node.js

## LOW Severity

- ☐ **Missing Security Headers** (`security_headers`)
  - Reasons: Default check