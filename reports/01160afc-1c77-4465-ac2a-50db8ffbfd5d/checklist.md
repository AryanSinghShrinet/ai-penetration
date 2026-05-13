# Vulnerability Checklist


## CRITICAL Severity

- ☐ **SQL Injection** (`sqli`)
  - Reasons: Parameter: sid, Parameter: amp;pageCriteria, Default check
- ☐ **Authentication Bypass** (`auth_bypass`)
  - Reasons: Admin path detected, Default check
- ☐ **Unrestricted File Upload** (`file_upload`)
  - Reasons: Default check
- ☐ **Command Injection** (`cmd_injection`)
  - Reasons: Default check

## HIGH Severity

- ☐ **Cross-Site Scripting** (`xss`)
  - Reasons: Form: search, Default check, Parameter: q
- ☐ **Insecure Direct Object Reference** (`idor`)
  - Reasons: Parameter: sid, Default check, Parameter: amp;hpid
- ☐ **Local File Inclusion** (`lfi`)
  - Reasons: Parameter: amp;pageCriteria, Default check, Endpoint pattern
- ☐ **Server-Side Request Forgery** (`ssrf`)
  - Reasons: Default check, Technology: node.js
- ☐ **Path Traversal** (`path_traversal`)
  - Reasons: Default check
- ☐ **Business Logic Flaw** (`business_logic`)
  - Reasons: Default check
- ☐ **NoSQL Injection** (`nosql_injection`)
  - Reasons: Technology: node.js
- ☐ **LDAP Injection** (`ldap_injection`)
  - Reasons: Form: search

## MEDIUM Severity

- ☐ **Brute Force** (`brute_force`)
  - Reasons: Admin path detected, Default check
- ☐ **CORS Misconfiguration** (`cors`)
  - Reasons: Default check
- ☐ **Open Redirect** (`open_redirect`)
  - Reasons: Default check
- ☐ **Cross-Site Request Forgery** (`csrf`)
  - Reasons: Default check
- ☐ **Information Disclosure** (`information_disclosure`)
  - Reasons: Default check
- ☐ **Prototype_Pollution** (`prototype_pollution`)
  - Reasons: Technology: node.js

## LOW Severity

- ☐ **Missing Security Headers** (`security_headers`)
  - Reasons: Default check