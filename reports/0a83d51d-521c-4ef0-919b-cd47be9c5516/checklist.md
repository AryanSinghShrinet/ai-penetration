# Vulnerability Checklist


## CRITICAL Severity

- ☐ **SQL Injection** (`sqli`)
  - Reasons: Default check, Form: login, Form: search
- ☐ **Authentication Bypass** (`auth_bypass`)
  - Reasons: Default check, Form: login
- ☐ **Unrestricted File Upload** (`file_upload`)
  - Reasons: Default check
- ☐ **Command Injection** (`cmd_injection`)
  - Reasons: Default check

## HIGH Severity

- ☐ **Cross-Site Scripting** (`xss`)
  - Reasons: Default check, Parameter: q, Form: search
- ☐ **Insecure Direct Object Reference** (`idor`)
  - Reasons: Default check, Parameter: sid, Parameter: amp;lid
- ☐ **Local File Inclusion** (`lfi`)
  - Reasons: Default check, Parameter: amp;pageCriteria, Endpoint pattern
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
  - Reasons: Default check, Form: login
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
- ☐ **Credential_Stuffing** (`credential_stuffing`)
  - Reasons: Form: login

## LOW Severity

- ☐ **Missing Security Headers** (`security_headers`)
  - Reasons: Default check