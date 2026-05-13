#!/usr/bin/env python3
"""
Payload DB Builder
==================
Reads cloned datasets (SecLists, Nuclei, PayloadsAllTheThings, HackerOne)
and extracts real-world payloads into data/payload_db/*.txt files.

Run after cloning datasets:
    python core/build_payload_db.py

Or run automatically via: python data/setup_datasets.py
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Set

DATASETS_DIR  = Path(__file__).parent.parent / "data" / "datasets"
PAYLOAD_DB_DIR = Path(__file__).parent.parent / "data" / "payload_db"

# ─────────────────────────────────────────────────────────────────────────────
# SecLists: maps payload_db key → list of SecLists relative paths to read
# ─────────────────────────────────────────────────────────────────────────────
SECLISTS_PAYLOAD_MAP: Dict[str, List[str]] = {
    "xss": [
        "Fuzzing/XSS/XSS-Jhaddix.txt",
        "Fuzzing/XSS/XSS-BruteLogic.txt",
        "Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt",
        "Fuzzing/XSS/XSS-RSNAKE.txt",
    ],
    "sqli": [
        "Fuzzing/SQLi/Generic-SQLi.txt",
        "Fuzzing/SQLi/quick-SQLi.txt",
        "Fuzzing/SQLi-Error-Messages.fuzz.txt",
    ],
    "lfi": [
        "Fuzzing/LFI/LFI-Jhaddix.txt",
        "Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt",
    ],
    "path_traversal": [
        "Fuzzing/LFI/LFI-Jhaddix.txt",
    ],
    "ssrf": [
        "Fuzzing/SSRF/SSRF-Bypass-Params.txt",
    ],
    "cmd_injection": [
        "Fuzzing/command-injection-commix.txt",
        "Fuzzing/Metacharacters.fuzz.txt",
    ],
    "ssti": [
        "Fuzzing/template-injection.txt",
    ],
    "open_redirect": [
        "Fuzzing/redirect-payloads.txt",
    ],
    "xxe": [
        "Fuzzing/XXE-Fuzzing.txt",
    ],
    "ldap_injection": [
        "Fuzzing/LDAP.fuzz.txt",
    ],
    # Brute force — top credentials for executor.py
    "_credentials_users": [
        "Usernames/top-usernames-shortlist.txt",
        "Usernames/Names/names.txt",
    ],
    "_credentials_passwords": [
        "Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
        "Passwords/Common-Credentials/best1050.txt",
    ],
    # Fuzzing polyglots — generic parameter fuzzing
    "_polyglot": [
        "Fuzzing/Polyglots/Polyglot-all-the-things.txt",
        "Fuzzing/special-chars.txt",
    ],
}

# SecLists: discovery wordlists written to dedicated files (not payload_db)
SECLISTS_DISCOVERY_MAP: Dict[str, List[str]] = {
    "web_paths": [
        "Discovery/Web-Content/raft-large-directories.txt",
        "Discovery/Web-Content/raft-medium-files.txt",
        "Discovery/Web-Content/common.txt",
        "Discovery/Web-Content/api-endpoints.txt",
    ],
    "subdomains": [
        "Discovery/DNS/subdomains-top1million-5000.txt",
        "Discovery/DNS/deepmagic.com-prefixes-top500.txt",
    ],
}

# PayloadsAllTheThings: dir-name → payload_db key
PAT_DIR_MAP: Dict[str, str] = {
    "XSS Injection":               "xss",
    "SQL Injection":               "sqli",
    "Command Injection":           "cmd_injection",
    "Server Side Template Injection": "ssti",
    "Server Side Request Forgery": "ssrf",
    "XXE Injection":               "xxe",
    "File Inclusion":              "lfi",
    "Directory Traversal":         "path_traversal",
    "Open Redirect":               "open_redirect",
    "LDAP Injection":              "ldap_injection",
    "Upload Insecure Files":       "file_upload",
    "CORS Misconfiguration":       "cors",
    "JSON Web Token":              "_jwt_payloads",
    "OAuth Misconfiguration":      "_oauth_payloads",
    "Race Condition":              "_race_payloads",
    "Request Smuggling":           "_smuggling_payloads",
}

# Nuclei: tag → payload_db key
NUCLEI_TAG_MAP: Dict[str, str] = {
    "xss": "xss", "sqli": "sqli", "lfi": "lfi", "ssrf": "ssrf",
    "xxe": "xxe", "ssti": "ssti", "rce": "cmd_injection",
    "idor": "idor", "cors": "cors", "redirect": "open_redirect",
    "traversal": "path_traversal", "ldap": "ldap_injection",
    "upload": "file_upload",
}

# Maximum payloads per file (keeps files manageable)
MAX_PAYLOADS_PER_FILE = 500
MAX_CREDS = 200  # credential list cap per type


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _read_lines(path: Path, max_lines: int = 5000) -> List[str]:
    """Read non-empty, non-comment lines from a text file."""
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return [l.strip() for l in lines
                if l.strip() and not l.strip().startswith("#")][:max_lines]
    except Exception as e:
        print(f"  [build] read error {path.name}: {e}")
        return []


def _extract_code_blocks(md_content: str) -> List[str]:
    """Pull payloads out of markdown code blocks."""
    blocks = re.findall(r"```[^\n]*\n(.*?)```", md_content, re.DOTALL)
    payloads: List[str] = []
    for block in blocks:
        for line in block.splitlines():
            line = line.strip()
            if line and len(line) < 300:
                payloads.append(line)
    return payloads


def _write_payload_file(key: str, payloads: Set[str], label: str = ""):
    """Write a deduplicated, sorted payload file to payload_db."""
    dest = PAYLOAD_DB_DIR / f"{key}.txt"
    # Merge with existing if present
    existing: Set[str] = set()
    if dest.exists():
        existing = set(_read_lines(dest, max_lines=10000))

    combined = existing | {p for p in payloads if p and len(p) < 300}
    # Trim to MAX
    ordered = sorted(combined)[:MAX_PAYLOADS_PER_FILE]

    dest.write_text("\n".join(ordered) + "\n", encoding="utf-8")
    added = len(ordered) - len(existing)
    print(f"  [build] {key}.txt  ->  {len(ordered)} payloads  (+{max(0, added)} new)  {label}")


def _write_discovery_file(key: str, entries: List[str]):
    """Write a discovery wordlist to data/wordlists/."""
    wl_dir = PAYLOAD_DB_DIR.parent / "wordlists"
    wl_dir.mkdir(parents=True, exist_ok=True)
    dest = wl_dir / f"{key}.txt"
    seen: Set[str] = set()
    if dest.exists():
        seen = set(_read_lines(dest, max_lines=200000))
    combined = seen | set(entries)
    ordered = sorted(combined)
    dest.write_text("\n".join(ordered) + "\n", encoding="utf-8")
    print(f"  [build] wordlists/{key}.txt  ->  {len(ordered)} entries  (+{len(combined)-len(seen)} new)")


# ─────────────────────────────────────────────────────────────────────────────
# Source 1: SecLists
# ─────────────────────────────────────────────────────────────────────────────

def build_from_seclists():
    seclists = DATASETS_DIR / "seclists"
    if not seclists.exists():
        print("[build] SecLists not cloned — skipping (run data/setup_datasets.py first)")
        return

    print("\n[build] === SecLists ===")

    # Payloads
    for key, paths in SECLISTS_PAYLOAD_MAP.items():
        payloads: Set[str] = set()
        for rel in paths:
            src = seclists / rel
            payloads |= set(_read_lines(src))
        if payloads:
            _write_payload_file(key, payloads, "(SecLists)")

    # Discovery wordlists
    for key, paths in SECLISTS_DISCOVERY_MAP.items():
        entries: List[str] = []
        for rel in paths:
            src = seclists / rel
            entries.extend(_read_lines(src, max_lines=100000))
        if entries:
            _write_discovery_file(key, entries)

    # Credentials → write combined credential file
    users_file = seclists / "Usernames/top-usernames-shortlist.txt"
    pass_file  = seclists / "Passwords/Common-Credentials/10-million-password-list-top-1000.txt"
    users = _read_lines(users_file, MAX_CREDS) or [
        "admin", "root", "user", "administrator", "test", "guest",
        "info", "webmaster", "operator", "support",
    ]
    passwords = _read_lines(pass_file, MAX_CREDS) or [
        "password", "123456", "admin", "12345678", "qwerty", "abc123",
        "password1", "letmein", "welcome", "monkey",
    ]
    # Write JSON credential pairs for the brute-force handler
    cred_file = PAYLOAD_DB_DIR.parent / "wordlists" / "credentials.json"
    cred_file.parent.mkdir(parents=True, exist_ok=True)
    pairs = []
    for u in users[:MAX_CREDS]:
        for p in passwords[:MAX_CREDS]:
            pairs.append({"username": u, "password": p, "email": f"{u}@example.com"})
    # Cap to 2000 pairs (enough for detection without spamming)
    import json as _json
    cred_file.write_text(_json.dumps(pairs[:2000], indent=2), encoding="utf-8")
    print(f"  [build] wordlists/credentials.json  ->  {min(len(pairs), 2000)} credential pairs")


# ─────────────────────────────────────────────────────────────────────────────
# Source 2: PayloadsAllTheThings
# ─────────────────────────────────────────────────────────────────────────────

def build_from_payloads_all_things():
    pat = DATASETS_DIR / "realworld_pocs"
    if not pat.exists():
        print("[build] PayloadsAllTheThings not cloned — skipping")
        return

    print("\n[build] === PayloadsAllTheThings ===")

    for dir_name, key in PAT_DIR_MAP.items():
        vuln_dir = pat / dir_name
        if not vuln_dir.exists():
            continue
        payloads: Set[str] = set()
        for md_file in vuln_dir.glob("**/*.md"):
            try:
                content = md_file.read_text(encoding="utf-8", errors="replace")
                payloads |= set(_extract_code_blocks(content))
            except Exception as e:
                print(f"  [build] parse error {md_file.name}: {e}")
        if payloads:
            _write_payload_file(key, payloads, "(PayloadsAllTheThings)")

    # Also write a "techniques" summary file for the attack planner
    techniques_dir = PAYLOAD_DB_DIR.parent / "techniques"
    techniques_dir.mkdir(parents=True, exist_ok=True)
    for dir_name, key in PAT_DIR_MAP.items():
        vuln_dir = pat / dir_name
        if not vuln_dir.exists():
            continue
        summaries = []
        for md_file in sorted(vuln_dir.glob("*.md"))[:5]:
            try:
                content = md_file.read_text(encoding="utf-8", errors="replace")
                # First 500 chars of each markdown file as technique description
                summaries.append(f"## {md_file.stem}\n{content[:500]}\n")
            except Exception as _e:
                import logging; logging.getLogger(__name__).debug(f'[build_payload_db] file read error: {_e}')
        if summaries:
            out = techniques_dir / f"{key}.md"
            out.write_text("\n".join(summaries), encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Source 3: Nuclei Templates
# ─────────────────────────────────────────────────────────────────────────────

def build_from_nuclei():
    nuclei = DATASETS_DIR / "nuclei"
    if not nuclei.exists():
        print("[build] Nuclei templates not cloned — skipping")
        return

    try:
        import yaml
    except ImportError:
        print("[build] PyYAML not installed — skipping Nuclei (pip install pyyaml)")
        return

    print("\n[build] === Nuclei Templates ===")

    collected: Dict[str, Set[str]] = {k: set() for k in NUCLEI_TAG_MAP.values()}

    for yaml_file in nuclei.glob("http/**/*.yaml"):
        try:
            with open(yaml_file, encoding="utf-8", errors="replace") as fh:
                tpl = yaml.safe_load(fh)
            if not tpl or not isinstance(tpl, dict):
                continue

            info = tpl.get("info", {})
            tags = " ".join(str(t) for t in (
                info.get("tags", []) if isinstance(info.get("tags"), list)
                else [info.get("tags", "")]
            )).lower()

            target_key = None
            for tag, key in NUCLEI_TAG_MAP.items():
                if tag in tags:
                    target_key = key
                    break
            if not target_key:
                continue

            # Extract matchers-based payloads
            for req in tpl.get("http", []):
                if not isinstance(req, dict):
                    continue
                # Path probes
                for p in req.get("path", []):
                    stripped = str(p).replace("{{BaseURL}}", "").strip("/ ")
                    if stripped and len(stripped) < 200:
                        collected[target_key].add(stripped)
                # Body payloads
                body = req.get("body", "")
                if body and len(body) < 300:
                    collected[target_key].add(body.strip())
                # Fuzzing payloads
                for section in req.get("payloads", {}).values():
                    if isinstance(section, list):
                        for item in section[:20]:
                            if item and len(str(item)) < 200:
                                collected[target_key].add(str(item))
        except Exception as _e:
            import logging; logging.getLogger(__name__).debug(f'[build_payload_db] YAML parse error: {_e}')
            continue

    for key, payloads in collected.items():
        if payloads:
            _write_payload_file(key, payloads, "(Nuclei)")


# ─────────────────────────────────────────────────────────────────────────────
# Source 4: HackerOne data.csv → extract unique payloads from titles/reports
# ─────────────────────────────────────────────────────────────────────────────

def build_from_hackerone():
    h1 = DATASETS_DIR / "hackerone"
    if not h1.exists():
        print("[build] HackerOne dataset not cloned — skipping")
        return

    csv_file = h1 / "data.csv"
    if not csv_file.exists():
        # Try common alternate paths
        for alt in h1.glob("**/*.csv"):
            csv_file = alt
            break

    if not csv_file.exists():
        print("[build] HackerOne data.csv not found — skipping")
        return

    print("\n[build] === HackerOne Reports ===")
    try:
        import csv
        type_counts: Dict[str, int] = {}
        with open(csv_file, encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                title = (row.get("title") or row.get("Title") or "").lower()
                for tag, key in NUCLEI_TAG_MAP.items():
                    if tag in title:
                        type_counts[key] = type_counts.get(key, 0) + 1
        print(f"  [build] HackerOne: {sum(type_counts.values())} reports mapped to vuln types:")
        for k, v in sorted(type_counts.items(), key=lambda x: -x[1]):
            print(f"    {k}: {v}")
    except Exception as e:
        print(f"  [build] HackerOne parse error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    PAYLOAD_DB_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[build] Payload DB: {PAYLOAD_DB_DIR.resolve()}")
    print(f"[build] Datasets  : {DATASETS_DIR.resolve()}\n")

    build_from_seclists()
    build_from_payloads_all_things()
    build_from_nuclei()
    build_from_hackerone()

    # Final summary
    print("\n[build] === Final payload_db summary ===")
    for f in sorted(PAYLOAD_DB_DIR.glob("*.txt")):
        count = len([l for l in f.read_text(encoding="utf-8").splitlines() if l.strip()])
        print(f"  {f.name:<35s}  {count:>5} payloads")

    wl_dir = PAYLOAD_DB_DIR.parent / "wordlists"
    if wl_dir.exists():
        print("\n[build] === Wordlists ===")
        for f in sorted(wl_dir.iterdir()):
            if f.is_file():
                try:
                    count = len([l for l in f.read_text(encoding="utf-8").splitlines() if l.strip()])
                    print(f"  {f.name:<35s}  {count:>6} entries")
                except Exception as _e:
                    import logging; logging.getLogger(__name__).debug(f"[build_payload_db] wordlist count error: {_e}")

    print("\n[build] Done.")


if __name__ == "__main__":
    main()
