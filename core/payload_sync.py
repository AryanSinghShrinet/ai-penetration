import requests
import hashlib
from pathlib import Path

PAYLOAD_DB = Path("data/payload_db")
PAYLOAD_DB.mkdir(parents=True, exist_ok=True)

def normalize(line):
    return line.strip()

def payload_hash(p):
    return hashlib.sha256(p.encode()).hexdigest()

def load_existing(vuln):
    f = PAYLOAD_DB / f"{vuln}.txt"
    if not f.exists():
        return set()
    return set(map(normalize, f.read_text(encoding="utf-8").splitlines()))

def save_payloads(vuln, payloads):
    f = PAYLOAD_DB / f"{vuln}.txt"
    existing = load_existing(vuln)
    merged = existing.union(payloads)
    f.write_text("\n".join(sorted(merged)), encoding="utf-8")

def fetch(url):
    try:
        r = requests.get(url, timeout=20)
        if r.status_code == 200:
            return r.text.splitlines()
    except Exception as _e:
        import logging; logging.getLogger(__name__).debug(f'[payload_sync] remote payload fetch failed: {_e}')
    return []

def sync_xss():
    url = (
        "https://raw.githubusercontent.com/"
        "swisskyrepo/PayloadsAllTheThings/master/XSS/README.md"
    )
    lines = fetch(url)
    payloads = set()

    for l in lines:
        if "<" in l and ">" in l:
            payloads.add(normalize(l))

    save_payloads("xss", payloads)

def sync_sqli():
    url = (
        "https://raw.githubusercontent.com/"
        "swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/README.md"
    )
    lines = fetch(url)
    payloads = set()

    for l in lines:
        if "'" in l or "--" in l:
            payloads.add(normalize(l))

    save_payloads("sqli", payloads)

def run_sync():
    sync_xss()
    sync_sqli()
