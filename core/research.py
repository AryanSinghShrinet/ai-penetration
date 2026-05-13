import requests
import re
from pathlib import Path

RESEARCH_DB = Path("data/research")
RESEARCH_DB.mkdir(parents=True, exist_ok=True)

BLOG_SOURCES = [
    "https://raw.githubusercontent.com/EdOverflow/bugcrowd_university/master/lessons.md"
]

def extract_patterns(text):
    patterns = set()
    for line in text.splitlines():
        if any(k in line.lower() for k in ["bypass", "filter", "encoding"]):
            patterns.add(line.strip())
    return patterns

def research_blogs():
    results = set()
    for url in BLOG_SOURCES:
        try:
            r = requests.get(url, timeout=20)
            if r.status_code == 200:
                results |= extract_patterns(r.text)
        except Exception as _e:
            import logging; logging.getLogger(__name__).debug(f'[research] research fetch failed: {_e}')
    return results

def save_patterns(patterns):
    f = RESEARCH_DB / "patterns.txt"
    existing = set()
    if f.exists():
        existing = set(f.read_text().splitlines())
    merged = existing.union(patterns)
    f.write_text("\n".join(sorted(merged)))

def run_research():
    patterns = research_blogs()
    save_patterns(patterns)
