#!/usr/bin/env python3
"""
Dataset Setup Script
====================
Run this ONCE before your first scan to clone the four dataset repos:

    python data/setup_datasets.py

What it clones:
  1. HackerOne public disclosed reports  (~185k reports)
  2. Nuclei vulnerability templates      (~15k YAML signatures)
  3. PayloadsAllTheThings / realworld PoCs (~60 attack categories)
  4. SecLists                            (wordlists, credentials, fuzzing)

After cloning it runs build_payload_db.py to populate data/payload_db/
from the real data.
"""

import subprocess
import sys
from pathlib import Path

DATASETS_DIR = Path(__file__).parent / "datasets"

REPOS = {
    "hackerone": {
        "url": "https://github.com/reddelexc/hackerone-reports.git",
        "alt_url": "https://github.com/ArcSecurityDev/H1-Public-Disclosed-Reports.git",
        "depth": 1,
    },
    "nuclei": {
        "url": "https://github.com/projectdiscovery/nuclei-templates.git",
        "depth": 1,
    },
    "realworld_pocs": {
        "url": "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
        "depth": 1,
    },
    "seclists": {
        "url": "https://github.com/danielmiessler/SecLists.git",
        "depth": 1,
    },
}


def clone_or_update(name: str, config: dict) -> bool:
    dest = DATASETS_DIR / name
    if dest.exists():
        print(f"[setup] {name}: already present — pulling updates...")
        try:
            subprocess.run(["git", "pull", "--depth", "1"], cwd=dest,
                           capture_output=True, timeout=300)
            return True
        except Exception as e:
            print(f"[setup] {name}: pull failed ({e}), using existing copy")
            return True

    print(f"[setup] Cloning {name} from {config['url']} ...")
    for url_key in ["url", "alt_url"]:
        url = config.get(url_key)
        if not url:
            continue
        try:
            args = ["git", "clone", "--depth", str(config.get("depth", 1)),
                    url, str(dest)]
            result = subprocess.run(args, capture_output=True, timeout=600)
            if result.returncode == 0:
                print(f"[setup] {name}: cloned OK")
                return True
            else:
                print(f"[setup] {name}: clone failed — {result.stderr.decode()[:200]}")
        except subprocess.TimeoutExpired:
            print(f"[setup] {name}: clone timed out")
        except Exception as e:
            print(f"[setup] {name}: error — {e}")

    print(f"[setup] {name}: FAILED — could not clone from any source")
    return False


def main():
    DATASETS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[setup] Dataset directory: {DATASETS_DIR.resolve()}\n")

    results = {}
    for name, config in REPOS.items():
        results[name] = clone_or_update(name, config)

    print("\n[setup] Clone summary:")
    for name, ok in results.items():
        status = "OK" if ok else "FAILED"
        print(f"  {status:6s}  {name}")

    # Now populate payload_db from the cloned data
    build_script = Path(__file__).parent.parent / "core" / "build_payload_db.py"
    if build_script.exists():
        print("\n[setup] Running payload_db builder...")
        subprocess.run([sys.executable, str(build_script)], check=False)
    else:
        print("\n[setup] payload_db builder not found — skipping payload extraction")

    print("\n[setup] Done. You can now run: python main.py --target <URL> --phase all")


if __name__ == "__main__":
    main()
