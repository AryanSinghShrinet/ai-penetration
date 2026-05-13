import json
import time
from pathlib import Path

MEMORY_PATH = Path("data/learning/memory.json")

def load_memory():
    if not MEMORY_PATH.exists():
        return {}
    try:
        return json.loads(MEMORY_PATH.read_text())
    except json.JSONDecodeError:
        return {}

def save_memory(memory):
    # Ensure directory exists
    MEMORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    MEMORY_PATH.write_text(json.dumps(memory, indent=2))

def target_key(target):
    if not target:
        return "unknown"
    return target.replace("https://", "").replace("http://", "")

def record_result(target, vuln, payload, status):
    memory = load_memory()
    tkey = target_key(target)

    memory.setdefault(tkey, {})
    memory[tkey].setdefault(vuln, {})
    
    # Payload can be a dict in some cases (e.g. file upload or logic plan)
    # We need a string key.
    # If payload is dict, use a representative string or hash.
    payload_key = str(payload)
    if isinstance(payload, dict):
        # Try to find a meaningful key
        if "payload" in payload:
             payload_key = str(payload["payload"])
        elif "original" in payload:
             payload_key = str(payload["original"])
        else:
             # Fallback to stringified dict
             payload_key = str(payload)

    memory[tkey][vuln].setdefault(payload_key, {
        "success": 0,
        "failure": 0,
        "blocked": 0,
        "last_seen": None
    })

    entry = memory[tkey][vuln][payload_key]

    if status == "SUCCESS":
        entry["success"] += 1
    elif status == "FAILED":
        entry["failure"] += 1
    elif status == "BLOCKED":
        entry["blocked"] += 1

    entry["last_seen"] = int(time.time())
    save_memory(memory)

def score_payload(entry):
    # Simple confidence scoring
    return (entry["success"] * 3) - (entry["failure"] + entry["blocked"] * 2)

def get_ranked_payloads(target, vuln):
    memory = load_memory()
    tkey = target_key(target)

    if tkey not in memory or vuln not in memory[tkey]:
        return []

    scored = []
    for payload, data in memory[tkey][vuln].items():
        scored.append((payload, score_payload(data)))

    # Highest score first
    scored.sort(key=lambda x: x[1], reverse=True)
    return [p for p, _ in scored]
