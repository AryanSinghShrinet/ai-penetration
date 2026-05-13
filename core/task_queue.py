import json
import threading
from pathlib import Path

QUEUE_PATH = Path("data/tasks/queue.json")
QUEUE_PATH.parent.mkdir(parents=True, exist_ok=True)

_LOCK = threading.Lock()

# Track (endpoint, vuln_type) pairs that have been confirmed - skip remaining payloads for that combo only
_found_endpoint_vulns = set()

def load_queue():
    if not QUEUE_PATH.exists():
        return []
    try:
        content = QUEUE_PATH.read_text()
        if not content: 
            return []
        return json.loads(content)
    except json.JSONDecodeError:
        return []

def save_queue(queue):
    QUEUE_PATH.write_text(json.dumps(queue, indent=2))

def enqueue(task):
    with _LOCK:
        q = load_queue()
        q.append(task)
        save_queue(q)

def dequeue():
    with _LOCK:
        q = load_queue()
        if not q:
            return None
        # Skip tasks for endpoint+vuln combos that are already found
        while q:
            task = q.pop(0)
            endpoint_vuln_key = (task.get("target", ""), task.get("vuln", ""))
            if endpoint_vuln_key not in _found_endpoint_vulns:
                save_queue(q)
                return task
        save_queue(q)
        return None

def mark_endpoint_vuln_found(endpoint, vuln_type):
    """Mark a (endpoint, vuln_type) pair as found - remaining payloads for this combo will be skipped."""
    with _LOCK:
        _found_endpoint_vulns.add((endpoint, vuln_type))

def is_endpoint_vuln_found(endpoint, vuln_type):
    """Check if a specific endpoint+vuln combo has already been found."""
    return (endpoint, vuln_type) in _found_endpoint_vulns

def reset_found_vulns():
    """Reset the found vulns set for a new scan."""
    global _found_endpoint_vulns
    _found_endpoint_vulns = set()
