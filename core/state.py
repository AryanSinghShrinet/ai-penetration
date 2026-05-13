import json
import uuid
import threading
import os
import sys
from pathlib import Path
from datetime import datetime
import logging

try:
    import psycopg2
    from psycopg2.extras import Json
except ImportError:
    psycopg2 = None
    Json = None

logger = logging.getLogger("state")


def _safe_json_default(obj):
    """
    Custom JSON serializer fallback.
    Converts un-serializable objects to a safe string instead of crashing.
    Fixes: TypeError: Object of type Response is not JSON serializable
    """
    # requests.Response — store key metadata only
    try:
        import requests
        if isinstance(obj, requests.Response):
            return {
                "__type__": "Response",
                "status_code": obj.status_code,
                "url": obj.url,
                "content_length": len(obj.content),
            }
    except ImportError:
        pass
    # datetime objects
    if isinstance(obj, datetime):
        return obj.isoformat()
    # sets
    if isinstance(obj, set):
        return list(obj)
    # bytes
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    # Anything else — use repr so we at least see what it was
    return f"<non-serializable: {type(obj).__name__}: {repr(obj)[:120]}>"

STATE_DIR = Path("data/run_state")
STATE_DIR.mkdir(parents=True, exist_ok=True)

_LOCK = threading.RLock()

# ============================================================================
# FIX S1: Cross-process file locking using OS-level advisory locks
# This prevents JSON corruption when Flask + scanner run as separate processes.
# ============================================================================

def _lock_file_path(state_file: Path) -> Path:
    """Return the lock file path for a given state file."""
    return state_file.with_suffix(".lock")


def _acquire_file_lock(lock_path: Path):
    """Acquire an OS-level file lock. Returns the file handle.
    E-1 FIX: wrap in try/except so the file handle is always closed on failure.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(lock_path, "w")
    try:
        if sys.platform == "win32":
            import msvcrt
            import time
            for _ in range(20):
                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                    return fh
                except OSError:
                    time.sleep(0.05)
            msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(fh, fcntl.LOCK_EX)
        return fh
    except Exception as _e:
        fh.close()
        raise


def _release_file_lock(fh, lock_path: Path):
    """Release the OS-level file lock."""
    try:
        if sys.platform == "win32":
            import msvcrt
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh, fcntl.LOCK_UN)
    except Exception as _e:
        import logging; logging.getLogger(__name__).debug(f'[state] file unlock error: {_e}')
    finally:
        try:
            fh.close()
        except Exception as _e:
            import logging; logging.getLogger(__name__).debug(f'[state] file close error: {_e}')


def _safe_write_state(state_file: Path, state: dict):
    """
    Atomically write state using a temp file + rename.
    Prevents partial writes from corrupting the state file.
    Uses _safe_json_default to handle non-serializable objects (e.g. Response).
    """
    tmp_file = state_file.with_suffix(".tmp")
    tmp_file.write_text(
        json.dumps(state, indent=2, default=_safe_json_default),
        encoding="utf-8"
    )
    # Atomic replace: on Windows this may fail if .json exists, so remove first
    try:
        tmp_file.replace(state_file)
    except Exception as _e:
        tmp_file.rename(state_file)

# ============================================================================
# PostgreSQL Backend Support
# ============================================================================

def _is_postgres():
    url = os.environ.get("DATABASE_URL")
    return url is not None and url.startswith("postgres") and psycopg2 is not None

def _get_db_conn():
    if not _is_postgres():
        return None
    try:
        conn = psycopg2.connect(os.environ.get("DATABASE_URL"))
        conn.autocommit = True
        return conn
    except Exception as e:
        logger.error(f"Failed to connect to Postgres: {e}")
        return None

def _init_db():
    if not _is_postgres():
        return
    conn = _get_db_conn()
    if not conn:
        return
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_runs (
                    run_id TEXT PRIMARY KEY,
                    target TEXT,
                    state JSONB,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                )
            """)
    finally:
        conn.close()

# Initialize DB on import if needed
_init_db()

def create_run(target, resume_enabled):
    with _LOCK:
        run_id = str(uuid.uuid4())
        state_file = STATE_DIR / f"{run_id}.json"

        # Initial checklist with all vulnerability types to test
        checklist = {
            # Critical & High severity
            "xss": "NOT_STARTED",
            "sqli": "NOT_STARTED",
            "idor": "NOT_STARTED",
            "ssrf": "NOT_STARTED",
            "file_upload": "NOT_STARTED",
            "lfi": "NOT_STARTED",
            "path_traversal": "NOT_STARTED",
            "cmd_injection": "NOT_STARTED",
            "auth_bypass": "NOT_STARTED",
            "business_logic": "NOT_STARTED",
            # Medium severity
            "cors": "NOT_STARTED",
            "open_redirect": "NOT_STARTED",
            "csrf": "NOT_STARTED",
            "brute_force": "NOT_STARTED",
            "information_disclosure": "NOT_STARTED",
            # Low severity
            "security_headers": "NOT_STARTED",
        }

        state = {
            "run_id": run_id,
            "target": target,
            "created_at": datetime.utcnow().isoformat(),
            "resume": resume_enabled,
            "phases": {
                "layer_1": "DONE",
                "layer_2": "NOT_STARTED",
                "layer_3": "NOT_STARTED",
                "layer_4": "NOT_STARTED",
                "layer_5": "NOT_STARTED"
            },
            # Real-time pipeline tracking for UI
            "pipeline": {
                "current_layer": 1,
                "total_layers": 5,
                "layer_name": "Initialization",
                "status": "running",
                "progress": 0.0,
                "message": "Starting scan..."
            },
            # Scan abort control
            "cancel_requested": False,
            # User-configurable scan settings
            "scan_config": {
                "crawl_depth": 3,
                "max_pages": 100,
                "rate_limit_rps": 5,
                "verification_enabled": True,
                "selected_vulns": list(checklist.keys())
            },
            "checklist": checklist,
            "blocked": False,
            "authenticated": False
        }

        # D-4 FIX: use atomic write to prevent corruption on crash
        if _is_postgres():
            conn = _get_db_conn()
            if conn:
                try:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO scan_runs (run_id, target, state) VALUES (%s, %s, %s)",
                            (run_id, target, Json(state))
                        )
                finally:
                    conn.close()
        
        _safe_write_state(state_file, state)
        return state

def _load_state_unlocked(state_file: Path) -> dict:
    """L-1 FIX: Read state assuming the caller already holds the file lock.
    Avoids re-acquiring a non-reentrant advisory lock inside composed writers."""
    content_raw = state_file.read_text(encoding="utf-8")
    return json.loads(content_raw) if content_raw.strip() else {}


def load_state(run_id):
    with _LOCK:
        if _is_postgres():
            conn = _get_db_conn()
            if conn:
                try:
                    with conn.cursor() as cur:
                        cur.execute("SELECT state FROM scan_runs WHERE run_id = %s", (run_id,))
                        row = cur.fetchone()
                        if row:
                            return row[0]
                finally:
                    conn.close()

        state_file = STATE_DIR / f"{run_id}.json"
        if not state_file.exists():
            raise FileNotFoundError("Run state not found")
        # FIX S1: Use OS-level file lock for cross-process safety
        lock_path = _lock_file_path(state_file)
        fh = _acquire_file_lock(lock_path)
        try:
            return _load_state_unlocked(state_file)
        finally:
            _release_file_lock(fh, lock_path)

def update_state(run_id, key, value):
    with _LOCK:
        state_file = STATE_DIR / f"{run_id}.json"
        lock_path = _lock_file_path(state_file)
        # L-1 FIX: acquire file lock ONCE, then use _load_state_unlocked to
        # avoid re-entering the non-reentrant advisory lock inside load_state.
        fh = _acquire_file_lock(lock_path)
        try:
            state = _load_state_unlocked(state_file)
            state[key] = value
            _safe_write_state(state_file, state)
        finally:
            _release_file_lock(fh, lock_path)

def update_checklist(run_id, vuln, status):
    with _LOCK:
        state_file = STATE_DIR / f"{run_id}.json"
        lock_path = _lock_file_path(state_file)
        # L-1 FIX: single file-lock acquisition for read+write
        fh = _acquire_file_lock(lock_path)
        try:
            state = _load_state_unlocked(state_file)
            if vuln in state["checklist"]:
                state["checklist"][vuln] = status
                _safe_write_state(state_file, state)
        finally:
            _release_file_lock(fh, lock_path)


# ============================================================================
# PIPELINE TRACKING (FIX 1) - Real progress for UI
# ============================================================================

LAYER_NAMES = {
    1: "Initialization",
    2: "Reconnaissance",
    3: "Payload Planning",
    4: "Execution",
    5: "Verification & Reporting"
}


def update_pipeline(run_id: str, layer: int, progress: float = 0.0, 
                    message: str = "", status: str = "running") -> None:
    """
    Update pipeline progress for real-time UI tracking.
    
    Args:
        run_id: The scan run ID
        layer: Current layer (1-5)
        progress: Progress within this layer (0.0 - 1.0)
        message: Human-readable status message
        status: One of 'running', 'completed', 'error', 'cancelled'
    """
    with _LOCK:
        state_file = STATE_DIR / f"{run_id}.json"
        if not state_file.exists():
            return
        
        # C-4 FIX: acquire the file lock before read-modify-write so this
        # function is safe to call from multiple processes/threads.
        lock_path = _lock_file_path(state_file)
        fh = _acquire_file_lock(lock_path)
        try:
            content_raw = state_file.read_text(encoding="utf-8")
            state = json.loads(content_raw) if content_raw.strip() else {}
            state["pipeline"] = {
                "current_layer": layer,
                "total_layers": 5,
                "layer_name": LAYER_NAMES.get(layer, f"Layer {layer}"),
                "status": status,
                "progress": min(1.0, max(0.0, progress)),
                "message": message or LAYER_NAMES.get(layer, "Processing...")
            }
            if layer <= 5:
                phase_key = f"layer_{layer}"
                if phase_key in state.get("phases", {}):
                    state["phases"][phase_key] = "IN_PROGRESS" if status == "running" else "DONE"
            _safe_write_state(state_file, state)
        finally:
            _release_file_lock(fh, lock_path)


def get_pipeline_status(run_id: str) -> dict:
    """Get current pipeline status for UI."""
    with _LOCK:
        try:
            state = load_state(run_id)
            return state.get("pipeline", {
                "current_layer": 0,
                "total_layers": 5,
                "layer_name": "Unknown",
                "status": "unknown",
                "progress": 0.0,
                "message": "No status available"
            })
        except FileNotFoundError:
            return {"error": "Run not found"}


# ============================================================================
# CANCEL CONTROL (FIX 2) - Abort scan functionality
# ============================================================================

def request_cancel(run_id: str) -> bool:
    """Request cancellation of a running scan."""
    with _LOCK:
        try:
            state = load_state(run_id)
            state["cancel_requested"] = True
            state["pipeline"]["status"] = "cancelling"
            state["pipeline"]["message"] = "Cancellation requested..."
            state_file = STATE_DIR / f"{run_id}.json"
            _safe_write_state(state_file, state)
            return True
        except FileNotFoundError:
            return False


def is_cancel_requested(run_id: str) -> bool:
    """Check if cancellation was requested."""
    with _LOCK:
        try:
            state = load_state(run_id)
            return state.get("cancel_requested", False)
        except FileNotFoundError:
            return False


def mark_cancelled(run_id: str) -> None:
    """Mark scan as cancelled."""
    with _LOCK:
        try:
            state = load_state(run_id)
            state["pipeline"]["status"] = "cancelled"
            state["pipeline"]["message"] = "Scan cancelled by user"
            state_file = STATE_DIR / f"{run_id}.json"
            # C-4 FIX: use atomic write
            _safe_write_state(state_file, state)
        except FileNotFoundError as _e:
            import logging; logging.getLogger(__name__).debug(f'[state] cancel-state FileNotFoundError: {_e}')


# ============================================================================
# SCAN CONFIG (FIX 5) - User configurable settings
# ============================================================================

def update_scan_config(run_id: str, config: dict) -> None:
    """Update scan configuration."""
    with _LOCK:
        try:
            state = load_state(run_id)
            if "scan_config" not in state:
                state["scan_config"] = {}
            state["scan_config"].update(config)
            state_file = STATE_DIR / f"{run_id}.json"
            # D-4 FIX: atomic write
            _safe_write_state(state_file, state)
        except FileNotFoundError as _e:
            import logging; logging.getLogger(__name__).debug(f'[state] update-config FileNotFoundError: {_e}')


def get_scan_config(run_id: str) -> dict:
    """Get scan configuration."""
    with _LOCK:
        try:
            state = load_state(run_id)
            return state.get("scan_config", {})
        except FileNotFoundError:
            return {}

def _safe_state_write(run_id: str, mutator):
    """
    D-4 helper: acquire file lock once, load state (unlocked), apply
    mutator function, then write atomically. All 11 writers use this.
    """
    with _LOCK:
        state_file = STATE_DIR / f"{run_id}.json"
        
        # Determine if we should use Postgres
        use_pg = _is_postgres()
        state = None
        
        if use_pg:
            conn = _get_db_conn()
            if conn:
                try:
                    with conn.cursor() as cur:
                        cur.execute("SELECT state FROM scan_runs WHERE run_id = %s", (run_id,))
                        row = cur.fetchone()
                        if row:
                            state = row[0]
                finally:
                    conn.close()

        if state is None:
            # Fallback to file if DB entry missing or PG not used
            if not state_file.exists():
                return
            lock_path = _lock_file_path(state_file)
            fh = _acquire_file_lock(lock_path)
            try:
                state = _load_state_unlocked(state_file)
            finally:
                _release_file_lock(fh, lock_path)

        if state is not None:
            mutator(state)
            
            # Sync to DB
            if use_pg:
                conn = _get_db_conn()
                if conn:
                    try:
                        with conn.cursor() as cur:
                            cur.execute(
                                "UPDATE scan_runs SET state = %s, updated_at = CURRENT_TIMESTAMP WHERE run_id = %s",
                                (Json(state), run_id)
                            )
                    finally:
                        conn.close()
            
            # Sync to file (for local cache/safety)
            _safe_write_state(state_file, state)


def save_layer2_output(run_id, recon_data, context_data):
    def _m(state):
        state["layer_2"] = {"recon": recon_data, "context": context_data}
        state["phases"]["layer_2"] = "DONE"
    _safe_state_write(run_id, _m)

def save_layer3_payloads(run_id, payload_plan):
    def _m(state):
        state["layer_3"] = {"payload_plan": payload_plan}
        state["phases"]["layer_3"] = "DONE"
    _safe_state_write(run_id, _m)

def save_execution_result(run_id, vuln, execution_result):
    def _m(state):
        if "layer_4" not in state:
            state["layer_4"] = {}
        if vuln not in state["layer_4"]:
            state["layer_4"][vuln] = []
        state["layer_4"][vuln].append(execution_result)
    _safe_state_write(run_id, _m)

def mark_blocked(run_id):
    _safe_state_write(run_id, lambda s: s.update({"blocked": True}))

_VALID_VULN_STATUSES = {
    "NOT_STARTED", "IN_PROGRESS", "FOUND", "FAILED",
    "BLOCKED", "PLANNED", "SKIPPED", "ERROR"
}

def update_vuln_status(run_id, vuln, status):
    # D-1 FIX: reject unknown status strings before they corrupt the checklist
    if status not in _VALID_VULN_STATUSES:
        raise ValueError(f"Invalid vuln status {status!r}. Must be one of {_VALID_VULN_STATUSES}")
    def _m(state):
        state["checklist"][vuln] = status
    _safe_state_write(run_id, _m)

def mark_out_of_scope(run_id, url):
    def _m(state):
        state["out_of_scope"] = True
        state["out_of_scope_url"] = url
    _safe_state_write(run_id, _m)

def save_rate_state(run_id, rate_state):
    _safe_state_write(run_id, lambda s: s.update({"rate_state": rate_state}))

def load_rate_state(run_id):
    with _LOCK:
        state = load_state(run_id)
        return state.get("rate_state", {})

def mark_dry_run(run_id, enabled: bool):
    _safe_state_write(run_id, lambda s: s.update({"dry_run": enabled}))


def save_completed_endpoints(run_id, endpoints: list):
    """Save list of completed endpoints for resume support."""
    def _m(state):
        if "completed_endpoints" not in state:
            state["completed_endpoints"] = []
        existing = set(state["completed_endpoints"])
        for ep in endpoints:
            if ep not in existing:
                state["completed_endpoints"].append(ep)
    _safe_state_write(run_id, _m)


def load_completed_endpoints(run_id) -> list:
    """Load completed endpoints for resume."""
    with _LOCK:
        state = load_state(run_id)
        return state.get("completed_endpoints", [])


def save_crawl_frontier(run_id, frontier: list):
    """Save crawl frontier (URLs pending to visit) for resume."""
    _safe_state_write(run_id, lambda s: s.update({"crawl_frontier": frontier}))


def load_crawl_frontier(run_id) -> list:
    """Load crawl frontier for resume."""
    with _LOCK:
        state = load_state(run_id)
        return state.get("crawl_frontier", [])


def save_confirmed_vulnkeys(run_id, vulnkeys: list):
    """Save confirmed VulnKey strings for resume."""
    _safe_state_write(run_id, lambda s: s.update({"confirmed_vulnkeys": vulnkeys}))


def load_confirmed_vulnkeys(run_id) -> list:
    """Load confirmed VulnKeys for resume."""
    with _LOCK:
        state = load_state(run_id)
        return state.get("confirmed_vulnkeys", [])


def get_resume_state(run_id) -> dict:
    """Get comprehensive resume state."""
    with _LOCK:
        state = load_state(run_id)
        return {
            "phases": state.get("phases", {}),
            "checklist": state.get("checklist", {}),
            "completed_endpoints": state.get("completed_endpoints", []),
            "crawl_frontier": state.get("crawl_frontier", []),
            "confirmed_vulnkeys": state.get("confirmed_vulnkeys", []),
            "rate_state": state.get("rate_state", {}),
            "blocked": state.get("blocked", False),
        }


def is_phase_complete(run_id, phase: str) -> bool:
    """Check if a phase is complete for resume logic."""
    with _LOCK:
        state = load_state(run_id)
        return state.get("phases", {}).get(phase) == "DONE"

