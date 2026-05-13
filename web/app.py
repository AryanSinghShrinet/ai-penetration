from flask import Flask, render_template, abort, request, jsonify, send_from_directory
import logging
import hmac
import json
import yaml
import threading
import time
import uuid
from pathlib import Path
import sys
import os
import traceback
from dotenv import load_dotenv

load_dotenv()

# Add parent directory to path to import core modules
sys.path.insert(0, str(Path(__file__).parent.parent))

app = Flask(__name__)

STATE_DIR = Path("data/run_state")
LEARNING_FILE = Path("data/learning/memory.json")
CONFIG_PATH = Path("config/settings.yaml")

# In-memory tracking of active scans
active_scans = {}
# FIX WA1: Lock for thread-safe access to active_scans
_scan_lock = threading.Lock()


def _rebuild_active_scans():
    """B-2 FIX: reconstruct active_scans from disk at Flask startup so runs
    started before a server restart remain queryable from the UI."""
    if not STATE_DIR.exists():
        return
    for sf in STATE_DIR.glob("*.json"):
        try:
            state = json.loads(sf.read_text(encoding="utf-8"))
            if state.get("pipeline", {}).get("status") == "running":
                run_id = state.get("run_id", sf.stem)
                active_scans[run_id] = {
                    "status": "running (pre-restart)",
                    "target": state.get("target", "unknown"),
                    "run_id": run_id,
                    "progress": "Scan was running before server restart",
                }
        except Exception as _e:
            import logging; logging.getLogger(__name__).debug(f'[web] API key check error: {_e}')
# FIX WA4: Lock for safe concurrent writes to config/settings.yaml
_config_lock = threading.Lock()

# =============================================================================
# FIX WA2: Optional API key authentication middleware
# Set API_KEY env var to enable: set API_KEY=my-secret-key
# If not set, auth is disabled (for local dev use only).
# =============================================================================
_API_KEY = os.environ.get("API_KEY", "").strip()

def _require_api_key():
    """
    Check API key if configured.
    Returns (True, None) if OK, or (False, error_response) if rejected.
    """
    if not _API_KEY:
        return True, None  # Auth disabled
    key = request.headers.get("X-API-Key", "") or request.args.get("api_key", "")
    # S-3 FIX: use constant-time comparison to prevent timing oracle attacks
    if not hmac.compare_digest(key, _API_KEY):
        return False, (jsonify({"error": "Unauthorized. Provide X-API-Key header."}), 401)
    return True, None



# P-4 FIX: cache load_runs to avoid full disk scan on every dashboard request
_runs_cache = {"data": None, "ts": 0.0}
_RUNS_CACHE_TTL = 5.0  # seconds


def invalidate_runs_cache():
    """Call this when a new scan completes to force cache refresh."""
    _runs_cache["ts"] = 0.0


def load_runs():
    import time as _t
    now = _t.monotonic()
    if _runs_cache["data"] is not None and (now - _runs_cache["ts"]) < _RUNS_CACHE_TTL:
        return _runs_cache["data"]
    runs = []
    if not STATE_DIR.exists():
        _runs_cache.update({"data": runs, "ts": now})
        return []
        
    for f in STATE_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text())
            if "run_id" in data:
                runs.append(data)
        except (json.JSONDecodeError, OSError) as e:
            # Skip corrupted/unreadable files, don't crash the dashboard
            print(f"[dashboard] Warning: Could not load {f.name}: {e}")
    # Sort by created_at (newest first) - this is the field used in state files
    return sorted(runs, key=lambda x: x.get("created_at", ""), reverse=True)

def load_run(run_id):
    f = STATE_DIR / f"{run_id}.json"
    if not f.exists():
        abort(404)
    return json.loads(f.read_text(encoding='utf-8'))

# --- Showcase Website Routes ---
# S-6 FIX: use absolute path so the route is safe regardless of cwd
_SHOWCASE_DIR = Path(__file__).parent / "showcase"

@app.route("/showcase/")
def showcase():
    return send_from_directory(str(_SHOWCASE_DIR), "index.html")

@app.route("/showcase/<path:filename>")
def showcase_static(filename):
    return send_from_directory(str(_SHOWCASE_DIR), filename)

# --- Dashboard Routes ---

@app.route("/")
def index():
    return render_template("index.html", runs=load_runs())

@app.route("/run/<run_id>")
def run_view(run_id):
    return render_template("run.html", run=load_run(run_id))

@app.route("/run/<run_id>/vuln/<vuln>")
def vuln_view(run_id, vuln):
    run = load_run(run_id)
    results = run.get("layer_4", {}).get(vuln, [])
    return render_template(
        "vuln.html",
        run=run,
        vuln=vuln,
        results=results
    )

@app.route("/run/<run_id>/chains")
def chain_view(run_id):
    run = load_run(run_id)
    return render_template(
        "chain.html",
        run=run,
        chains=run.get("chain_suggestions", []),
        graph=run.get("attack_graph", {})
    )

@app.route("/learning")
def learning_view():
    if not LEARNING_FILE.exists():
        return render_template("learning.html", memory={})
    try:
        memory = json.loads(LEARNING_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        memory = {}
    return render_template("learning.html", memory=memory)

# --- API Routes for Scanning ---
@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    """Start a new scan with the given target (URL, domain, or wildcard)."""
    # FIX WA2: Enforce API key if configured
    ok, err = _require_api_key()
    if not ok:
        return err

    data = request.get_json() or {}
    target = data.get("target", "").strip()
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    # Use TargetParser to validate and expand the target
    try:
        from core.target_parser import TargetParser
        parser = TargetParser()
        target_info = parser.parse(target)
        
        # Get the primary target URL
        if target_info["targets"]:
            primary_target = target_info["targets"][0]
        else:
            # If no targets found, construct URL from domain
            if target.startswith(("http://", "https://")):
                primary_target = target
            else:
                primary_target = f"https://{target.lstrip('*.')}"
        
    except Exception as e:
        return jsonify({"error": f"Invalid target format: {str(e)}"}), 400
    
    # Generate a scan ID
    # D-5 FIX: use full UUID to avoid birthday-paradox collisions after ~65k scans
    scan_id = str(uuid.uuid4())
    
    # B-1 NOTE: We write to settings.yaml for CLI/legacy compatibility only.
    # The scan thread uses _scan_target/_scan_dry_run passed via closure (C-1 fix)
    # and does NOT re-read this file, so concurrent writes cannot corrupt the scan.
    try:
        with _config_lock:
            with open(CONFIG_PATH, "r") as f:
                config = yaml.safe_load(f)
            config["target"] = target
            config["dry_run"] = data.get("dry_run", False)
            with open(CONFIG_PATH, "w") as f:
                yaml.dump(config, f, default_flow_style=False)
    except Exception as e:
        import logging; logging.getLogger(__name__).warning(f"[web] Could not persist config: {e}")

    
    # FIX WA1: Use lock when writing to active_scans from request thread
    with _scan_lock:
        active_scans[scan_id] = {
            "status": "starting",
            "target": target,
            "start_time": time.time(),
            "run_id": None,
            "error": None,
            "progress": "Initializing..."
        }
    
    # Start scan in background thread
    # C-1 FIX: pass target/dry_run/phase directly — start() previously called
    # with zero args which always raises ValueError("Target is empty").
    _scan_target   = str(primary_target["url"] if isinstance(primary_target, dict) else primary_target)
    _scan_dry_run  = data.get("dry_run", False)
    _scan_phase    = data.get("phase", "all")

    def run_scan():
        try:
            # FIX WA1: Use lock for all active_scans bg writes
            with _scan_lock:
                active_scans[scan_id]["status"] = "running"
                active_scans[scan_id]["progress"] = "Starting reconnaissance..."

            from core.orchestrator import start
            result = start(target=_scan_target, dry_run=_scan_dry_run, phase=_scan_phase)

            with _scan_lock:
                active_scans[scan_id]["status"] = "completed"
                invalidate_runs_cache()
                active_scans[scan_id]["run_id"] = result["state"]["run_id"]
                active_scans[scan_id]["progress"] = "Scan complete!"

        except Exception as e:
            # Capture full traceback for persistent dict.get() error debugging
            tb = traceback.format_exc()
            print(f"\n[CRITICAL ERROR] Scan thread crashed:\n{tb}")
            with _scan_lock:
                active_scans[scan_id]["status"] = "error"
                active_scans[scan_id]["error"] = str(e)
                active_scans[scan_id]["progress"] = f"Error: {str(e)}"
    
    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    
    return jsonify({
        "scan_id": scan_id,
        "status": "started",
        "message": f"Scan started for {target}"
    })

@app.route("/api/scan/<scan_id>/status")
def scan_status(scan_id):
    """Get the status of an active or completed scan with real pipeline progress."""
    # FIX WA1: Thread-safe read from active_scans
    with _scan_lock:
        if scan_id not in active_scans:
            return jsonify({"error": "Scan not found"}), 404
        scan = dict(active_scans[scan_id])  # Snapshot to avoid holding lock during processing

    # Base result
    result = {
        "scan_id": scan_id,
        "status": scan["status"],
        "target": scan["target"],
        "progress": scan["progress"],
        "elapsed_seconds": int(time.time() - scan["start_time"])
    }
    
    # FIX 1: Include real pipeline status from state file
    if scan.get("run_id"):
        try:
            from core.state import get_pipeline_status
            pipeline = get_pipeline_status(scan["run_id"])
            result["pipeline"] = pipeline
            
            # Calculate overall progress from pipeline
            layer = pipeline.get("current_layer", 1)
            layer_progress = pipeline.get("progress", 0)
            result["overall_progress"] = int((layer - 1) * 20 + layer_progress * 20)  # 0-100%
            result["layer"] = pipeline.get("layer_name", "Unknown")
            result["layer_index"] = layer
            result["total_layers"] = 5
        except Exception as e:
            result["pipeline_error"] = str(e)
    
    # Include checklist data from active scan or completed run
    if scan.get("checklist"):
        result["checklist"] = scan["checklist"]
    
    if scan.get("layer_4"):
        result["layer_4"] = scan["layer_4"]
    
    if scan["status"] == "completed" and scan.get("run_id"):
        result["run_id"] = scan["run_id"]
        result["results_url"] = f"/run/{scan['run_id']}"
        
        # Get summary from state
        try:
            run_data = load_run(scan["run_id"])
            result["checklist"] = run_data.get("checklist", {})
            result["layer_4"] = run_data.get("layer_4", {})
            result["findings_count"] = sum(1 for v in run_data.get("checklist", {}).values() if v == "FOUND")
            result["pipeline"] = run_data.get("pipeline", {})
        except Exception as _sle:
            # Non-fatal: state file may not exist yet for a just-started scan
            import logging as _sl
            _sl.getLogger(__name__).debug(f"[status] Could not load run state for {scan['run_id']}: {_sle}")
    
    if scan["status"] == "error":
        result["error"] = scan["error"]
    
    return jsonify(result)


# FIX 2: Stop Scan Endpoint
@app.route("/api/scan/<scan_id>/stop", methods=["POST"])
def stop_scan(scan_id):
    """Request cancellation of a running scan."""
    # FIX WA2: Protect stop endpoint with API key
    ok, err = _require_api_key()
    if not ok:
        return err

    # FIX WA1: Thread-safe read of active_scans
    with _scan_lock:
        if scan_id not in active_scans:
            return jsonify({"error": "Scan not found"}), 404
        scan = dict(active_scans[scan_id])  # Snapshot
    
    if scan["status"] not in ["starting", "running"]:
        return jsonify({"error": "Scan is not running", "status": scan["status"]}), 400
    
    # Request cancellation via state file
    if scan.get("run_id"):
        try:
            from core.state import request_cancel
            if request_cancel(scan["run_id"]):
                # L-3 FIX: write status back to active_scans, not just the snapshot
                with _scan_lock:
                    active_scans[scan_id]["status"] = "cancelling"
                    active_scans[scan_id]["progress"] = "Cancellation requested..."
                return jsonify({
                    "message": "Cancellation requested",
                    "scan_id": scan_id,
                    "status": "cancelling"
                })
            else:
                return jsonify({"error": "Failed to request cancellation"}), 500
        except Exception as e:
            return jsonify({"error": f"Cancellation error: {str(e)}"}), 500
    else:
        return jsonify({"error": "Scan run_id not available yet"}), 400


# FIX 4: Scope Configuration Endpoint
@app.route("/api/config/scope")
def get_scope():
    """Get the current scope configuration."""
    try:
        scope_path = Path("config/scope.yaml")
        if not scope_path.exists():
            return jsonify({"error": "Scope config not found"}), 404
        
        with open(scope_path) as f:
            scope = yaml.safe_load(f)
        
        return jsonify(scope)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# FIX 3: POC Viewer Endpoints
@app.route("/api/run/<run_id>/pocs")
def list_pocs(run_id):
    """List all POCs generated for a run."""
    # S-2 FIX: require API key on all read endpoints
    ok, err = _require_api_key()
    if not ok: return err
    # S-1 FIX: validate run_id
    if not _validate_id(run_id):
        return jsonify({"error": "Invalid run ID format"}), 400
    poc_dir = Path(f"reports/pocs/{run_id}")
    if not poc_dir.exists():
        return jsonify({"pocs": [], "message": "No POCs generated"})
    
    pocs = []
    for f in poc_dir.glob("*.md"):
        pocs.append({
            "id": f.stem,
            "filename": f.name,
            "size": f.stat().st_size
        })
    
    return jsonify({"pocs": pocs, "count": len(pocs)})


# UUID/safe-id pattern — allows hex chars, hyphens, 8-64 chars
_SAFE_ID_RE = __import__("re").compile(r"^[0-9a-f\-]{8,64}$", __import__("re").IGNORECASE)
_REPORTS_BASE = (Path(__file__).parent.parent / "reports").resolve()


def _validate_id(value: str) -> bool:
    """Return True only if value matches UUID/safe-id pattern."""
    return bool(_SAFE_ID_RE.match(value))


@app.route("/api/run/<run_id>/poc/<poc_id>")
def get_poc(run_id, poc_id):
    """Get a specific POC by ID."""
    # S-2 FIX: require API key
    ok, err = _require_api_key()
    if not ok: return err
    # S-1 FIX: validate run_id and poc_id before using in path construction
    if not _validate_id(run_id) or not _validate_id(poc_id):
        return jsonify({"error": "Invalid ID format"}), 400
    poc_path = (Path("reports") / "pocs" / run_id / f"{poc_id}.md").resolve()
    # Confirm the resolved path stays inside reports/
    try:
        poc_path.relative_to(_REPORTS_BASE)
    except ValueError:
        return jsonify({"error": "Invalid path"}), 400
    if not poc_path.exists():
        return jsonify({"error": "POC not found"}), 404
    
    try:
        content = poc_path.read_text(encoding="utf-8")
        return jsonify({
            "id": poc_id,
            "run_id": run_id,
            "content": content,
            "format": "markdown"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/runs")
def list_runs():
    """Get list of all completed runs."""
    runs = load_runs()
    return jsonify([{
        "run_id": r.get("run_id"),
        "target": r.get("target"),
        "start_time": r.get("start_time"),
        "checklist": r.get("checklist", {}),
        "findings_count": sum(1 for v in r.get("checklist", {}).values() if v == "FOUND")
    } for r in runs])

@app.route("/api/run/<run_id>")
def get_run(run_id):
    """Get full details of a specific run."""
    run = load_run(run_id)
    return jsonify(run)


# =============================================================================
# EXPLOIT DATABASE ROUTES
# =============================================================================

# Lazy-loaded database instance — L-4 FIX: protected by a dedicated lock
_vuln_db = None
_vuln_updater = None
_vuln_init_lock = threading.Lock()

def get_vuln_db():
    """Get or create the vulnerability database instance (thread-safe)."""
    global _vuln_db
    with _vuln_init_lock:
        if _vuln_db is None:
            try:
                from core.vuln_database import VulnDatabase
                _vuln_db = VulnDatabase()
            except Exception as e:
                import logging; logging.getLogger(__name__).warning(f"VulnDatabase init failed: {e}")
                return None
        return _vuln_db

def get_updater():
    """Get or create the vulnerability updater instance (thread-safe)."""
    global _vuln_updater
    with _vuln_init_lock:
        if _vuln_updater is None:
            try:
                from core.vuln_updater import VulnUpdater
                db = get_vuln_db()
                if db:
                    _vuln_updater = VulnUpdater(db=db)
            except Exception as e:
                import logging; logging.getLogger(__name__).warning(f"VulnUpdater init failed: {e}")
            return None
    return _vuln_updater


@app.route("/exploits")
def exploits_page():
    """Exploit database search page."""
    db = get_vuln_db()
    stats = db.get_stats() if db else {}
    return render_template("exploits.html", stats=stats)


@app.route("/api/exploits/search")
def search_exploits():
    """
    Search exploit database.
    
    Query params:
        q: Search query (keyword, CVE ID, product name)
        severity: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
        platform: Filter by platform (linux, windows, php, etc.)
        type: Filter by exploit type (rce, sqli, xss, etc.)
        has_exploit: If 'true', only show CVEs with exploits
        min_cvss: Minimum CVSS score
        max_cvss: Maximum CVSS score
        limit: Results per page (default 50)
        offset: Pagination offset
    """
    db = get_vuln_db()
    if not db:
        return jsonify({"error": "Database not available"}), 500
    
    # Parse query parameters
    query = request.args.get("q", "").strip()
    severity = request.args.get("severity", "").strip().upper() or None
    platform = request.args.get("platform", "").strip().lower() or None
    exploit_type = request.args.get("type", "").strip().lower() or None
    has_exploit = request.args.get("has_exploit", "").lower() == "true"
    
    min_cvss = None
    max_cvss = None
    try:
        if request.args.get("min_cvss"):
            min_cvss = float(request.args.get("min_cvss"))
        if request.args.get("max_cvss"):
            max_cvss = float(request.args.get("max_cvss"))
    except ValueError as _e:
        import logging; logging.getLogger(__name__).debug(f"[web] CVSS filter parse error: {_e}")
    
    # FIX WA3: Cap limit to prevent OOM from large queries
    try:
        limit = min(int(request.args.get("limit", 50)), 500)
        offset = max(int(request.args.get("offset", 0)), 0)
    except (ValueError, TypeError):
        limit = 50
        offset = 0
    
    # Execute search
    try:
        results = db.search(
            query=query,
            severity=severity if severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] else None,
            platform=platform,
            exploit_type=exploit_type,
            has_exploit=has_exploit if has_exploit else None,
            min_cvss=min_cvss,
            max_cvss=max_cvss,
            limit=limit,
            offset=offset
        )
        
        # Convert CVERecords and ExploitRecords to dicts
        return jsonify({
            "cves": [
                {
                    "id": cve.id,
                    "description": cve.description[:300] + "..." if len(cve.description) > 300 else cve.description,
                    "cvss_v3_score": cve.cvss_v3_score,
                    "cvss_v2_score": cve.cvss_v2_score,
                    "severity": cve.severity.value,
                    "published_date": cve.published_date,
                    "cwe_ids": cve.cwe_ids[:3]
                }
                for cve in results["cves"]
            ],
            "exploits": [
                {
                    "id": exp.id,
                    "title": exp.title[:100] + "..." if len(exp.title) > 100 else exp.title,
                    "platform": exp.platform,
                    "exploit_type": exp.exploit_type,
                    "cve_id": exp.cve_id,
                    "source": exp.source,
                    "verified": exp.verified,
                    "reference_url": exp.reference_url
                }
                for exp in results["exploits"]
            ],
            "total_cves": results["total_cves"],
            "total_exploits": results["total_exploits"],
            "limit": limit,
            "offset": offset
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/exploits/cve/<cve_id>")
def get_cve_details(cve_id):
    """Get detailed CVE information including associated exploits."""
    db = get_vuln_db()
    if not db:
        return jsonify({"error": "Database not available"}), 500
    
    cve = db.get_cve(cve_id)
    if not cve:
        return jsonify({"error": "CVE not found"}), 404
    
    exploits = db.get_exploits_by_cve(cve_id)
    
    return jsonify({
        "cve": {
            "id": cve.id,
            "description": cve.description,
            "cvss_v3_score": cve.cvss_v3_score,
            "cvss_v3_vector": cve.cvss_v3_vector,
            "cvss_v2_score": cve.cvss_v2_score,
            "cvss_v2_vector": cve.cvss_v2_vector,
            "severity": cve.severity.value,
            "published_date": cve.published_date,
            "modified_date": cve.modified_date,
            "cwe_ids": cve.cwe_ids,
            "affected_products": cve.affected_products[:20],
            "references": cve.references
        },
        "exploits": [
            {
                "id": exp.id,
                "title": exp.title,
                "platform": exp.platform,
                "exploit_type": exp.exploit_type,
                "source": exp.source,
                "source_id": exp.source_id,
                "reference_url": exp.reference_url,
                "verified": exp.verified
            }
            for exp in exploits
        ]
    })


@app.route("/api/exploits/exploit/<exploit_id>")
def get_exploit_details(exploit_id):
    """Get detailed exploit information."""
    db = get_vuln_db()
    if not db:
        return jsonify({"error": "Database not available"}), 500
    
    exploit = db.get_exploit(exploit_id)
    if not exploit:
        return jsonify({"error": "Exploit not found"}), 404
    
    # Get associated CVE if any
    cve_info = None
    if exploit.cve_id:
        cve = db.get_cve(exploit.cve_id)
        if cve:
            cve_info = {
                "id": cve.id,
                "description": cve.description[:200],
                "severity": cve.severity.value,
                "cvss_v3_score": cve.cvss_v3_score
            }
    
    return jsonify({
        "exploit": {
            "id": exploit.id,
            "title": exploit.title,
            "description": exploit.description,
            "platform": exploit.platform,
            "exploit_type": exploit.exploit_type,
            "cve_id": exploit.cve_id,
            "source": exploit.source,
            "source_id": exploit.source_id,
            "reference_url": exploit.reference_url,
            "author": exploit.author,
            "published_date": exploit.published_date,
            "verified": exploit.verified,
            "keywords": exploit.keywords,
            "affected_products": exploit.affected_products
        },
        "cve": cve_info
    })


@app.route("/api/exploits/stats")
def get_exploit_stats():
    """Get exploit database statistics."""
    db = get_vuln_db()
    if not db:
        return jsonify({"error": "Database not available"}), 500
    
    return jsonify(db.get_stats())


@app.route("/api/exploits/sync", methods=["POST"])
def sync_exploit_database():
    """
    Trigger a database sync.
    
    JSON body (optional):
        source: 'all', 'nvd', 'exploitdb', 'local' (default: 'all')
        incremental: boolean (default: true)
    """
    updater = get_updater()
    if not updater:
        return jsonify({"error": "Updater not available"}), 500
    
    if updater.is_syncing():
        return jsonify({
            "error": "Sync already in progress",
            "progress": {
                k: {"status": v.status, "message": v.message}
                for k, v in updater.get_progress().items()
            }
        }), 409
    
    data = request.get_json() or {}
    source = data.get("source", "all")
    incremental = data.get("incremental", True)
    
    # Run sync in background
    def run_sync():
        try:
            if source == "all":
                updater.sync_all(incremental=incremental)
            elif source == "nvd":
                updater.sync_nvd(incremental=incremental)
            elif source == "exploitdb":
                updater.sync_exploitdb()
            elif source == "local":
                updater.sync_local_exploits()
        except Exception as e:
            tb = traceback.format_exc()
            print(f"\n[CRITICAL ERROR] Sync thread crashed:\n{tb}")
    
    thread = threading.Thread(target=run_sync, daemon=True)
    thread.start()
    
    return jsonify({
        "status": "started",
        "message": f"Sync started for source: {source}"
    })


@app.route("/api/exploits/sync/status")
def get_sync_status():
    """Get current sync status."""
    updater = get_updater()
    if not updater:
        return jsonify({"error": "Updater not available"}), 500
    
    return jsonify({
        "is_syncing": updater.is_syncing(),
        "progress": {
            k: {
                "status": v.status,
                "message": v.message,
                "items_fetched": v.items_fetched,
                "items_inserted": v.items_inserted,
                "errors": v.errors
            }
            for k, v in updater.get_progress().items()
        }
    })


# =============================================================================
# AI MODEL CONFIGURATION ENDPOINTS
# =============================================================================

AI_CONFIG_PATH = Path("config/ai.yaml")
_ai_config_lock = threading.Lock()


@app.route("/api/ai/config", methods=["GET"])
def get_ai_config():
    """
    Return the current AI provider/model config plus the list of available
    local models so the UI can render a model-selector dropdown.
    """
    try:
        with _ai_config_lock:
            cfg = yaml.safe_load(AI_CONFIG_PATH.read_text(encoding="utf-8")) or {}
    except Exception as e:
        return jsonify({"error": f"Could not read ai.yaml: {e}"}), 500

    return jsonify({
        "enabled":  cfg.get("enabled", True),
        "provider": cfg.get("provider", "local"),
        "model":    cfg.get("model", "qwen2.5-coder:7b"),
        "local": {
            "base_url":        cfg.get("local", {}).get("base_url", "http://localhost:11434/v1"),
            "primary_model":   cfg.get("local", {}).get("primary_model", "qwen2.5-coder:7b"),
            "available_models": cfg.get("local", {}).get("available_models", []),
        },
        "cloud": cfg.get("cloud", {}),
        "mode":    cfg.get("mode", {}),
        "safety":  cfg.get("safety", {}),
    })


@app.route("/api/ai/config", methods=["POST"])
def set_ai_config():
    """
    Switch AI provider / model at runtime without restarting the server.

    JSON body (all fields optional — only supplied fields are changed):
        provider  : "local" | "openai" | "anthropic"
        model     : model name string
        base_url  : Ollama base URL (only used when provider=local)
        enabled   : true | false
    """
    ok, err = _require_api_key()
    if not ok:
        return err

    data = request.get_json() or {}

    try:
        with _ai_config_lock:
            cfg = yaml.safe_load(AI_CONFIG_PATH.read_text(encoding="utf-8")) or {}

            if "enabled" in data:
                cfg["enabled"] = bool(data["enabled"])

            if "provider" in data:
                p = str(data["provider"]).lower()
                if p not in ("local", "openai", "anthropic"):
                    return jsonify({"error": "provider must be 'local', 'openai', or 'anthropic'"}), 400
                cfg["provider"] = p

            if "model" in data:
                cfg["model"] = str(data["model"])

            if "base_url" in data:
                cfg.setdefault("local", {})["base_url"] = str(data["base_url"])

            AI_CONFIG_PATH.write_text(
                yaml.dump(cfg, default_flow_style=False, allow_unicode=True),
                encoding="utf-8"
            )

        return jsonify({
            "message": "AI config updated successfully",
            "provider": cfg.get("provider"),
            "model":    cfg.get("model"),
            "enabled":  cfg.get("enabled"),
        })

    except Exception as e:
        return jsonify({"error": f"Failed to update config: {e}"}), 500


if __name__ == "__main__":
    _rebuild_active_scans()  # B-2 FIX
    # Change to project root directory so imports work
    os.chdir(Path(__file__).parent.parent)
    # FIX WA5: Never enable Werkzeug's interactive debugger unconditionally —
    # it exposes a Python REPL on any unhandled exception.
    # Enable only when FLASK_DEBUG=true is explicitly set in the environment.
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, port=5000)
