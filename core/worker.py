"""
Distributed Worker with Canonical Vulnerability Engine

Processes tasks from the queue with:
- VulnKey-based canonical vulnerability tracking
- ScanScheduler for stop-after-confirmed rule
- Evidence scoring for POC selection
- Thread-safe concurrent execution
"""

import time
import threading
from core.task_queue import dequeue, mark_endpoint_vuln_found, is_endpoint_vuln_found
from core.executor import execute_payload
from core.learning_memory import record_result
from core.state import save_execution_result, update_vuln_status, mark_blocked, load_state

# Scanner integration
from core.scanner.knowledge_base import ScannerKnowledgeBase
from core.scanner.scan_scheduler import ScanScheduler
from core.scanner.vuln_key import normalize_vuln_key, Evidence, ScanMode


# Track which vulns have been found globally (for status updates)
_vuln_found_any = set()

# Shared scanner components (initialized by first worker or main thread)
_shared_knowledge_base = None
_shared_scheduler = None
_init_lock = threading.Lock()  # Lock for thread-safe initialization


def reset_worker_cache():
    """Reset the worker's vuln cache for a new scan."""
    global _vuln_found_any, _shared_knowledge_base, _shared_scheduler
    with _init_lock:
        _vuln_found_any = set()
        _shared_knowledge_base = None
        _shared_scheduler = None


def init_worker_scanner(run_id, logger=None):
    """
    Initialize shared scanner components for workers.
    
    This should be called once from the main thread before spawning workers.
    Uses lock to prevent race conditions when called from multiple threads.
    The knowledge base uses RLock for thread safety.
    """
    global _shared_knowledge_base, _shared_scheduler
    
    with _init_lock:
        if _shared_knowledge_base is None:
            _shared_knowledge_base = ScannerKnowledgeBase(run_id)
        
        if _shared_scheduler is None:
            _shared_scheduler = ScanScheduler(_shared_knowledge_base, logger)
    
    return _shared_knowledge_base, _shared_scheduler


def worker_loop(worker_id, session, logger, rate_controller, dry_run, run_id):
    """
    Worker loop with scanner integration.
    
    Uses shared ScanScheduler for stop-after-confirmed enforcement.
    """
    global _vuln_found_any, _shared_knowledge_base, _shared_scheduler
    
    logger.info(f"[worker-{worker_id}] started")
    
    # Initialize scanner if not already done
    if _shared_scheduler is None:
        init_worker_scanner(run_id, logger)
    
    scheduler = _shared_scheduler

    while True:
        task = dequeue()
        if not task:
            logger.info(f"[worker-{worker_id}] no tasks left")
            break

        task["worker_id"] = worker_id
        vuln = task["vuln"]
        payload_entry = task["payload"]
        target = task["target"]  # This is now the specific endpoint
        
        # Extract payload details
        if isinstance(payload_entry, dict):
            payload_str = payload_entry.get("original", str(payload_entry))
            param = payload_entry.get("param") or payload_entry.get("field") or vuln
            location = payload_entry.get("location", "query")
            method = payload_entry.get("method", "GET")
        else:
            payload_str = str(payload_entry)
            param = vuln
            location = "query"
            method = "GET"
        
        # =====================================================================
        # SCANNER INTEGRATION: Use ScanScheduler for stop-after-confirmed
        # =====================================================================
        if scheduler:
            scan_decision = scheduler.should_scan(
                endpoint=target,
                param=param,
                location=location,
                vuln_type=vuln,
                payload=payload_str,
                method=method
            )
            
            if not scan_decision.should_scan:
                logger.info(f"[worker-{worker_id}] SKIPPING: {scan_decision.reason_detail}")
                continue
        else:
            # Fallback to legacy skip logic
            if is_endpoint_vuln_found(target, vuln):
                logger.info(f"[worker-{worker_id}] SKIPPING {vuln} on {target[:60]}... - already found")
                continue
        
        # Mark as IN_PROGRESS if not already found anywhere
        if vuln not in _vuln_found_any:
            update_vuln_status(run_id, vuln, "IN_PROGRESS")

        result = execute_payload(
            target,
            vuln,
            payload_entry,
            logger,
            rate_controller,
            dry_run,
            session
        )
        
        # Record payload execution in scheduler
        if scheduler:
            scheduler.record_payload_sent(target, param, location, payload_str)

        record_result(target, vuln, result.get("payload", payload_entry), result["status"])
        
        # Save result to state as well (for reporting)
        save_execution_result(run_id, vuln, result)
        
        if result["status"] == "SUCCESS":
            logger.info(f"[worker-{worker_id}] [+] FOUND {vuln} on {target[:60]}!")
            update_vuln_status(run_id, vuln, "FOUND")
            _vuln_found_any.add(vuln)
            
            # Mark in legacy system too
            mark_endpoint_vuln_found(target, vuln)
            
            # CRITICAL: Record in scanner knowledge base with VulnKey
            if scheduler:
                scheduler.record_vulnerability_confirmed(
                    endpoint=target,
                    param=param,
                    location=location,
                    vuln_type=vuln,
                    payload=payload_str,
                    method=method,
                    response_code=result.get("response_code", 200),
                    response_body=result.get("response_body", ""),
                    evidence_dict=result.get("evidence", {})
                )
                logger.info(f"[worker-{worker_id}] [canonical] Recorded VulnKey - stop rule active")
                
        elif result["status"] == "BLOCKED":
            if vuln not in _vuln_found_any:
                update_vuln_status(run_id, vuln, "BLOCKED")
        elif result["status"] == "FAILED":
            # Only update to FAILED if not already FOUND anywhere
            if vuln not in _vuln_found_any:
                update_vuln_status(run_id, vuln, "FAILED")

        time.sleep(0.1)

    logger.info(f"[worker-{worker_id}] finished")
    
    # Log scanner stats if available
    if scheduler:
        stats = scheduler.get_scan_stats()
        logger.info(f"[worker-{worker_id}] Scanner stats: {stats}")
