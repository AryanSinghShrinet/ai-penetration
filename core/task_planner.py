from core.task_queue import enqueue, reset_found_vulns, save_queue
from core.worker import reset_worker_cache

def plan_tasks(target, payload_plan, endpoints=None, mode="endpoint"):
    """
    Plan tasks for execution.
    
    Args:
        target: The main target URL (used as fallback)
        payload_plan: Dict of vuln_type -> list of payloads
        endpoints: List of discovered endpoints to test (optional)
                   If None, only tests the main target
        mode: Testing mode (endpoint, parameter, etc.)
    
    Returns:
        Number of tasks planned
    """
    # Reset found vulns tracking for new scan
    reset_found_vulns()
    reset_worker_cache()
    
    # Clear existing queue
    save_queue([])
    
    tasks = []
    
    # Use discovered endpoints if available, otherwise just the main target
    targets_to_test = endpoints if endpoints else [target]
    
    # For each endpoint, test each vulnerability type
    for endpoint in targets_to_test:
        for vuln, payloads in payload_plan.items():
            for payload in payloads:
                tasks.append({
                    "target": endpoint,  # Use specific endpoint, not root target
                    "vuln": vuln,
                    "payload": payload,
                    "worker_id": None
                })

    for t in tasks:
        enqueue(t)

    return len(tasks)
