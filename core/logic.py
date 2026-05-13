from collections import defaultdict

WORKFLOW_HINTS = {
    "checkout": ["cart", "checkout", "payment", "order"],
    "profile": ["profile", "account", "settings"],
    "coupon": ["coupon", "promo", "discount"],
}

INVARIANTS = {
    "price_non_negative": {
        "description": "Price should never be negative",
        "check": lambda before, after: after.get("price", 0) >= 0
    },
    "single_use_token": {
        "description": "Token should not be reusable",
        "check": lambda first, second: first != second
    },
    "step_order_enforced": {
        "description": "Skipping steps should be rejected",
        "check": lambda status: status in (401, 403)
    }
}

def discover_workflows(recon_data):
    """
    Infer workflows by grouping endpoints by semantic hints.
    """
    workflows = defaultdict(list)
    endpoints = recon_data.get("endpoints", [])

    for ep in endpoints:
        low = ep.lower()
        for name, hints in WORKFLOW_HINTS.items():
            if any(h in low for h in hints):
                workflows[name].append(ep)

    # Keep only meaningful workflows (2+ steps)
    return {k: v for k, v in workflows.items() if len(v) >= 2}

def plan_logic_probes(workflows):
    """
    Build a minimal probe plan per workflow.
    """
    plans = []
    for name, steps in workflows.items():
        plans.append({
            "workflow": name,
            "steps": steps,
            "probes": ["skip_step", "replay_once"]
        })
    return plans
