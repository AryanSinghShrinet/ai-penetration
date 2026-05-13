import re

def build_graphs(recon_data, logger):
    """
    Layer 3 & 4: Relationship & Workflow Graph
    Infers entity ownership and workflow states.
    """
    logger.info("  [3/6] Building Entity & Workflow Graphs...")
    
    entity_graph = {}
    workflow_graph = {
        "nodes": [],
        "edges": []
    }

    # 1. Entity Inference (Regex on parameters)
    # matching things like 'user_id', 'order_id'
    id_pattern = re.compile(r"([a-z_]+)_id")
    
    for param in recon_data.get("parameters", []):
        match = id_pattern.match(param)
        if match:
            entity = match.group(1)
            if entity not in entity_graph:
                entity_graph[entity] = []
            entity_graph[entity].append(param)

    # 2. Workflow Inference (Basic Path Analysis)
    # If we have endpoints /register, /login, /cart - infer flow
    endpoints = recon_data.get("endpoints", [])
    
    # Simple keyword mapping
    steps = ["register", "verify", "login", "profile", "cart", "checkout", "pay"]
    
    found_steps = []
    for step in steps:
        for url in endpoints:
            if step in url:
                found_steps.append(step)
                workflow_graph["nodes"].append(step)
    
    # Create simple linear edges for found steps
    # This is a heuristic, distinct from real crawling
    found_steps = list(set(found_steps))
    found_steps.sort(key=lambda s: steps.index(s)) # sort by logical order
    
    for i in range(len(found_steps) - 1):
        workflow_graph["edges"].append({
            "from": found_steps[i],
            "to": found_steps[i+1],
            "type": "inferred_flow"
        })

    return entity_graph, workflow_graph
