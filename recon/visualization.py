import json
import os

def export_profile_graphs(profile, report_dir):
    """
    Export Recon Graphs for Visualization.
    """
    os.makedirs(report_dir, exist_ok=True)
    
    # 1. Entity Graph
    entity_graph = profile.entities
    if entity_graph:
        with open(f"{report_dir}/entity_graph.json", "w") as f:
            json.dump(entity_graph, f, indent=2)
            
    # 2. Workflow Graph
    workflow_graph = profile.workflows
    if workflow_graph:
        with open(f"{report_dir}/workflow_graph.json", "w") as f:
            json.dump(workflow_graph, f, indent=2)
            
    # 3. Trust Map
    trust_map = profile.trust_boundaries
    if trust_map:
        with open(f"{report_dir}/trust_map.json", "w") as f:
            json.dump(trust_map, f, indent=2)
