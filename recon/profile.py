import json

class ReconProfile:
    """
    Canonical Reconnaissance Profile.
    Centralizes all intelligence gathered about the target.
    """
    def __init__(self, target):
        self.target = target
        
        # Core Assets
        self.endpoints = []      # List of URLs
        self.server = ""         # Server header
        self.technologies = []   # List of strings
        self.parameters = []     # List of params
        
        # Structures
        self.forms = []          # List of dicts
        self.headers = {}        # Dict
        self.cookies = []        # List of strings
        
        # Advanced Intelligence (Layers 3-6)
        self.entities = {}       # Entity graph (entity -> params)
        self.workflows = {}      # Workflow graph (nodes, edges)
        self.trust_boundaries = [] # List of trust issues
        self.risk_scores = []    # List of ranked targets (dict)
        self.hypotheses = []     # List of potential vulnerabilities inferred
        
        # Metrics
        self.status_code = None
        self.content_type = ""
        self.comments = []
        self.hidden_elements = []

    def to_dict(self):
        """Convert profile to dictionary for serialization/logging"""
        return {
            "target": self.target,
            "status_code": self.status_code,
            "server": self.server,
            "technologies": self.technologies,
            "endpoints": self.endpoints,
            "parameters": self.parameters,
            "forms": self.forms,
            "entities": self.entities,
            "workflows": self.workflows,
            "trust_boundaries": self.trust_boundaries,
            "risk_scores": self.risk_scores,
            "hypotheses": self.hypotheses
        }

    def __getitem__(self, key):
        """Backward compatibility for dict-style access (recon_data['key'])"""
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(f"ReconProfile has no attribute '{key}'")

    def __setitem__(self, key, value):
        """Backward compatibility for dict-style assignment"""
        setattr(self, key, value)

    def get(self, key, default=None):
        """Dict-like get method"""
        if hasattr(self, key):
            val = getattr(self, key)
            return val if val is not None else default
        return default

    def add_hypothesis(self, vuln_type, confidence, evidence):
        self.hypotheses.append({
            "type": vuln_type,
            "confidence": confidence,
            "evidence": evidence
        })
