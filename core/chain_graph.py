class AttackNode:
    def __init__(self, vuln, endpoint, evidence):
        self.vuln = vuln
        self.endpoint = endpoint
        self.evidence = evidence

class AttackEdge:
    def __init__(self, src, dst, reason):
        self.src = src
        self.dst = dst
        self.reason = reason

class AttackGraph:
    def __init__(self):
        self.nodes = []
        self.edges = []

    def add_node(self, node):
        self.nodes.append(node)

    def add_edge(self, src, dst, reason):
        self.edges.append(AttackEdge(src, dst, reason))

    def serialize(self):
        return {
            "nodes": [
                {
                    "vuln": n.vuln,
                    "endpoint": n.endpoint
                } for n in self.nodes
            ],
            "edges": [
                {
                    "from": e.src.vuln,
                    "to": e.dst.vuln,
                    "reason": e.reason
                } for e in self.edges
            ]
        }
