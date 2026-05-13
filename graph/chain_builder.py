"""
Enhanced Attack Graph + Chain Builder
========================================
Graph-based vulnerability chaining system.

UPGRADE from old chain_graph.py which only had nodes/edges with no algorithms.

Now includes:
  1. Proper directed graph with typed edges
  2. Shortest path algorithms (BFS for minimum-step chains)
  3. Critical path analysis (highest-impact chains)
  4. Automatic chain inference from vulnerability co-occurrence
  5. CVSS-weighted path scoring
  6. Visual export (DOT format for Graphviz, JSON for web UI)
"""

import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Set, Tuple
from enum import Enum


# ---------------------------------------------------------------------------
# Graph Node and Edge Types
# ---------------------------------------------------------------------------

class NodeType(Enum):
    ENDPOINT    = "endpoint"
    CREDENTIAL  = "credential"
    TOKEN       = "token"
    VULNERABILITY = "vulnerability"
    DATA        = "data"
    PERMISSION  = "permission"


class EdgeType(Enum):
    ENABLES     = "enables"       # Vuln A enables access for Vuln B
    EXPOSES     = "exposes"       # Endpoint exposes credential/data
    REQUIRES    = "requires"      # Attack requires this prerequisite
    BYPASSES    = "bypasses"      # Authentication bypass
    ESCALATES   = "escalates"     # Privilege escalation
    EXFILTRATES = "exfiltrates"   # Data exfiltration link


@dataclass
class GraphNode:
    """A node in the attack graph."""
    node_id: str
    node_type: NodeType
    label: str
    endpoint: str = ""
    vuln_type: str = ""
    impact_score: float = 0.0
    confidence: float = 1.0
    evidence: Dict = field(default_factory=dict)
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["node_type"] = self.node_type.value
        return d


@dataclass
class GraphEdge:
    """A directed edge in the attack graph."""
    edge_id: str
    from_node: str
    to_node: str
    edge_type: EdgeType
    weight: float = 1.0       # Lower = easier/more likely
    description: str = ""

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["edge_type"] = self.edge_type.value
        return d


# ---------------------------------------------------------------------------
# Chain Inference Rules
# ---------------------------------------------------------------------------

# Rules: (vuln_a, vuln_b) → edge_type, chain_description, impact_bonus
CHAIN_INFERENCE_RULES = [
    # Authentication chains
    ("xss",            "csrf",          EdgeType.ENABLES,    "XSS used to steal CSRF token → CSRF attack", 1.5),
    ("xss",            "account_takeover", EdgeType.ENABLES, "XSS to steal session cookie → ATO", 2.0),
    ("open_redirect",  "xss",           EdgeType.ENABLES,    "Open redirect to trusted XSS payload", 1.3),
    ("open_redirect",  "phishing",      EdgeType.ENABLES,    "Trusted domain redirect for phishing", 1.2),

    # Injection chains
    ("sqli",           "lfi",           EdgeType.ENABLES,    "SQLi INTO OUTFILE → LFI to execute = RCE", 2.5),
    ("sqli",           "auth_bypass",   EdgeType.BYPASSES,   "SQLi to bypass login authentication", 2.0),
    ("ssrf",           "rce",           EdgeType.ENABLES,    "SSRF to internal metadata → credentials → RCE", 2.5),
    ("ssrf",           "idor",          EdgeType.ENABLES,    "SSRF to access internal APIs with IDOR", 1.8),

    # IDOR chains
    ("idor",           "xss",           EdgeType.ENABLES,    "IDOR to read stored XSS from other user", 1.4),
    ("idor",           "file_upload",   EdgeType.ENABLES,    "IDOR to upload files as another user = RCE", 2.0),
    ("idor",           "account_takeover", EdgeType.ESCALATES, "IDOR on password/email field = ATO", 2.2),

    # CORS chains
    ("cors",           "xss",           EdgeType.ENABLES,    "CORS misconfiguration amplifies XSS impact", 1.6),
    ("cors",           "credential_theft", EdgeType.EXFILTRATES, "CORS allows cross-origin credential theft", 1.8),

    # File operation chains
    ("file_upload",    "rce",           EdgeType.ENABLES,    "Arbitrary file upload → Remote code execution", 2.5),
    ("lfi",            "rce",           EdgeType.ENABLES,    "LFI with PHP wrapper → RCE", 2.3),
    ("path_traversal", "lfi",           EdgeType.ENABLES,    "Path traversal to LFI", 1.5),

    # Logic chains
    ("auth_bypass",    "idor",          EdgeType.ENABLES,    "Auth bypass grants access to admin IDOR", 2.0),
    ("auth_bypass",    "sqli",          EdgeType.ENABLES,    "Auth bypass to authenticated SQLi endpoint", 1.8),
]


# ---------------------------------------------------------------------------
# Attack Path
# ---------------------------------------------------------------------------

@dataclass
class AttackPath:
    """A discovered attack chain from source to high-impact target."""
    path_id: str
    nodes: List[str]
    edges: List[str]
    total_weight: float
    total_impact: float
    chain_description: str
    steps: List[str]
    final_impact: str

    def to_dict(self) -> Dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Main Attack Graph
# ---------------------------------------------------------------------------

class AttackGraph:
    """
    Directed attack graph for vulnerability chaining.

    Uses BFS for shortest paths and Dijkstra-style for highest-impact paths.
    """

    def __init__(self):
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[str, GraphEdge] = {}
        self._adjacency: Dict[str, List[str]] = defaultdict(list)  # node_id → [edge_ids]
        self._reverse_adjacency: Dict[str, List[str]] = defaultdict(list)

    # -------------------------------------------------------------------------
    # Graph construction
    # -------------------------------------------------------------------------

    def add_node(self, node: GraphNode) -> None:
        """Add a node to the graph."""
        self._nodes[node.node_id] = node

    def add_vulnerability(
        self,
        vuln_type: str,
        endpoint: str,
        impact_score: float = 5.0,
        confidence: float = 0.8,
        evidence: Optional[Dict] = None,
    ) -> str:
        """Convenience method to add a vulnerability node."""
        node_id = f"vuln_{vuln_type}_{hash(endpoint) % 10000}"
        node = GraphNode(
            node_id=node_id,
            node_type=NodeType.VULNERABILITY,
            label=f"{vuln_type.upper()} @ {endpoint}",
            endpoint=endpoint,
            vuln_type=vuln_type,
            impact_score=impact_score,
            confidence=confidence,
            evidence=evidence or {},
        )
        self.add_node(node)
        return node_id

    def add_edge(self, edge: GraphEdge) -> None:
        """Add a directed edge to the graph."""
        self._edges[edge.edge_id] = edge
        self._adjacency[edge.from_node].append(edge.edge_id)
        self._reverse_adjacency[edge.to_node].append(edge.edge_id)

    def connect(
        self,
        from_node_id: str,
        to_node_id: str,
        edge_type: EdgeType,
        weight: float = 1.0,
        description: str = "",
    ) -> str:
        """Create an edge between two nodes."""
        edge_id = f"edge_{from_node_id}_{to_node_id}"
        edge = GraphEdge(
            edge_id=edge_id,
            from_node=from_node_id,
            to_node=to_node_id,
            edge_type=edge_type,
            weight=weight,
            description=description,
        )
        self.add_edge(edge)
        return edge_id

    # -------------------------------------------------------------------------
    # Automatic chain inference
    # -------------------------------------------------------------------------

    def infer_chains(self, logger=None) -> int:
        """
        Automatically infer edges between vulnerabilities based on known patterns.
        Returns number of new edges created.
        """
        new_edges = 0

        # Get all vulnerability nodes grouped by type
        vuln_nodes_by_type: Dict[str, List[str]] = defaultdict(list)
        for node_id, node in self._nodes.items():
            if node.node_type == NodeType.VULNERABILITY:
                vuln_nodes_by_type[node.vuln_type].append(node_id)

        # Apply inference rules
        for vuln_a, vuln_b, edge_type, description, impact_mult in CHAIN_INFERENCE_RULES:
            nodes_a = vuln_nodes_by_type.get(vuln_a, [])
            nodes_b = vuln_nodes_by_type.get(vuln_b, [])

            for node_a_id in nodes_a:
                for node_b_id in nodes_b:
                    edge_id = f"inferred_{node_a_id}_{node_b_id}"
                    if edge_id not in self._edges:
                        edge = GraphEdge(
                            edge_id=edge_id,
                            from_node=node_a_id,
                            to_node=node_b_id,
                            edge_type=edge_type,
                            weight=1.0 / impact_mult,  # Lower weight = higher priority
                            description=description,
                        )
                        self.add_edge(edge)
                        new_edges += 1

        if logger:
            logger.info(f"[graph] Inferred {new_edges} new attack chain edges")

        return new_edges

    # -------------------------------------------------------------------------
    # Path finding algorithms
    # -------------------------------------------------------------------------

    def bfs_shortest_path(self, from_node_id: str, to_node_id: str) -> Optional[List[str]]:
        """
        BFS to find shortest path (minimum steps) between two nodes.
        Returns list of node IDs or None if no path.
        """
        if from_node_id not in self._nodes or to_node_id not in self._nodes:
            return None

        visited = {from_node_id}
        queue = deque([[from_node_id]])

        while queue:
            path = queue.popleft()
            current = path[-1]

            if current == to_node_id:
                return path

            for edge_id in self._adjacency.get(current, []):
                edge = self._edges[edge_id]
                next_node = edge.to_node
                if next_node not in visited:
                    visited.add(next_node)
                    queue.append(path + [next_node])

        return None

    def find_high_impact_paths(
        self,
        min_chain_length: int = 2,
        max_chain_length: int = 5,
        min_impact: float = 5.0,
    ) -> List[AttackPath]:
        """
        Find all high-impact attack paths in the graph.

        Uses modified DFS with pruning for impact threshold.
        Returns paths sorted by total impact score.
        """
        paths = []

        def dfs(node_id: str, current_path: List[str], visited: Set[str], depth: int):
            if depth > max_chain_length:
                return

            current_node = self._nodes.get(node_id)
            if not current_node:
                return

            # Record path if it meets minimum requirements
            if len(current_path) >= min_chain_length:
                total_impact = sum(
                    self._nodes[n].impact_score
                    for n in current_path
                    if n in self._nodes
                )
                if total_impact >= min_impact:
                    path_edges = []
                    for i in range(len(current_path) - 1):
                        edge_id = f"inferred_{current_path[i]}_{current_path[i+1]}"
                        if edge_id in self._edges:
                            path_edges.append(edge_id)

                    # Generate chain description
                    vuln_sequence = [
                        self._nodes[n].vuln_type
                        for n in current_path
                        if self._nodes.get(n) and self._nodes[n].node_type == NodeType.VULNERABILITY
                    ]
                    steps = [
                        self._edges.get(f"inferred_{current_path[i]}_{current_path[i+1]}", None)
                        for i in range(len(current_path) - 1)
                    ]
                    step_descriptions = [
                        e.description for e in steps if e is not None
                    ]

                    attack_path = AttackPath(
                        path_id=f"path_{hash(tuple(current_path)) % 100000}",
                        nodes=list(current_path),
                        edges=path_edges,
                        total_weight=sum(
                            self._edges.get(e, GraphEdge("", "", "", EdgeType.ENABLES, weight=1)).weight
                            for e in path_edges
                        ),
                        total_impact=total_impact,
                        chain_description=" → ".join(
                            v.upper() for v in vuln_sequence
                        ),
                        steps=step_descriptions,
                        final_impact=self._infer_final_impact(vuln_sequence),
                    )
                    paths.append(attack_path)

            # Continue DFS
            for edge_id in self._adjacency.get(node_id, []):
                edge = self._edges[edge_id]
                next_node = edge.to_node
                if next_node not in visited:
                    visited.add(next_node)
                    dfs(next_node, current_path + [next_node], visited, depth + 1)
                    visited.discard(next_node)

        # Start DFS from each vulnerability node
        for node_id, node in self._nodes.items():
            if node.node_type == NodeType.VULNERABILITY:
                dfs(node_id, [node_id], {node_id}, 1)

        # Sort by impact (highest first), deduplicate
        seen_chains = set()
        unique_paths = []
        for path in sorted(paths, key=lambda p: p.total_impact, reverse=True):
            chain_key = path.chain_description
            if chain_key not in seen_chains:
                seen_chains.add(chain_key)
                unique_paths.append(path)

        return unique_paths[:20]  # Return top 20 chains

    def _infer_final_impact(self, vuln_sequence: List[str]) -> str:
        """Infer the final impact of a vulnerability chain."""
        high_impact = {
            "rce": "Remote Code Execution",
            "account_takeover": "Account Takeover",
            "sqli": "Database Compromise",
            "ssrf": "Internal Network Access",
            "file_upload": "Remote Code Execution via File Upload",
            "auth_bypass": "Authentication Bypass",
        }
        for vuln in reversed(vuln_sequence):
            if vuln in high_impact:
                return high_impact[vuln]
        return "Data Exfiltration / Information Disclosure"

    # -------------------------------------------------------------------------
    # Serialization
    # -------------------------------------------------------------------------

    def to_dict(self) -> Dict:
        """Export graph as dictionary for JSON serialization."""
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges.values()],
            "stats": {
                "node_count": len(self._nodes),
                "edge_count": len(self._edges),
                "vulnerability_nodes": sum(
                    1 for n in self._nodes.values()
                    if n.node_type == NodeType.VULNERABILITY
                ),
            }
        }

    def to_dot(self) -> str:
        """Export as DOT format for Graphviz visualization."""
        lines = ["digraph AttackGraph {", '  rankdir=LR;', '  node [shape=box];']

        # Node colors by type
        colors = {
            NodeType.VULNERABILITY: "red",
            NodeType.ENDPOINT: "lightblue",
            NodeType.CREDENTIAL: "orange",
            NodeType.TOKEN: "yellow",
            NodeType.DATA: "lightgreen",
        }

        for node in self._nodes.values():
            color = colors.get(node.node_type, "white")
            label = node.label.replace('"', '\\"')
            lines.append(f'  "{node.node_id}" [label="{label}" fillcolor={color} style=filled];')

        for edge in self._edges.values():
            lines.append(
                f'  "{edge.from_node}" -> "{edge.to_node}" [label="{edge.edge_type.value}"];'
            )

        lines.append("}")
        return "\n".join(lines)

    def serialize(self) -> Dict:
        """Legacy-compatible serialize method."""
        return self.to_dict()


def build_attack_graph(findings: List[Dict], logger=None) -> AttackGraph:
    """
    Build an attack graph from a list of confirmed findings.

    Args:
        findings: List of {vuln_type, endpoint, impact_score, confidence, evidence}
    """
    graph = AttackGraph()

    for finding in findings:
        graph.add_vulnerability(
            vuln_type=finding.get("vuln_type", "unknown"),
            endpoint=finding.get("endpoint", ""),
            impact_score=finding.get("impact_score", 5.0),
            confidence=finding.get("confidence", 0.8),
            evidence=finding.get("evidence", {}),
        )

    # Auto-infer chains based on co-occurring vulnerabilities
    new_edges = graph.infer_chains(logger=logger)

    if logger:
        logger.info(
            f"[graph] Attack graph: {len(graph._nodes)} nodes, "
            f"{len(graph._edges)} edges ({new_edges} inferred)"
        )

    return graph
