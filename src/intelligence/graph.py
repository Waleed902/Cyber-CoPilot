import networkx as nx
from typing import List
from .engine import Finding

class AttackGraph:
    """
    Topological representation of discovered environments and vulnerabilities.
    Nodes represent access boundaries/contexts (e.g. 'Public Web', 'DB Server').
    Edges represent transition payloads (Findings).
    """
    
    def __init__(self):
        self.graph = nx.DiGraph()
        
    def add_node(self, node_id: str, **attributes):
        """Add a strategic location or asset node to the graph."""
        self.graph.add_node(node_id, **attributes)
        
    def add_finding_edge(self, source_node: str, target_node: str, finding: Finding):
        """
        Record an edge mapping how one node compromises another via a Finding.
        """
        # Ensure nodes exist
        if not self.graph.has_node(source_node):
            self.add_node(source_node)
        if not self.graph.has_node(target_node):
            self.add_node(target_node)
            
        # Add directed finding edge
        self.graph.add_edge(source_node, target_node, finding=finding)
        
    def get_attack_paths(self, start_node: str, target_node: str) -> List[List[Finding]]:
        """
        Retrieve all chains of Findings required to reach the target from start.
        """
        if not self.graph.has_node(start_node) or not self.graph.has_node(target_node):
            return []
            
        try:
            # simple_paths returns generators of nodes like ["Internet", "Web", "DB"]
            nx_paths = list(nx.all_simple_paths(self.graph, start_node, target_node))
        except nx.NetworkXNoPath:
            return []
            
        finding_paths = []
        for nx_path in nx_paths:
            path_findings = []
            # Extract edge finding attributes sequentially
            for i in range(len(nx_path) - 1):
                u = nx_path[i]
                v = nx_path[i+1]
                edge_data = self.graph.get_edge_data(u, v)
                if 'finding' in edge_data:
                    path_findings.append(edge_data['finding'])
            finding_paths.append(path_findings)
            
        return finding_paths
