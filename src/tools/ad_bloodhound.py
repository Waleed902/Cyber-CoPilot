"""
Active Directory BloodHound Integrator

Allows the framework to query BloodHound/Neo4j for attack paths, enabling
autonomous Pass-the-Hash, Kerberoasting, and lateral movement.
"""

import json
from typing import Dict, List, Optional
from loguru import logger
from src.sdk.tool import function_tool

try:
    from neo4j import GraphDatabase
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False

class BloodHoundClient:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="password"):
        self.uri = uri
        self.user = user
        self.password = password
        self.driver = None
        self._connect()

    def _connect(self):
        if not HAS_NEO4J:
            logger.error("neo4j library not installed.")
            return
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
        except Exception as e:
            logger.error(f"Failed to connect to BloodHound/Neo4j: {e}")
            self.driver = None

    def close(self):
        if self.driver:
            self.driver.close()

    def query(self, cypher: str) -> List[Dict]:
        if not self.driver:
            return [{"error": "Not connected to BloodHound"}]
        
        try:
            with self.driver.session() as session:
                result = session.run(cypher)
                return [dict(record) for record in result]
        except Exception as e:
            return [{"error": str(e)}]


@function_tool()
def get_shortest_path_to_domain_admin(start_node: str, domain: str) -> str:
    """
    Query BloodHound for the shortest attack path from a compromised user/computer to Domain Admin.
    
    Args:
        start_node: The starting user or computer (e.g. 'USER@DOMAIN.LOCAL')
        domain: The target domain (e.g. 'DOMAIN.LOCAL')
        
    Returns:
        A list of attack steps (edges and nodes) leading to DA.
    """
    client = BloodHoundClient()
    if not client.driver:
        return "Error: Could not connect to BloodHound backend. Ensure neo4j is running."
        
    # Standard BloodHound cypher query for shortest path to DA
    cypher = f"""
    MATCH (n {{name: '{start_node.upper()}'}}), 
          (g:Group),
          p=shortestPath((n)-[*1..]->(g))
    WHERE g.objectid ENDS WITH '-512' OR g.name STARTS WITH 'DOMAIN ADMINS'
    RETURN p
    """
    
    results = client.query(cypher)
    client.close()
    
    if not results or "error" in results[0]:
        err = results[0].get("error", "No path found.") if results else "No path found."
        return f"No path to Domain Admin found from {start_node}. Details: {err}"
        
    path = results[0].get('p')
    if not path:
        return "Path found, but could not parse Neo4j node data."
        
    steps = ["## Attack Path to Domain Admin\n"]
    # Simplistic parsing of Neo4j path object for the LLM
    for i, node in enumerate(path.nodes):
        name = node.get('name', 'Unknown')
        node_type = list(node.labels)[0] if node.labels else 'Unknown'
        steps.append(f"{i+1}. {node_type}: {name}")
        
    steps.append("\n**Action Plan**: Review the steps above. If you see 'HasSession', use lateral movement tools (crackmapexec). If you see 'MemberOf', no further action is needed for that hop. If you see 'GenericAll', attempt password reset or kerberoasting.")
    return "\n".join(steps)

@function_tool()
def query_bloodhound_custom(cypher_query: str) -> str:
    """
    Execute a custom Cypher query against the BloodHound Neo4j database to find specific misconfigurations.
    
    Args:
        cypher_query: The exact Cypher query string
        
    Returns:
        JSON representation of the query results.
    """
    client = BloodHoundClient()
    results = client.query(cypher_query)
    client.close()
    
    # Trim results if they are too large
    output = json.dumps(results, indent=2)
    if len(output) > 5000:
        return output[:5000] + "\n... [Truncated due to size limits]"
    return output
