import pytest
from src.intelligence.engine import Finding, Severity, Confidence
from src.intelligence.graph import AttackGraph

def test_attack_graph_paths():
    """Test building a topological graph and retrieving finding paths."""
    graph = AttackGraph()
    
    graph.add_node("Internet", type="Public")
    graph.add_node("Web Server", type="Internal")
    graph.add_node("AWS Account", type="Cloud")
    
    # Simulate discovering a web server from the internet
    f_nmap = Finding(
        tool="nmap",
        description="Found open port 80",
        severity=Severity.INFO,
        confidence=Confidence.CERTAIN,
        evidence="Port 80/tcp open"
    )
    graph.add_finding_edge("Internet", "Web Server", f_nmap)
    
    # Simulate finding SSRF on Web Server to hit AWS Metadata
    f_ssrf = Finding(
        tool="ssrf_scanner",
        description="Fetched EC2 Metadata",
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        evidence="ami-12345"
    )
    graph.add_finding_edge("Web Server", "AWS Account", f_ssrf)
    
    # Request paths from Internet to AWS Account
    paths = graph.get_attack_paths("Internet", "AWS Account")
    
    assert len(paths) == 1
    path = paths[0]
    
    # Path should contain the sequence of edges (Findings)
    assert len(path) == 2
    assert path[0].tool == "nmap"
    assert path[1].tool == "ssrf_scanner"
    assert path[1].severity == Severity.HIGH

def test_attack_graph_no_path():
    """Test retrieving paths when none exist."""
    graph = AttackGraph()
    graph.add_node("A")
    graph.add_node("B")
    
    paths = graph.get_attack_paths("A", "B")
    assert len(paths) == 0
