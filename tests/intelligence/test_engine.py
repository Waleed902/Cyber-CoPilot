import pytest
from src.intelligence.engine import Severity, Confidence, Finding, IntelligenceBus

def test_finding_scoring():
    f1 = Finding(
        tool="sqli_scanner",
        description="Blind SQLi",
        severity=Severity.HIGH,
        confidence=Confidence.FIRM,
        evidence="Sleep completed in 5s"
    )
    
    # threat_score should be severity(3) * 10 + confidence(2) = 32
    assert f1.threat_score == 32
    
    f2 = Finding(
        tool="xss_scanner",
        description="Reflected XSS",
        severity=Severity.MEDIUM,
        confidence=Confidence.CERTAIN,
        evidence="Found payload"
    )
    
    # threat_score should be severity(2) * 10 + confidence(3) = 23
    assert f2.threat_score == 23

    bus = IntelligenceBus()
    bus.register_finding(f2)
    bus.register_finding(f1)
    
    prioritized = bus.get_prioritized_findings()
    assert len(prioritized) == 2
    # f1 outranks f2
    assert prioritized[0].tool == "sqli_scanner"

def test_filter_findings():
    bus = IntelligenceBus()
    bus.register_finding(Finding("nmap", "Open ports", Severity.INFO, Confidence.CERTAIN, ""))
    bus.register_finding(Finding("sqli_scanner", "SQLi", Severity.CRITICAL, Confidence.CERTAIN, ""))
    
    # Filter by tool
    nmap_results = bus.filter_findings(tool="nmap")
    assert len(nmap_results) == 1
    assert nmap_results[0].tool == "nmap"
    
    # Filter by minimum severity
    high_threats = bus.filter_findings(min_severity=Severity.HIGH)
    assert len(high_threats) == 1
    assert high_threats[0].severity == Severity.CRITICAL
