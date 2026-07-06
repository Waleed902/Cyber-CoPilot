import pytest
from src.intelligence.scoring import ConfidenceEstimator

def test_confidence_estimator_ok():
    estimator = ConfidenceEstimator()
    assert estimator.is_viable() is True
    
    score = estimator.evaluate_outcome("curl_request", "OK: 200 list of users", False)
    assert score == 100
    assert estimator.is_viable() is True

def test_confidence_estimator_waf_block():
    estimator = ConfidenceEstimator()
    score = estimator.evaluate_outcome("sqlmap", "Connection blocked by WAF", False)
    # WAF penalty is 50
    assert score == 50
    assert estimator.is_viable() is True
    
    score = estimator.evaluate_outcome("sqlmap", "403 Forbidden", False)
    # Another penalty is 50, score is 0
    assert score == 0
    assert estimator.is_viable() is False

def test_confidence_estimator_not_vulnerable():
    estimator = ConfidenceEstimator()
    score = estimator.evaluate_outcome("nuclei", "0 vulnerabilities found", False)
    # penalty 40
    assert score == 60
    assert estimator.is_viable() is True

def test_confidence_estimator_errors():
    estimator = ConfidenceEstimator()
    score = estimator.evaluate_outcome("tool", "JSON Decode Error", True)
    assert score == 95

def test_confidence_estimator_rewards():
    estimator = ConfidenceEstimator()
    # Apply penalty first to drop score below 100
    score = estimator.evaluate_outcome("nuclei", "0 vulnerabilities found", False)
    assert score == 60
    
    # Success outcome (+5)
    score = estimator.evaluate_outcome("tool", "Success response", False)
    assert score == 65
    
    # Positive indicator (+20)
    score = estimator.evaluate_outcome("tool", "Vulnerability found: CVE-2024-1234", False)
    assert score == 85
    
    # Positive indicator capping at 100
    score = estimator.evaluate_outcome("tool", "Exploit successful!", False)
    assert score == 100

