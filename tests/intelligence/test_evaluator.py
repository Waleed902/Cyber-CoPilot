from unittest.mock import MagicMock
import pytest
from src.intelligence.evaluator import FindingExtractor
from src.intelligence.engine import Severity, Confidence
import json

def test_extract_findings():
    # Mock LLM Client
    mock_client = MagicMock()
    mock_response = MagicMock()
    
    mock_message = MagicMock()
    mock_message.content = json.dumps({
        "findings": [
            {
                "severity": "CRITICAL",
                "confidence": "FIRM",
                "description": "SQL Injection found via error message",
                "evidence": "You have an error in your SQL syntax",
                "remediation_hints": "Use parameterized queries"
            }
        ]
    })
    
    # Set up the choices
    mock_choice = MagicMock()
    mock_choice.message = mock_message
    mock_response.choices = [mock_choice]
    
    mock_client.chat.completions.create.return_value = mock_response
    
    extractor = FindingExtractor(client=mock_client, model="stub-model")
    
    tool_output = "Response: HTTP 500. Error: You have an error in your SQL syntax near '''."
    findings = extractor.extract_findings("curl_request", tool_output)
    
    assert len(findings) == 1
    assert findings[0].tool == "curl_request"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].confidence == Confidence.FIRM
    assert findings[0].description == "SQL Injection found via error message"
    assert "syntax" in findings[0].evidence
