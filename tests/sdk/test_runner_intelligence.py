"""
Phase 7: Tests for Runner Intelligence Integration.
Validates that:
1. The confidence estimator correctly marks a vector as low viability.
2. Runner supervisor adjudication can pivot instead of aborting automatically.
3. The syntax error counter correctly aborts after 3 consecutive tool errors.
"""
import asyncio
import pytest
from unittest.mock import MagicMock, patch
from src.sdk.runner import Conversation, Runner
from src.sdk.core import Agent, FunctionTool
from src.intelligence.scoring import ConfidenceEstimator
from src.intelligence.evaluator import FindingExtractor
from src.intelligence.engine import Finding, Severity, Confidence, IntelligenceBus


# ─── Unit: ConfidenceEstimator ────────────────────────────────────────────────

def test_confidence_viable_after_clean_result():
    est = ConfidenceEstimator()
    est.evaluate_outcome("some_tool", "200 OK – directory listing found", False)
    assert est.is_viable() is True


def test_confidence_drops_on_waf():
    est = ConfidenceEstimator()
    score = est.evaluate_outcome("curl_request", "403 Forbidden – blocked by WAF", False)
    assert score == 50
    assert est.is_viable() is True  # still above threshold of 30

    score = est.evaluate_outcome("curl_request", "403 Forbidden – blocked by WAF", False)
    assert score == 0
    assert est.is_viable() is False  # below threshold


def test_confidence_drops_on_no_results():
    est = ConfidenceEstimator()
    score = est.evaluate_outcome("nuclei", "0 vulnerabilities found", False)
    assert score == 60


def test_confidence_drops_on_error():
    est = ConfidenceEstimator()
    score = est.evaluate_outcome("tool", "some output", True)
    assert score == 95


def test_runner_detects_ctf_context_from_user_request():
    runner = Runner()
    assert runner._is_ctf_context(
        "Orchestrator",
        "solve this ctf challenge Host target 154.57.164.65:31009",
        "",
    )


def test_runner_detects_ctf_context_from_challenge_flag_prompt():
    runner = Runner()
    assert runner._is_ctf_context(
        "Orchestrator",
        "Challenge Scenario: restricted shell. Submit challenge Flag HTB{s0me_t3xt}",
        "",
    )


def test_runner_does_not_mark_plain_host_port_as_ctf():
    runner = Runner()
    assert not runner._is_ctf_context("ReconAgent", "scan 192.0.2.10:443 for TLS", "")


def test_supervisor_decision_normalization():
    runner = Runner()
    assert runner._normalize_supervisor_decision({"decision": "pivot"}) == "pivot_vector"
    assert runner._normalize_supervisor_decision({"decision": "abort"}) == "abort_current_test"
    assert runner._normalize_supervisor_decision({"status": "stuck"}) == "pivot_vector"
    assert runner._normalize_supervisor_decision({}, default="pivot_vector") == "pivot_vector"


def test_low_confidence_supervisor_pivot_does_not_cancel():
    runner = object.__new__(Runner)

    async def fake_supervisor_check(**kwargs):
        return {
            "status": "stuck",
            "decision": "pivot_vector",
            "decision_reason": "Repeated WAF blocks mean this exact vector is low yield.",
            "recommendation": "Try a different endpoint or summarize the blocked vector.",
            "efficiency_pct": 20,
            "risk_flags": ["low_confidence"],
        }

    runner._run_supervisor_check = fake_supervisor_check
    agent = MagicMock()
    agent.get_instructions.return_value = "system"
    conversation = Conversation(agent=agent)
    Runner.cancel_requested = False
    Runner.cancel_reason = None
    Runner.on_supervisor_check = None

    should_cancel, feedback = asyncio.run(
        runner._adjudicate_low_confidence(
            agent_name="WebSecAgent",
            target="example.test",
            iteration=10,
            max_iterations=80,
            tools_run=[("curl_request", False)],
            findings=[],
            last_thinking="Testing reflected XSS.",
            conversation=conversation,
            confidence_score=0,
        )
    )

    assert should_cancel is False
    assert Runner.cancel_requested is False
    assert "[SUPERVISOR LOW-CONFIDENCE REVIEW]" in feedback
    assert "pivot_vector" in feedback


# ─── Unit: FindingExtractor (mocked LLM) ──────────────────────────────────────

def test_finding_extractor_parses_llm_json():
    import json
    mock_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = json.dumps({
        "findings": [{
            "severity": "CRITICAL",
            "confidence": "FIRM",
            "description": "SQL injection via error message",
            "evidence": "You have an error in your SQL syntax",
            "remediation_hints": "Use parameterized queries"
        }]
    })
    mock_client.chat.completions.create.return_value = MagicMock(choices=[mock_choice])

    extractor = FindingExtractor(client=mock_client, model="stub")
    findings = extractor.extract_findings("sqlmap", "Error: SQL syntax near '''")

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].confidence == Confidence.FIRM
    assert findings[0].tool == "sqlmap"


def test_finding_extractor_handles_empty_json():
    import json
    mock_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = json.dumps({"findings": []})
    mock_client.chat.completions.create.return_value = MagicMock(choices=[mock_choice])

    extractor = FindingExtractor(client=mock_client, model="stub")
    findings = extractor.extract_findings("nmap", "No open ports found")
    assert findings == []


# ─── Unit: IntelligenceBus ────────────────────────────────────────────────────

def test_intelligence_bus_registers_and_sorts():
    bus = IntelligenceBus()
    bus.register_finding(Finding("tool_a", "Low issue", Severity.LOW, Confidence.TENTATIVE, "evidence"))
    bus.register_finding(Finding("tool_b", "Critical issue", Severity.CRITICAL, Confidence.CERTAIN, "evidence"))

    prioritized = bus.get_prioritized_findings()
    assert prioritized[0].severity == Severity.CRITICAL
    assert prioritized[1].severity == Severity.LOW
