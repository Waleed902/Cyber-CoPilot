from src.sdk.finding_lifecycle import FindingLifecycle
from src.sdk.http_knowledge import HttpKnowledgeBase


def test_http_knowledge_suggests_targeted_tests(tmp_path):
    kb = HttpKnowledgeBase(storage_path=str(tmp_path / "http.json"))

    kb.record(
        target="example.com",
        url="https://api.example.com/api/v1/users/123?format=json",
        method="GET",
        status_code=200,
        source_tool="curl_request",
    )
    kb.record(
        target="example.com",
        url="https://example.com/fetch?url=https%3A%2F%2Fexample.org",
        method="GET",
        status_code=200,
    )

    suggestions = kb.suggest_tests("example.com")

    assert any(item["kind"] == "idor" for item in suggestions)
    assert any(item["kind"] == "redirect_ssrf" for item in suggestions)
    assert kb.summary("example.com")["endpoints"] == 2


def test_finding_lifecycle_requires_report_quality_evidence(tmp_path):
    lifecycle = FindingLifecycle(storage_path=str(tmp_path / "findings.json"))
    candidate = lifecycle.add_candidate(
        title="IDOR in user API",
        target="example.com",
        severity="high",
        endpoint="/api/v1/users/123",
        parameter="id",
        category="idor",
        evidence="Scanner said possible IDOR",
    )

    ok, message, finding = lifecycle.promote(candidate.fingerprint, evidence="Looks exploitable")

    assert not ok
    assert "below reportable threshold" in message
    assert finding.status == "candidate"

    proof = """
GET /api/v1/users/123 HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
{"id":123,"email":"victim@example.com"}

Negative control: GET /api/v1/users/999 returned HTTP/1.1 403 Forbidden.
Validated with response diff and confirmed unauthorized data exposure.
PoC proof shows observable impact.
"""
    ok, message, finding = lifecycle.promote(
        candidate.fingerprint,
        evidence=proof,
        validation_notes="Compared authorized and unauthorized object IDs.",
        impact="An authenticated user can read another user's profile.",
    )

    assert ok
    assert finding.reportable
    assert lifecycle.reportable("example.com")[0].fingerprint == candidate.fingerprint


def test_finding_lifecycle_builds_chain_opportunities(tmp_path):
    lifecycle = FindingLifecycle(storage_path=str(tmp_path / "findings.json"))
    f1 = lifecycle.add_candidate("Open redirect in OAuth callback", "example.com", "medium", category="open redirect")
    f2 = lifecycle.add_candidate("OAuth flow accepts weak state", "example.com", "high", category="oauth")
    proof = "GET /x HTTP/1.1\nHTTP/1.1 200 OK\nConfirmed PoC proof with negative control and response diff."

    lifecycle.promote(f1.fingerprint, proof)
    lifecycle.promote(f2.fingerprint, proof)

    chains = lifecycle.chain_opportunities("example.com")

    assert chains
    assert "OAuth" in chains[0]["rationale"]
