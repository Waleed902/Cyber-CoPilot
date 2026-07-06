import pytest

from src.sdk.finding_lifecycle import FindingLifecycle
from src.tools.appsec import orchestrator
from src.tools.appsec.orchestrator import (
    full_appsec_scan,
    validate_browser_xss,
    validate_oast_ssrf,
)


@pytest.fixture()
def isolated_lifecycle(tmp_path, mocker):
    lifecycle = FindingLifecycle(storage_path=str(tmp_path / "findings.json"))
    mocker.patch.object(orchestrator, "get_finding_lifecycle", return_value=lifecycle)
    orchestrator._appsec_scanned_urls.clear()
    return lifecycle


@pytest.mark.asyncio
async def test_full_appsec_scan_registers_structured_candidates(mocker, isolated_lifecycle):
    from src.tools.appsec.sqli import sqli_scanner
    from src.tools.appsec.xss import xss_scanner

    mocker.patch.object(
        xss_scanner,
        "invoke",
        new=mocker.AsyncMock(return_value="VULNERABLE: reflected XSS in q"),
    )
    mocker.patch.object(
        sqli_scanner,
        "invoke",
        new=mocker.AsyncMock(return_value="ERROR-BASED: SQL error detected"),
    )

    result = await full_appsec_scan.invoke(
        url="https://example.com/search?q=test",
        scan_types="xss,sqli",
    )

    assert "Structured candidates registered: 2" in result
    assert "Validation required" in result
    assert len(isolated_lifecycle.findings) == 2
    assert {finding.category for finding in isolated_lifecycle.findings} == {"xss", "sqli"}
    assert all(finding.status == "candidate" for finding in isolated_lifecycle.findings)


@pytest.mark.asyncio
async def test_validate_browser_xss_promotes_confirmed_execution(mocker, isolated_lifecycle):
    from src.tools.browser_automation import browser_xss_test

    mocker.patch.object(
        browser_xss_test,
        "invoke",
        new=mocker.AsyncMock(return_value="XSS CONFIRMED: <svg onload=...>\nFound 1 working XSS payloads!"),
    )

    result = await validate_browser_xss.invoke(
        url="https://example.com/search?q=test",
        parameter="q",
    )

    assert "Confirmed" in result
    assert "Reportable: True" in result
    assert isolated_lifecycle.reportable("example.com")


@pytest.mark.asyncio
async def test_validate_oast_ssrf_requires_callback_before_promotion(mocker, isolated_lifecycle):
    from src.tools.appsec.ssrf import ssrf_scanner

    mocker.patch.object(
        ssrf_scanner,
        "invoke",
        new=mocker.AsyncMock(return_value="Custom/OAST target payload sent"),
    )

    pending = await validate_oast_ssrf.invoke(
        url="https://example.com/fetch?url=https://safe.example",
        parameter="url",
        oast_domain="abc.oast.fun",
    )
    assert "Awaiting callback proof" in pending
    assert isolated_lifecycle.findings[0].status == "candidate"

    promoted = await validate_oast_ssrf.invoke(
        url="https://example.com/fetch?url=https://safe.example",
        parameter="url",
        oast_domain="abc.oast.fun",
        callback_evidence="interactsh DNS callback observed from target resolver with HTTP 200",
    )
    assert "Confirmed" in promoted
    assert isolated_lifecycle.reportable("example.com")


@pytest.mark.asyncio
async def test_full_appsec_scan_registers_low_security_header_candidates(mocker, isolated_lifecycle):
    from src.tools.appsec.security_headers import security_headers_scanner

    mocker.patch.object(
        orchestrator,
        "_discover_parameters",
        new=mocker.AsyncMock(return_value=([], ["parameter discovery skipped"], [])),
    )
    mocker.patch.object(
        security_headers_scanner,
        "invoke",
        new=mocker.AsyncMock(
            return_value=(
                "## Security Headers and Cookie Scan\n"
                "### Findings\n"
                "- LOW -> Missing Content-Security-Policy\n"
                "  Evidence: Content-Security-Policy: (missing)\n"
                "Total findings: 1"
            )
        ),
    )

    result = await full_appsec_scan.invoke(
        url="https://example.com/account",
        scan_types="security_headers",
    )

    assert "Structured candidates registered: 1" in result
    assert len(isolated_lifecycle.findings) == 1
    assert isolated_lifecycle.findings[0].category == "security_headers"
    assert isolated_lifecycle.findings[0].severity == "low"
    report = isolated_lifecycle.markdown_report("example.com")
    assert "Candidates and Observations" in report
    assert "Missing Content-Security-Policy" in report


@pytest.mark.asyncio
async def test_full_appsec_scan_does_not_register_clean_cors_output(mocker, isolated_lifecycle):
    from src.tools.web import cors_scan

    mocker.patch.object(
        orchestrator,
        "_discover_parameters",
        new=mocker.AsyncMock(return_value=([], ["parameter discovery skipped"], [])),
    )
    mocker.patch.object(
        cors_scan,
        "invoke",
        new=mocker.AsyncMock(
            return_value=(
                "=== CORS Scan: https://example.com\n"
                "  [arbitrary] Origin: https://evil.com -> ACAO: '' ACAC: ''\n"
                "No CORS misconfigurations detected."
            )
        ),
    )

    result = await full_appsec_scan.invoke(
        url="https://example.com/api/profile",
        scan_types="cors",
    )

    assert "Structured candidates registered: 0" in result
    assert isolated_lifecycle.findings == []


@pytest.mark.asyncio
async def test_full_appsec_scan_fingerprints_before_deeper_scans(mocker, isolated_lifecycle):
    from src.tools.recon_active import wafw00f_detect, whatweb_scan

    call_order = []

    async def fake_whatweb(**kwargs):
        call_order.append("whatweb")
        return "https://example.com [200 OK] Apache, PHP, WordPress"

    async def fake_waf(**kwargs):
        call_order.append("wafw00f")
        return "## WAF Detection: https://example.com\nNo WAF detected"

    async def fake_discover(*args, **kwargs):
        call_order.append("discover")
        return [], ["parameter discovery skipped"], []

    mocker.patch.object(whatweb_scan, "invoke", new=mocker.AsyncMock(side_effect=fake_whatweb))
    mocker.patch.object(wafw00f_detect, "invoke", new=mocker.AsyncMock(side_effect=fake_waf))
    mocker.patch.object(orchestrator, "_discover_parameters", new=mocker.AsyncMock(side_effect=fake_discover))

    result = await full_appsec_scan.invoke(
        url="https://example.com/search?q=test",
        scan_types="fingerprint,xss",
    )

    assert call_order[:3] == ["whatweb", "wafw00f", "discover"]
    assert "## Fingerprint / WAF" in result
    assert "### WhatWeb" in result
    assert "### wafw00f" in result
    assert "Apache, PHP, WordPress" in result
