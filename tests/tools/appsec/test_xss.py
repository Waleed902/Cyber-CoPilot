import pytest
from src.tools.appsec.xss import xss_scanner


def _scan_result(req, text="", status=200, error=None, elapsed=0.1):
    return {"req": req, "text": text, "status": status, "error": error, "elapsed": elapsed}


@pytest.mark.asyncio
async def test_xss_scanner_positive(mocker, fake_exploit_craft):
    """Test XSS scanner successfully finds reflection."""
    mocker.patch("src.tools.appsec.xss._detect_waf", return_value=("None", 0.0))

    async def fake_fetch(requests_, *args, **kwargs):
        results = []
        for req in requests_:
            payload = req.get("_payload", "")
            results.append(_scan_result(req, f"<html><body>{payload}</body></html>"))
        return results

    mocker.patch("src.tools.appsec.xss.async_fetch_all", side_effect=fake_fetch)
    result = await xss_scanner.invoke(url="http://example.com/search?q=test1", parameter="q", custom_payloads="<script>alert(1)</script>")
    
    assert "Found 1 potential XSS" in result
    assert "VULNERABLE" in result
    assert "<script>alert(1)</script>" in result

@pytest.mark.asyncio
async def test_xss_scanner_negative(mocker):
    """Test XSS scanner safely handles sanitized reflection."""
    mocker.patch("src.tools.appsec.xss._detect_waf", return_value=("None", 0.0))

    async def fake_fetch(requests_, *args, **kwargs):
        results = []
        for req in requests_:
            payload = req.get("_payload", "")
            encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
            results.append(_scan_result(req, f"<html><body>{encoded}</body></html>"))
        return results

    mocker.patch("src.tools.appsec.xss.async_fetch_all", side_effect=fake_fetch)
    result = await xss_scanner.invoke(url="http://example.com/search?q=test2", parameter="q", custom_payloads="<script>alert(1)</script>")
    
    assert "No obvious XSS vulnerabilities found" in result

@pytest.mark.asyncio
async def test_xss_scanner_timeout(mocker):
    """Test XSS scanner handles connection timeouts gracefully."""
    mocker.patch("src.tools.appsec.xss._detect_waf", return_value=("None", 0.0))

    async def fake_fetch(requests_, *args, **kwargs):
        return [_scan_result(req, error="timeout") for req in requests_]

    mocker.patch("src.tools.appsec.xss.async_fetch_all", side_effect=fake_fetch)
    result = await xss_scanner.invoke(url="http://example.com/search?q=test3", parameter="q")
    
    # Needs to not crash
    assert "No obvious XSS" in result or "XSS Scan Results" in result
