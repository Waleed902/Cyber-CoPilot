import pytest
from src.tools.appsec.ssrf import ssrf_scanner


def _scan_result(req, text="", status=200, error=None, elapsed=0.1):
    return {"req": req, "text": text, "status": status, "error": error, "elapsed": elapsed}


@pytest.mark.asyncio
async def test_ssrf_positive(mocker, fake_exploit_craft):
    """Test SSRF scanner identifying AWS metadata."""
    async def fake_fetch(requests_, *args, **kwargs):
        return [_scan_result(req, "ami-id\ninstance-id\nlocal-ipv4") for req in requests_]

    mocker.patch("src.tools.appsec.ssrf.async_fetch_all", side_effect=fake_fetch)
    
    result = await ssrf_scanner.invoke(url="http://example.com/api/fetch?url=http://safe.com", parameter="url")
    
    assert "Found " in result and "SSRF vulnerabilities!" in result or "SSRF Scan Results" in result

@pytest.mark.asyncio
async def test_ssrf_negative(mocker):
    """Test SSRF with sanitized request behavior."""
    async def fake_fetch(requests_, *args, **kwargs):
        return [_scan_result(req, "Invalid URL scheme or internal IP blocked.", status=403) for req in requests_]

    mocker.patch("src.tools.appsec.ssrf.async_fetch_all", side_effect=fake_fetch)
    
    result = await ssrf_scanner.invoke(url="http://example.com/api/fetch?url=http://unsafe.com", parameter="url")
    
    assert "No obvious SSRF detected" in result

@pytest.mark.asyncio
async def test_ssrf_timeout(mocker):
    """Test SSRF handling request timeouts."""
    async def fake_fetch(requests_, *args, **kwargs):
        return [_scan_result(req, error="timeout") for req in requests_]

    mocker.patch("src.tools.appsec.ssrf.async_fetch_all", side_effect=fake_fetch)
    
    result = await ssrf_scanner.invoke(url="http://example.com/api/fetch?url=http://timeout.com", parameter="url")
    
    assert "No obvious SSRF detected" in result or "Testing" in result
