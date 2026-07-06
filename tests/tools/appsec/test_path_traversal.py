import pytest
from src.tools.appsec.path_traversal import path_traversal_scanner


def _scan_result(req, text="", status=200, error=None, elapsed=0.1):
    return {"req": req, "text": text, "status": status, "error": error, "elapsed": elapsed}


@pytest.mark.asyncio
async def test_path_traversal_positive(mocker):
    """Test path traversal finding root indicator."""
    mocker.patch("src.tools.appsec.path_traversal._detect_waf", return_value=("None", 0.0))

    async def fake_fetch(requests_, *args, **kwargs):
        return [
            _scan_result(
                req,
                "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            )
            for req in requests_
        ]

    mocker.patch("src.tools.appsec.path_traversal.async_fetch_all", side_effect=fake_fetch)
    
    result = await path_traversal_scanner.invoke(url="http://example.com/download?file=image.png", parameter="file")
    
    assert "Found 1 parameters vulnerable to Path Traversal" in result or "root:" in result
    assert "path traversal" in result.lower()

@pytest.mark.asyncio
async def test_path_traversal_negative(mocker):
    """Test path traversal with sanitized paths."""
    mocker.patch("src.tools.appsec.path_traversal._detect_waf", return_value=("None", 0.0))

    async def fake_fetch(requests_, *args, **kwargs):
        return [_scan_result(req, "File not found or illegal filename.") for req in requests_]

    mocker.patch("src.tools.appsec.path_traversal.async_fetch_all", side_effect=fake_fetch)
    
    result = await path_traversal_scanner.invoke(url="http://example.com/download?file=safe.png", parameter="file")
    
    assert "No path traversal detected" in result

@pytest.mark.asyncio
async def test_path_traversal_timeout(mocker):
    """Test scanner handles server timeouts properly."""
    mocker.patch("src.tools.appsec.path_traversal._detect_waf", return_value=("None", 0.0))

    async def fake_fetch(requests_, *args, **kwargs):
        return [_scan_result(req, error="timeout") for req in requests_]

    mocker.patch("src.tools.appsec.path_traversal.async_fetch_all", side_effect=fake_fetch)
    
    result = await path_traversal_scanner.invoke(url="http://example.com/download?file=timeout.png", parameter="file")
    
    assert "No path traversal detected" in result
