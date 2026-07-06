import pytest

from src.tools.appsec.security_headers import security_headers_scanner


class DummyResponse:
    def __init__(self, headers, status_code=200, url="https://example.com/account"):
        self.headers = headers
        self.status_code = status_code
        self.url = url
        self.raw = None


@pytest.mark.asyncio
async def test_security_headers_scanner_reports_low_and_info_findings(mocker):
    mocker.patch(
        "src.tools.appsec.security_headers.requests.get",
        return_value=DummyResponse(
            {
                "Server": "nginx/1.24.0",
                "Set-Cookie": "sessionid=abc123; Path=/",
            }
        ),
    )

    result = await security_headers_scanner.invoke(
        url="https://example.com/account",
        cookies="sessionid=abc123",
    )

    assert "LOW -> Missing Strict-Transport-Security" in result
    assert "LOW -> Missing Content-Security-Policy" in result
    assert "LOW -> Cookie missing Secure flag: sessionid" in result
    assert "LOW -> Session-like cookie missing HttpOnly: sessionid" in result
    assert "INFO -> Missing Referrer-Policy" in result
    assert "Total findings: 0" not in result
