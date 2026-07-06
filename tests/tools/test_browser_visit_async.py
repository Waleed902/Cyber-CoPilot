import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class _FakeConsoleMessage:
    type = "log"
    text = "ready"


class _FakeInput:
    async def get_attribute(self, name):
        return "password" if name == "name" else None


class _FakeForm:
    async def get_attribute(self, name):
        if name == "action":
            return "/login"
        if name == "method":
            return "POST"
        return None

    async def query_selector_all(self, selector):
        assert selector == "input"
        return [_FakeInput()]


class _FakeResponse:
    status = 200


class _FakePage:
    url = "https://example.test/login"

    def on(self, event, callback):
        assert event == "console"
        callback(_FakeConsoleMessage())

    async def goto(self, url, wait_until, timeout):
        assert url == "https://example.test"
        assert wait_until == "domcontentloaded"
        assert timeout == 60000
        return _FakeResponse()

    async def title(self):
        return "Example Login"

    async def content(self):
        return "<html><script></script><input type='password'></html>"

    async def query_selector_all(self, selector):
        assert selector == "form"
        return [_FakeForm()]


class _FakeContext:
    async def new_page(self):
        return _FakePage()

    async def cookies(self):
        return [
            {
                "name": "sessionid",
                "value": "abc123",
                "httpOnly": False,
                "secure": True,
                "sameSite": "Lax",
            }
        ]


class _FakeBrowser:
    async def new_context(self, user_agent=None):
        assert user_agent is None
        return _FakeContext()

    async def close(self):
        return None


class _FakeChromium:
    async def launch(self, headless=False):
        return _FakeBrowser()


class _FakePlaywright:
    chromium = _FakeChromium()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


@pytest.mark.asyncio
async def test_browser_visit_uses_async_playwright(monkeypatch):
    playwright_module = types.ModuleType("playwright")
    async_api_module = types.ModuleType("playwright.async_api")
    async_api_module.async_playwright = lambda: _FakePlaywright()
    async_api_module.TimeoutError = TimeoutError

    monkeypatch.setitem(sys.modules, "playwright", playwright_module)
    monkeypatch.setitem(sys.modules, "playwright.async_api", async_api_module)

    from src.tools import browser_automation

    monkeypatch.setattr(browser_automation, "_check_playwright", lambda: True)
    result = await browser_automation.browser_visit.invoke(
        url="https://example.test",
        wait_time=0,
        capture_console=True,
    )

    assert "## Browser Visit (Playwright): https://example.test" in result
    assert "**Title:** Example Login" in result
    assert "**Status:** 200" in result
    assert "Form 1: POST -> /login" in result
    assert "Session cookie without HttpOnly" in result
    assert "Sync API inside the asyncio loop" not in result


class _FakeSyncPage:
    url = "https://nama.co.in/"

    def goto(self, url, wait_until, timeout):
        assert url == "https://nama.co.in"
        assert wait_until == "domcontentloaded"
        assert timeout == 30000

    def title(self):
        return "Nama - New Age Multimedia Almanac"

    def inner_text(self, selector):
        assert selector == "body"
        return "Nama page loaded normally"


class _FakeSyncContext:
    def new_page(self):
        return _FakeSyncPage()

    def cookies(self):
        return []


class _FakeSyncBrowser:
    def new_context(self, user_agent, viewport):
        assert "Chrome" in user_agent
        assert viewport == {"width": 1280, "height": 1024}
        return _FakeSyncContext()

    def close(self):
        return None


class _FakeSyncChromium:
    def launch(self, headless=False):
        return _FakeSyncBrowser()


class _FakeSyncPlaywright:
    chromium = _FakeSyncChromium()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


@pytest.mark.asyncio
async def test_browser_solve_challenge_prefers_playwright(monkeypatch):
    playwright_module = types.ModuleType("playwright")
    sync_api_module = types.ModuleType("playwright.sync_api")
    sync_api_module.sync_playwright = lambda: _FakeSyncPlaywright()

    monkeypatch.setitem(sys.modules, "playwright", playwright_module)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api_module)

    from src.tools import browser_automation

    monkeypatch.setattr(browser_automation, "_check_playwright", lambda: True)
    monkeypatch.setattr(browser_automation, "_check_selenium", lambda: True)
    monkeypatch.setattr(
        browser_automation,
        "_solve_challenge_selenium",
        lambda *args, **kwargs: "wrong backend",
    )

    result = await browser_automation.browser_solve_challenge.invoke(
        url="https://nama.co.in",
        max_wait=0,
    )

    assert "## JS Challenge Bypass: https://nama.co.in" in result
    assert "No JS challenge detected" in result
    assert "**Title:** Nama - New Age Multimedia Almanac" in result
    assert "wrong backend" not in result
