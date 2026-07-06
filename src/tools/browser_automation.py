"""
Browser Automation Tools - Multi-tab browser control for security testing

Provides browser automation capabilities for:
- XSS testing with real browser execution
- CSRF testing
- Authentication flow testing
- Session management
- JavaScript execution
- DOM manipulation
"""

import subprocess
import os
import json
import time
import asyncio
from typing import Dict, List
from dataclasses import dataclass, field
from src.sdk.tool import function_tool


# Check for available browser automation tools
def _check_playwright() -> bool:
    """Check if Playwright is available."""
    try:
        import playwright

        return True
    except ImportError:
        return False


def _check_selenium() -> bool:
    """Check if Selenium is available."""
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options

        return True
    except Exception:
        return False


def _browser_dependency_hint(error: Exception) -> str:
    """Return a short operator-facing hint for known browser dependency failures."""
    import sys
    message = str(error)
    pip = f"{sys.executable} -m pip"
    if "pyee" in message or "No module named 'pyee'" in message:
        return (
            f"\nFix: {pip} install pyee playwright && playwright install chromium\n"
            "pyee is a required dependency of playwright."
        )
    if "playwright" in message.lower() or "No module named 'playwright'" in message:
        return (
            f"\nFix: {pip} install playwright pyee && playwright install chromium"
        )
    if "BaseHTTPResponse" in message and "urllib3" in message:
        return (
            "\nHint: Selenium is installed but its urllib3 dependency is incompatible. "
            f"Fix: {pip} install playwright pyee && playwright install chromium"
        )
    if "executable needs to be in PATH" in message or "chromium" in message.lower():
        return "\nFix: playwright install chromium"
    return ""


@dataclass
class BrowserSession:
    """Represents a browser session with multiple tabs."""

    session_id: str
    cookies: Dict[str, str] = field(default_factory=dict)
    local_storage: Dict[str, str] = field(default_factory=dict)
    session_storage: Dict[str, str] = field(default_factory=dict)
    tabs: List[str] = field(default_factory=list)
    current_url: str = ""


# Global browser state
_browser_sessions: Dict[str, BrowserSession] = {}


@function_tool()
async def browser_visit(
    url: str, wait_time: int = 3, user_agent: str = "", capture_console: bool = True, wait_strategy: str = "domcontentloaded"
) -> str:
    """
    Visit a URL in a headless browser and capture the result.
    Executes JavaScript, handles redirects, and captures console output.

    Args:
        url: URL to visit
        wait_time: Seconds to wait for page load
        user_agent: Custom user agent (optional)
        capture_console: Capture JavaScript console output
        wait_strategy: Playwright wait strategy (domcontentloaded, networkidle, load, commit)

    Returns:
        Page information including DOM, console logs, and cookies
    """
    results = [f"## Browser Visit: {url}\n"]

    # Try Playwright first, then Selenium, then fall back to curl
    if _check_playwright():
        return await _browser_visit_playwright_async(url, wait_time, user_agent, capture_console, wait_strategy)
    elif _check_selenium():
        return await asyncio.to_thread(_browser_visit_selenium, url, wait_time, user_agent)
    else:
        import sys

        results.append(
            f"⚠️ No browser automation available (playwright and selenium both missing).\n"
            f"Fix: {sys.executable} -m pip install playwright pyee && playwright install chromium"
        )
        results.append("Falling back to curl (no JavaScript execution)...")
        results.append("")

        # Fallback to curl
        cmd = ["curl", "-s", "-i", "--max-time", "15"]
        if user_agent:
            cmd.extend(["-H", f"User-Agent: {user_agent}"])
        cmd.append(url)

        try:
            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=20,
            )
            results.append(result.stdout[:3000])
        except Exception as e:
            results.append(f"Error: {str(e)}")

        return "\n".join(results)


async def _browser_visit_playwright_async(
    url: str, wait_time: int, user_agent: str, capture_console: bool, wait_strategy: str
) -> str:
    """Visit URL using Playwright's async API."""
    results = [f"## Browser Visit (Playwright): {url}\n"]

    try:
        from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

        console_logs = []
        response = None
        title = ""
        current_url = ""
        cookies = []
        content = ""
        form_info = []
        goto_warning = ""

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=False)
            try:
                context = await browser.new_context(user_agent=user_agent if user_agent else None)
                page = await context.new_page()

                if capture_console:
                    page.on(
                        "console",
                        lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"),
                    )

                try:
                    response = await page.goto(url, wait_until=wait_strategy, timeout=60000)
                except PlaywrightTimeoutError as e:
                    goto_warning = f"Page.goto timeout ({wait_strategy}): {e}"
                except Exception as e:
                    goto_warning = f"Page.goto error: {e}"

                await asyncio.sleep(wait_time)

                try:
                    title = await page.title()
                except Exception:
                    title = ""
                try:
                    current_url = page.url
                except Exception:
                    current_url = ""
                try:
                    cookies = await context.cookies()
                except Exception:
                    cookies = []

                try:
                    content = await page.content()
                except Exception:
                    content = ""

                try:
                    forms = await page.query_selector_all("form")
                except Exception:
                    forms = []

                for form in forms:
                    action = await form.get_attribute("action") or ""
                    method = await form.get_attribute("method") or "GET"
                    inputs = await form.query_selector_all("input")
                    input_names = []
                    for input_el in inputs:
                        name = await input_el.get_attribute("name")
                        if name:
                            input_names.append(name)
                    form_info.append(
                        {"action": action, "method": method, "inputs": input_names}
                    )
            finally:
                try:
                    await browser.close()
                except Exception:
                    pass

        if goto_warning:
            results.append(f"Warning: {goto_warning}")

        results.append(f"**Title:** {title or '(unknown)'}")
        results.append(f"**Final URL:** {current_url or '(unknown)'}")
        results.append(f"**Status:** {response.status if response else 'Unknown'}")

        results.append("\n### Cookies")
        for cookie in cookies[:10]:
            flags = []
            if cookie.get("httpOnly"):
                flags.append("HttpOnly")
            if cookie.get("secure"):
                flags.append("Secure")
            if cookie.get("sameSite"):
                flags.append(f"SameSite={cookie['sameSite']}")
            results.append(
                f"  {cookie['name']}: {cookie['value'][:30]}... [{', '.join(flags)}]"
            )

        if console_logs:
            results.append("\n### Console Output")
            for log in console_logs[:20]:
                results.append(f"  {log}")

        if form_info:
            results.append("\n### Forms Found")
            for i, form in enumerate(form_info):
                results.append(f"  Form {i+1}: {form['method']} -> {form['action']}")
                results.append(f"    Inputs: {', '.join(form['inputs'][:10])}")

        results.append("\n### Security Observations")

        if "<script" in content.lower():
            script_count = content.lower().count("<script")
            results.append(f"  Info: {script_count} script tags found")

        if "password" in content.lower():
            results.append("  Warning: Password field detected")

        if any(
            not c.get("httpOnly")
            for c in cookies
            if "session" in c.get("name", "").lower()
        ):
            results.append("  Critical: Session cookie without HttpOnly!")

    except Exception as e:
        results.append(f"Error: {str(e)}")

    return "\n".join(results)


def _browser_visit_playwright(
    url: str, wait_time: int, user_agent: str, capture_console: bool, wait_strategy: str
) -> str:
    """Visit URL using Playwright."""
    results = [f"## Browser Visit (Playwright): {url}\n"]

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

        console_logs = []
        response = None
        title = ""
        current_url = ""
        cookies = []
        content = ""
        form_info = []
        goto_warning = ""

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            try:
                context = browser.new_context(user_agent=user_agent if user_agent else None)
                page = context.new_page()

                # Capture console
                if capture_console:
                    page.on(
                        "console",
                        lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"),
                    )

                # Navigate
                try:
                    # networkidle has a higher chance of timing out but renders SPAs better
                    response = page.goto(url, wait_until=wait_strategy, timeout=60000)
                except PlaywrightTimeoutError as e:
                    goto_warning = f"Page.goto timeout ({wait_strategy}): {e}"
                except Exception as e:
                    goto_warning = f"Page.goto error: {e}"

                time.sleep(wait_time)

                # Get page info (best-effort; don't fail the whole tool)
                try:
                    title = page.title()
                except Exception:
                    title = ""
                try:
                    current_url = page.url
                except Exception:
                    current_url = ""
                try:
                    cookies = context.cookies()
                except Exception:
                    cookies = []

                # Get page content
                try:
                    content = page.content()
                except Exception:
                    content = ""

                # Get forms
                try:
                    forms = page.query_selector_all("form")
                except Exception:
                    forms = []

                for form in forms:
                    action = form.get_attribute("action") or ""
                    method = form.get_attribute("method") or "GET"
                    inputs = form.query_selector_all("input")
                    input_names = [
                        i.get_attribute("name") for i in inputs if i.get_attribute("name")
                    ]
                    form_info.append(
                        {"action": action, "method": method, "inputs": input_names}
                    )
            finally:
                try:
                    browser.close()
                except Exception:
                    pass

        if goto_warning:
            results.append(f"⚠️ {goto_warning}")

        results.append(f"**Title:** {title or '(unknown)'}")
        results.append(f"**Final URL:** {current_url or '(unknown)'}")
        results.append(f"**Status:** {response.status if response else 'Unknown'}")

        results.append("\n### Cookies")
        for cookie in cookies[:10]:
            flags = []
            if cookie.get("httpOnly"):
                flags.append("HttpOnly")
            if cookie.get("secure"):
                flags.append("Secure")
            if cookie.get("sameSite"):
                flags.append(f"SameSite={cookie['sameSite']}")
            results.append(
                f"  {cookie['name']}: {cookie['value'][:30]}... [{', '.join(flags)}]"
            )

        if console_logs:
            results.append("\n### Console Output")
            for log in console_logs[:20]:
                results.append(f"  {log}")

        if form_info:
            results.append("\n### Forms Found")
            for i, form in enumerate(form_info):
                results.append(f"  Form {i+1}: {form['method']} -> {form['action']}")
                results.append(f"    Inputs: {', '.join(form['inputs'][:10])}")

        # Security observations
        results.append("\n### Security Observations")

        if "<script" in content.lower():
            script_count = content.lower().count("<script")
            results.append(f"  ℹ️ {script_count} script tags found")

        if "password" in content.lower():
            results.append("  ⚠️ Password field detected")

        if any(
            not c.get("httpOnly")
            for c in cookies
            if "session" in c.get("name", "").lower()
        ):
            results.append("  🔴 Session cookie without HttpOnly!")

    except Exception as e:
        results.append(f"Error: {str(e)}")

    return "\n".join(results)


def _browser_visit_selenium(url: str, wait_time: int, user_agent: str) -> str:
    """Visit URL using Selenium."""
    results = [f"## Browser Visit (Selenium): {url}\n"]

    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.common.by import By

        options = Options()
        # options.add_argument("--headless")  # Disabled so user can see it
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1280,1024")  # Give it a nice default size

        try:
            from webdriver_manager.chrome import ChromeDriverManager
            from selenium.webdriver.chrome.service import Service

            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=options)
        except ImportError:
            # Fallback to default PATH driver if webdriver-manager not available
            driver = webdriver.Chrome(options=options)

        try:
            driver.get(url)
            time.sleep(wait_time)

            title = driver.title
            current_url = driver.current_url
            cookies = driver.get_cookies()

            results.append(f"**Title:** {title}")
            results.append(f"**Final URL:** {current_url}")

            results.append("\n### Cookies")
            for cookie in cookies[:10]:
                results.append(f"  {cookie['name']}: {cookie['value'][:30]}...")

            # Get forms
            forms = driver.find_elements(By.TAG_NAME, "form")
            if forms:
                results.append(f"\n### Forms Found: {len(forms)}")

        finally:
            driver.quit()

    except Exception as e:
        results.append(f"Error: {str(e)}")

    return "\n".join(results)


@function_tool()
def browser_xss_test(url: str, parameter: str, payloads: str = "") -> str:
    """
    Test for XSS vulnerabilities using a real browser.
    Executes payloads and checks if JavaScript runs.

    Args:
        url: Target URL with parameter
        parameter: Parameter to inject XSS payload
        payloads: Custom payloads (semicolon-separated) or use defaults

    Returns:
        XSS test results with execution confirmation
    """
    results = ["## Browser XSS Test\n"]

    if not _check_playwright():
        return "Error: Playwright not installed. Run: pip install playwright && playwright install"

    # Default payloads that will trigger alerts we can detect
    default_payloads = [
        "<script>window.xss_triggered=true</script>",
        '<img src=x onerror="window.xss_triggered=true">',
        '<svg onload="window.xss_triggered=true">',
        '"><script>window.xss_triggered=true</script>',
        "'-window.xss_triggered=true-'",
    ]

    test_payloads = payloads.split(";") if payloads else default_payloads

    vulnerable = []

    try:
        from playwright.sync_api import sync_playwright
        import urllib.parse

        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)

            for payload in test_payloads:
                context = browser.new_context()
                page = context.new_page()

                # Build test URL
                test_params = params.copy()
                test_params[parameter] = payload
                test_query = urllib.parse.urlencode(test_params)
                test_url = (
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                )

                try:
                    page.goto(test_url, timeout=10000)
                    time.sleep(1)

                    # Check if XSS triggered
                    triggered = page.evaluate("() => window.xss_triggered === true")

                    if triggered:
                        vulnerable.append({"payload": payload, "url": test_url})
                        results.append(f"  ✅ XSS CONFIRMED: {payload[:50]}...")
                    else:
                        results.append(f"  ❌ No execution: {payload[:50]}...")

                except Exception as e:
                    results.append(f"  ⚠️ Error with payload: {str(e)[:40]}")

                finally:
                    context.close()

            browser.close()

    except Exception as e:
        results.append(f"Error: {str(e)}")

    # Summary
    results.append("\n### Summary")
    if vulnerable:
        results.append(f"🔴 Found {len(vulnerable)} working XSS payloads!")
        for vuln in vulnerable:
            results.append(f"  - {vuln['payload'][:60]}")
    else:
        results.append(
            "✅ No XSS execution detected (payloads may be filtered/encoded)"
        )

    return "\n".join(results)


@function_tool()
def browser_auth_test(
    login_url: str,
    username_field: str,
    password_field: str,
    username: str,
    password: str,
    success_indicator: str = "",
    submit_button: str = "",
) -> str:
    """
    Test authentication flow in a browser.

    Args:
        login_url: URL of login page
        username_field: CSS selector or name of username field
        password_field: CSS selector or name of password field
        username: Username to test
        password: Password to test
        success_indicator: Text or element that indicates successful login
        submit_button: CSS selector for submit button (optional)

    Returns:
        Authentication test results
    """
    results = ["## Browser Authentication Test\n"]

    if not _check_playwright():
        return "Error: Playwright not installed. Run: pip install playwright && playwright install"

    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            context = browser.new_context()
            page = context.new_page()

            # Navigate to login page
            page.goto(login_url, wait_until="networkidle")
            results.append(f"Loaded: {page.title()}")

            # Find and fill username
            if username_field.startswith("#") or username_field.startswith("."):
                page.fill(username_field, username)
            else:
                page.fill(f"[name='{username_field}']", username)
            results.append(f"Filled username: {username}")

            # Find and fill password
            if password_field.startswith("#") or password_field.startswith("."):
                page.fill(password_field, password)
            else:
                page.fill(f"[name='{password_field}']", password)
            results.append(f"Filled password: {'*' * len(password)}")

            # Submit
            if submit_button:
                page.click(submit_button)
            else:
                # Try common submit selectors
                for selector in [
                    'button[type="submit"]',
                    'input[type="submit"]',
                    "button",
                    ".login-btn",
                    "#login",
                ]:
                    try:
                        page.click(selector, timeout=2000)
                        break
                    except:
                        continue

            # Wait for navigation
            time.sleep(3)

            final_url = page.url
            final_title = page.title()
            cookies = context.cookies()
            content = page.content()

            results.append("\n### After Login")
            results.append(f"URL: {final_url}")
            results.append(f"Title: {final_title}")

            # Check success

            if success_indicator:
                if success_indicator in content:
                    results.append(f"✅ Success indicator found: {success_indicator}")
            else:
                # Heuristics
                if login_url != final_url:
                    results.append("✅ URL changed after login")
                if any(
                    "session" in c["name"].lower() or "auth" in c["name"].lower()
                    for c in cookies
                ):
                    results.append("✅ Session cookie set")

            results.append("\n### Cookies After Login")
            for cookie in cookies:
                flags = []
                if cookie.get("httpOnly"):
                    flags.append("HttpOnly")
                if cookie.get("secure"):
                    flags.append("Secure")
                results.append(f"  {cookie['name']}: [{', '.join(flags)}]")

            # Security analysis
            results.append("\n### Security Analysis")

            if "https" not in login_url:
                results.append("🔴 Login over HTTP (credentials sent in cleartext)")

            csrf_found = False
            for pattern in ["csrf", "_token", "authenticity"]:
                if pattern in content.lower():
                    csrf_found = True
                    break

            if not csrf_found:
                results.append("⚠️ No CSRF protection detected on login form")

            browser.close()

    except Exception as e:
        results.append(f"Error: {str(e)}")

    return "\n".join(results)


@function_tool()
def browser_execute_js(url: str, javascript: str) -> str:
    """
    Execute custom JavaScript in a browser context.
    Useful for testing DOM-based vulnerabilities.

    Args:
        url: Page to load before executing
        javascript: JavaScript code to execute

    Returns:
        JavaScript execution result
    """
    if not _check_playwright():
        return "Error: Playwright not installed"

    results = ["## JavaScript Execution\n"]

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            page = browser.new_page()

            goto_warning = ""
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=15000)
            except PlaywrightTimeoutError as e:
                goto_warning = f"Page.goto timeout (domcontentloaded): {e}"
            except Exception as e:
                goto_warning = f"Page.goto error: {e}"

            try:
                page.wait_for_load_state("networkidle", timeout=5000)
            except PlaywrightTimeoutError:
                results.append("Note: networkidle did not settle; continuing with the loaded DOM.")
            except Exception:
                pass

            if goto_warning:
                results.append(f"Warning: {goto_warning}")
            results.append(f"Loaded: {url}")

            try:
                result = page.evaluate(javascript)
                results.append("\n### Result")
                results.append(
                    f"```\n{json.dumps(result, indent=2) if result else 'undefined'}\n```"
                )
            except Exception as e:
                results.append("\n### Error")
                results.append(f"```\n{str(e)}\n```")

            browser.close()

    except Exception as e:
        results.append(f"Error: {str(e)}")

    return "\n".join(results)


@function_tool()
def browser_screenshot(url: str, filename: str = "") -> str:
    """
    Take a screenshot of a webpage.

    Args:
        url: URL to screenshot
        filename: Output filename (optional, auto-generated if empty)

    Returns:
        Screenshot result with path
    """
    from src.repl.target_manager import get_target_manager
    from pathlib import Path
    import os
    import time
    import hashlib

    tm = get_target_manager()

    if tm.session_dir:
        # Save explicitly in the current target's session directory
        screenshots_dir = tm.session_dir / "screenshots"
    else:
        screenshots_dir = Path(os.getcwd()) / "screenshots"

    screenshots_dir.mkdir(parents=True, exist_ok=True)

    if not filename:
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        filename = f"screenshot_{url_hash}.png"

    filepath = screenshots_dir / filename

    if _check_selenium():
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            
            options = Options()
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--window-size=1280,1024")
            
            try:
                from webdriver_manager.chrome import ChromeDriverManager
                from selenium.webdriver.chrome.service import Service
                
                service = Service(ChromeDriverManager().install())
                driver = webdriver.Chrome(service=service, options=options)
            except ImportError:
                driver = webdriver.Chrome(options=options)
                
            try:
                driver.get(url)
                time.sleep(3) # Wait for page load
                # Save screenshot to the determined filepath
                driver.save_screenshot(str(filepath))
            finally:
                driver.quit()
                
            return f"✅ Screenshot saved via Selenium: {filepath.absolute()}"
        except Exception as e:
            return f"Error taking screenshot with Selenium: {str(e)}"
            
    elif _check_playwright():
        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=False)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()

                page.goto(url, wait_until="networkidle", timeout=15000)
                page.screenshot(path=str(filepath), full_page=True)

                browser.close()

            return f"✅ Screenshot saved via Playwright: {filepath.absolute()}"

        except Exception as e:
            return f"Error taking screenshot with Playwright: {str(e)}"
    
    return "Error: Neither Selenium nor Playwright is installed."


@function_tool()
def browser_extract_forms(url: str) -> str:
    """
    Extract all forms from a page for analysis.

    Args:
        url: URL to analyze

    Returns:
        Detailed form information
    """
    results = ["## Form Extraction\n"]

    if not _check_playwright():
        # Fallback to curl + regex
        cmd = ["curl", "-s", "--max-time", "15", url]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            content = result.stdout

            import re

            forms = re.findall(
                r"<form[^>]*>(.*?)</form>", content, re.DOTALL | re.IGNORECASE
            )

            results.append(f"Found {len(forms)} forms (basic extraction)")

            for i, form in enumerate(forms):
                action = re.search(r'action=["\']([^"\']+)["\']', form)
                method = re.search(r'method=["\']([^"\']+)["\']', form)
                inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', form)

                results.append(f"\n### Form {i+1}")
                results.append(f"  Action: {action.group(1) if action else 'None'}")
                results.append(f"  Method: {method.group(1) if method else 'GET'}")
                results.append(f"  Inputs: {', '.join(inputs)}")

        except Exception as e:
            results.append(f"Error: {str(e)}")

        return "\n".join(results)

    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            page = browser.new_page()

            page.goto(url, wait_until="networkidle")

            forms = page.query_selector_all("form")
            results.append(f"Found {len(forms)} forms\n")

            for i, form in enumerate(forms):
                action = form.get_attribute("action") or "None"
                method = form.get_attribute("method") or "GET"
                enctype = (
                    form.get_attribute("enctype") or "application/x-www-form-urlencoded"
                )

                results.append(f"### Form {i+1}")
                results.append(f"  Action: {action}")
                results.append(f"  Method: {method.upper()}")
                results.append(f"  Enctype: {enctype}")

                # Get all inputs
                inputs = form.query_selector_all("input, select, textarea")
                results.append("  Fields:")

                for inp in inputs:
                    name = inp.get_attribute("name")
                    input_type = inp.get_attribute("type") or "text"
                    value = inp.get_attribute("value") or ""
                    required = inp.get_attribute("required") is not None

                    if name:
                        req_str = " (required)" if required else ""
                        results.append(
                            f"    - {name}: type={input_type}, value='{value[:20]}'{req_str}"
                        )

                # CSRF token detection
                csrf_input = form.query_selector(
                    'input[name*="csrf"], input[name*="token"], input[name="_token"]'
                )
                if csrf_input:
                    results.append("  ✅ CSRF token present")
                else:
                    results.append("  ⚠️ No CSRF token detected")

                results.append("")

            browser.close()

    except Exception as e:
        results.append(f"Error: {str(e)}")

    return "\n".join(results)


@function_tool()
def browser_check_available() -> str:
    """
    Check which browser automation tools are available.

    Returns:
        Status of browser automation capabilities
    """
    results = ["## Browser Automation Status\n"]

    if _check_playwright():
        results.append("✅ Playwright: Available")
        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=False)
                browser.close()
            results.append("  ✅ Chromium browser working")
        except Exception as e:
            results.append(f"  ⚠️ Browser issue: {str(e)[:50]}")
    else:
        results.append("❌ Playwright: Not installed")
        results.append("  Install with: pip install playwright && playwright install")

    if _check_selenium():
        results.append("✅ Selenium: Available")
    else:
        results.append("❌ Selenium: Not installed")
        results.append("  Install with: pip install selenium")

    results.append("\n### Recommendations")
    if not _check_playwright() and not _check_selenium():
        results.append("  Install Playwright for full browser automation:")
        results.append("  pip install playwright && playwright install")

    return "\n".join(results)


@function_tool()
def dom_vulnerability_scanner(url: str, cookies: str = "") -> str:
    """
    Scan for DOM-based vulnerabilities (DOM XSS, DOM Open Redirect) using Playwright.

    Injects tracking canaries into the URL fragment (#), query string (?), and path.
    Uses JavaScript instrumentation (Playwright init scripts) to hook dangerous DOM
    sinks like `innerHTML`, `eval()`, `document.write()`, and `setTimeout()` to
    detect if user-controlled sources flow into actionable execution sinks.

    Args:
        url: Target URL to test (e.g., https://example.com/page)
        cookies: Optional session cookies (format: name1=value1; name2=value2)

    Returns:
        DOM vulnerability report with trace details matching Sources to Sinks.
    """
    import urllib.parse
    import time

    if not _check_playwright():
        return "Error: Playwright not installed. Run: pip install playwright && playwright install"

    out = [f"=== DOM Vulnerability Scanner: {url}", ""]

    # ── Parse URL to inject canaries ──────────────────────────────────────────
    parsed = urllib.parse.urlparse(url)

    canary_hash = "cycophash123"
    canary_search = "cycopsearch456"
    canary_path = "cycoppath789"

    # Rebuild URL with canaries
    qs = dict(urllib.parse.parse_qsl(parsed.query))
    if not qs:
        # If no params, add a dummy one
        qs["q"] = canary_search
    else:
        # Infect existing params
        for k in qs:
            qs[k] = f"{qs[k]}{canary_search}"

    new_query = urllib.parse.urlencode(qs)

    # Attempt to inject path if it has an extension or trailing slash
    new_path = parsed.path
    if new_path.endswith("/"):
        new_path = f"{new_path}{canary_path}"

    test_url = urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, new_path, parsed.params, new_query, canary_hash)
    )

    out.append("── Source Injection ──────────────────────────────")
    out.append(f"  [source: location.hash]     {canary_hash}")
    out.append(f"  [source: location.search]   {canary_search}")
    out.append(f"  [source: location.pathname] {canary_path}")
    out.append(f"  Target URL: {test_url}")
    out.append("")

    # ── Playwright instrumentation script ─────────────────────────────────────
    # This script runs before any page JavaScript, hooking dangerous sinks
    init_script = """
    () => {
        window._cycop_sinks = [];
        const track = (sink, payload, tag = '') => {
            if (typeof payload === 'string' && payload.includes('cycop')) {
                window._cycop_sinks.push({ sink, payload, tag, stack: new Error().stack });
            }
        };

        // Hook eval
        const _eval = window.eval;
        window.eval = function(code) {
            track('eval()', code);
            return _eval.apply(this, arguments);
        };

        // Hook setTimeout / setInterval
        const _setTimeout = window.setTimeout;
        window.setTimeout = function(code, time) {
            if (typeof code === 'string') track('setTimeout()', code);
            return _setTimeout.apply(this, arguments);
        };
        const _setInterval = window.setInterval;
        window.setInterval = function(code, time) {
            if (typeof code === 'string') track('setInterval()', code);
            return _setInterval.apply(this, arguments);
        };

        // Hook document.write
        const _write = document.write;
        document.write = function(html) {
            track('document.write()', html);
            return _write.apply(this, arguments);
        };
        const _writeln = document.writeln;
        document.writeln = function(html) {
            track('document.writeln()', html);
            return _writeln.apply(this, arguments);
        };

        // Hook Element.innerHTML and Element.outerHTML
        const originalInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
        if (originalInnerHTML && originalInnerHTML.set) {
            Object.defineProperty(Element.prototype, 'innerHTML', {
                set: function(val) {
                    track('innerHTML', val, this.tagName);
                    return originalInnerHTML.set.call(this, val);
                },
                get: function() {
                    return originalInnerHTML.get.call(this);
                }
            });
        }
        
        // Hook location assignments (DOM Open Redirect)
        const originalAssign = window.location.assign;
        window.location.assign = function(url) {
            track('location.assign()', url);
            return originalAssign.apply(window.location, arguments);
        };
        const originalReplace = window.location.replace;
        window.location.replace = function(url) {
            track('location.replace()', url);
            return originalReplace.apply(window.location, arguments);
        };
    }
    """

    findings = []

    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=False, args=["--disable-web-security", "--no-sandbox"]
            )
            context = browser.new_context(ignore_https_errors=True)

            # Apply cookies
            if cookies:
                cookie_objs = []
                for pair in cookies.split(";"):
                    if "=" in pair:
                        k, v = pair.strip().split("=", 1)
                        cookie_objs.append(
                            {
                                "name": k,
                                "value": v,
                                "domain": urllib.parse.urlparse(url).hostname,
                                "path": "/",
                            }
                        )
                context.add_cookies(cookie_objs)

            page = context.new_page()
            page.add_init_script(init_script)

            # Navigate and intercept requests for Open Redirect tracking
            redirect_caught = []

            def handle_request(route, request):
                if request.is_navigation_request and request.url != test_url:
                    if "cycop" in request.url:
                        redirect_caught.append(request.url)
                route.continue_()

            page.route("**/*", handle_request)

            try:
                page.goto(test_url, wait_until="networkidle", timeout=15000)
            except Exception:
                # Page transitions or timeouts are fine, we just want to look at sinks
                pass

            # Allow time for delayed JS execution (setTimeout, promises, intervals)
            time.sleep(2)

            # Retrieve trapped sinks
            try:
                captured_sinks = page.evaluate("window._cycop_sinks || []")
            except Exception:
                captured_sinks = []

            out.append("── Trace Results ─────────────────────────────")
            out.append(f"  Intercepted JS flows: {len(captured_sinks)}")
            out.append("")

            if not captured_sinks and not redirect_caught:
                out.append("✅ No DOM-based vulnerabilities detected.")
                out.append(
                    "  Canaries did not flow into any dangerous execution sinks."
                )

            else:
                out.append("── FINDINGS ──────────────────────────────────")

                for s in captured_sinks:
                    sink_name = s.get("sink", "unknown")
                    payload = s.get("payload", "")
                    tag = s.get("tag", "")

                    # Determine source
                    source = "Unknown"
                    if canary_hash in payload:
                        source = "location.hash"
                    elif canary_search in payload:
                        source = "location.search"
                    elif canary_path in payload:
                        source = "location.pathname"

                    if "innerHTML" in sink_name and tag:
                        sink_name = f"{tag}.innerHTML"

                    findings.append(
                        f"CRITICAL → DOM XSS DETECTED!\n"
                        f"  Source : {source}\n"
                        f"  Sink   : {sink_name}\n"
                        f"  Value  : {payload[:150]}\n"
                        f"  PoC    : Attacker can achieve XSS by providing a malicious URL containing JavaScript payloads."
                    )

                for red_url in redirect_caught:
                    source = "Unknown"
                    if canary_hash in red_url:
                        source = "location.hash"
                    elif canary_search in red_url:
                        source = "location.search"
                    elif canary_path in red_url:
                        source = "location.pathname"

                    findings.append(
                        f"HIGH → DOM Open Redirect DETECTED!\n"
                        f"  Source : {source}\n"
                        f"  Sink   : Navigation (window.location / meta refresh)\n"
                        f"  URL    : {red_url[:150]}\n"
                        f"  PoC    : Attacker can redirect users to an arbitrary external domain."
                    )

                # Uniquify findings to avoid spam (e.g. setInterval loops)
                unique_findings = []
                for f in findings:
                    if f not in unique_findings:
                        unique_findings.append(f)

                for f in unique_findings:
                    out.append(f"🔴 {f}\n")

                out.append("Remediation:")
                out.append("  • Avoid using dangerous sinks like innerHTML or eval()")
                out.append(
                    "  • Instead use textContent, innerText, or DOMpurify library"
                )
                out.append(
                    "  • Ensure all untrusted inputs are properly context-encoded before reaching sinks"
                )

            browser.close()

    except Exception as e:
        out.append(f"Error during DOM scan: {str(e)}")

    return "\n".join(out)


# -----------------------------------------------------------------------------
# PERSISTENT BROWSER SESSION TOOLS (For interactive crawling)
# -----------------------------------------------------------------------------
_persistent_driver = None

@function_tool()
def browser_open_session(url: str) -> str:
    """
    Start a persistent interactive browser session that stays open across multiple steps.
    Use this when you need to click elements, type text, or navigate a multi-step flow.
    Args:
        url: The URL to open initially.
    Returns:
        The page title and current URL after loading.
    """
    global _persistent_driver
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options

        if _persistent_driver is not None:
            _persistent_driver.quit()

        options = Options()
        # options.add_argument("--headless") # Keep visible for testing
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1280,1024")

        # Selenium 4.6+ auto-manages the driver natively without webdriver_manager
        _persistent_driver = webdriver.Chrome(options=options)

        _persistent_driver.get(url)
        time.sleep(3)
        return f"✅ Persistent session started at: {_persistent_driver.current_url}\nTitle: {_persistent_driver.title}"
    except Exception as e:
        return f"Error starting session: {str(e)}{_browser_dependency_hint(e)}"

@function_tool()
def browser_click_element(css_selector: str) -> str:
    """
    Click an element in the currently open persistent browser session.
    Must run `browser_open_session` first. Wait 2 seconds after clicking.
    Args:
        css_selector: A valid CSS selector for the element to click.
    """
    global _persistent_driver
    if _persistent_driver is None:
        return "Error: No active browser session. Run `browser_open_session` first."
    
    try:
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        
        element = WebDriverWait(_persistent_driver, 5).until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, css_selector))
        )
        element.click()
        time.sleep(2)
        return f"✅ Clicked element: {css_selector}. Current URL: {_persistent_driver.current_url}"
    except Exception as e:
        return f"Error clicking element '{css_selector}': {str(e)}"

@function_tool()
def browser_type_text(css_selector: str, text: str) -> str:
    """
    Type text into an input field in the currently open persistent browser session.
    Must run `browser_open_session` first. 
    Args:
        css_selector: A valid CSS selector for the input element.
        text: The text to type.
    """
    global _persistent_driver
    if _persistent_driver is None:
        return "Error: No active browser session. Run `browser_open_session` first."
    
    try:
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        
        element = WebDriverWait(_persistent_driver, 5).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, css_selector))
        )
        element.clear()
        element.send_keys(text)
        return f"✅ Typed '{text}' into {css_selector}."
    except Exception as e:
        return f"Error typing into element '{css_selector}': {str(e)}"

@function_tool()
def browser_get_session_html() -> str:
    """
    Get the current DOM/HTML of the active persistent browser session.
    """
    global _persistent_driver
    if _persistent_driver is None:
        return "Error: No active browser session."
    return _persistent_driver.page_source[:8000] # Return first 8000 chars to avoid token limits

@function_tool()
def browser_close_session() -> str:
    """
    Close the currently open persistent browser session to free memory.
    """
    global _persistent_driver
    if _persistent_driver is not None:
        try:
            _persistent_driver.quit()
        except:
            pass
        _persistent_driver = None
        return "✅ Browser session closed."
    return "No active session to close."


# -----------------------------------------------------------------------------
# AUTONOMOUS BROWSER CONTROL PRIMITIVES
# These tools enable the AI to fully control a browser session step-by-step:
#   1. browser_get_page_state() — see the page (AI-friendly element list)
#   2. browser_navigate(url) — go to a URL  
#   3. browser_scroll(direction) — scroll to see more
#   4. browser_select_option(selector, value) — pick from dropdowns
#   5. browser_press_key(key) — press Enter, Escape, Tab, etc.
#   6. browser_wait_for(selector) — wait for dynamic content
#   7. browser_upload_file(selector, path) — upload files
#   8. browser_hover(selector) — hover for menus/tooltips
# -----------------------------------------------------------------------------


@function_tool()
def browser_get_page_state(include_screenshot: bool = True) -> str:
    """
    Get a compact, AI-friendly view of the current browser page state.
    Returns: current URL, title, a numbered list of ALL interactive elements
    (buttons, links, inputs, selects, textareas), and optionally a screenshot path.

    Use this INSTEAD of browser_get_session_html for understanding what's on screen.
    The numbered element list lets you reference elements by number in subsequent
    browser_click_element or browser_type_text calls.

    Args:
        include_screenshot: Take a screenshot and return its path (default True)

    Returns:
        Compact page state with numbered interactive elements
    """
    global _persistent_driver
    if _persistent_driver is None:
        return "Error: No active browser session. Run `browser_open_session(url)` first."

    try:
        from selenium.webdriver.common.by import By

        results = []
        results.append(f"URL: {_persistent_driver.current_url}")
        results.append(f"Title: {_persistent_driver.title}")

        # Take screenshot if requested
        if include_screenshot:
            try:
                from src.repl.target_manager import get_target_manager
                from pathlib import Path
                import hashlib

                tm = get_target_manager()
                if tm.session_dir:
                    ss_dir = tm.session_dir / "screenshots"
                else:
                    ss_dir = Path(os.getcwd()) / "screenshots"
                ss_dir.mkdir(parents=True, exist_ok=True)

                url_hash = hashlib.md5(_persistent_driver.current_url.encode()).hexdigest()[:8]
                ts = int(time.time())
                ss_path = ss_dir / f"state_{url_hash}_{ts}.png"
                _persistent_driver.save_screenshot(str(ss_path))
                results.append(f"Screenshot: {ss_path}")
            except Exception as e:
                results.append(f"Screenshot: (failed: {e})")

        # Extract interactive elements as numbered accessibility tree
        results.append("")
        results.append("Interactive Elements:")

        # Query all interactive elements in DOM order
        interactive_selectors = [
            ("a[href]", "Link"),
            ("button", "Button"),
            ("input", "Input"),
            ("select", "Select"),
            ("textarea", "Textarea"),
            ("[role='button']", "RoleButton"),
            ("[onclick]", "Clickable"),
        ]

        elements = []
        seen_ids = set()

        for css_sel, el_type in interactive_selectors:
            try:
                found = _persistent_driver.find_elements(By.CSS_SELECTOR, css_sel)
                for el in found:
                    # Skip invisible/zero-size elements
                    try:
                        if not el.is_displayed():
                            continue
                    except:
                        continue

                    # Deduplicate by element id
                    el_id = id(el)
                    if el_id in seen_ids:
                        continue
                    seen_ids.add(el_id)

                    elements.append((el, el_type))
            except:
                continue

        if not elements:
            results.append("  (no interactive elements found)")
        else:
            for idx, (el, el_type) in enumerate(elements[:60], 1):
                try:
                    tag = el.tag_name or ""
                    name = el.get_attribute("name") or ""
                    el_id_attr = el.get_attribute("id") or ""
                    input_type = el.get_attribute("type") or ""
                    placeholder = el.get_attribute("placeholder") or ""
                    value = el.get_attribute("value") or ""
                    href = el.get_attribute("href") or ""
                    text = (el.text or "").strip()[:50]
                    aria_label = el.get_attribute("aria-label") or ""

                    # Build a human-readable description
                    display_text = text or aria_label or placeholder or value
                    
                    # Build CSS selector for targeting this element
                    if el_id_attr:
                        selector = f"#{el_id_attr}"
                    elif name:
                        selector = f"{tag}[name='{name}']"
                    else:
                        selector = f"{tag}"
                        if input_type:
                            selector += f"[type='{input_type}']"

                    # Format based on element type
                    if tag == "a":
                        href_short = href[-60:] if len(href) > 60 else href
                        results.append(f"  [{idx}] Link \"{display_text}\" → {href_short}  |  selector: {selector}")
                    elif tag == "input":
                        results.append(f"  [{idx}] Input({input_type}) name=\"{name}\" placeholder=\"{placeholder}\" value=\"{value[:20]}\"  |  selector: {selector}")
                    elif tag == "select":
                        # Get options
                        try:
                            options = el.find_elements(By.TAG_NAME, "option")
                            opt_texts = [o.text.strip()[:20] for o in options[:5]]
                            opt_str = ", ".join(opt_texts)
                        except:
                            opt_str = "..."
                        results.append(f"  [{idx}] Select name=\"{name}\" options=[{opt_str}]  |  selector: {selector}")
                    elif tag == "textarea":
                        results.append(f"  [{idx}] Textarea name=\"{name}\" placeholder=\"{placeholder}\"  |  selector: {selector}")
                    elif tag == "button":
                        results.append(f"  [{idx}] Button \"{display_text}\"  |  selector: {selector}")
                    else:
                        results.append(f"  [{idx}] {el_type} \"{display_text}\"  |  selector: {selector}")
                except Exception:
                    continue

            if len(elements) > 60:
                results.append(f"  ... and {len(elements) - 60} more elements")

        # Also show visible text summary (first 1500 chars)
        try:
            body_text = _persistent_driver.find_element(By.TAG_NAME, "body").text
            if body_text:
                results.append("")
                results.append("Visible Text (first 1500 chars):")
                results.append(body_text[:1500])
        except:
            pass

        return "\n".join(results)

    except Exception as e:
        return f"Error getting page state: {str(e)}"


@function_tool()
def browser_navigate(url: str) -> str:
    """
    Navigate the active persistent browser session to a new URL without restarting.
    Use this to move between pages while keeping cookies, session, and history.

    Args:
        url: The URL to navigate to

    Returns:
        New page title and URL after navigation
    """
    global _persistent_driver
    if _persistent_driver is None:
        return "Error: No active browser session. Run `browser_open_session(url)` first."

    try:
        _persistent_driver.get(url)
        time.sleep(3)
        return (
            f"✅ Navigated to: {_persistent_driver.current_url}\n"
            f"Title: {_persistent_driver.title}"
        )
    except Exception as e:
        return f"Error navigating to {url}: {str(e)}"


@function_tool()
def browser_scroll(direction: str = "down", amount: int = 500) -> str:
    """
    Scroll the page in the active browser session.
    Use this to reveal content below the fold or to scroll to specific areas.

    Args:
        direction: "down", "up", "bottom" (jump to bottom), "top" (jump to top)
        amount: Pixels to scroll (default 500, ignored for "top"/"bottom")

    Returns:
        Scroll result with new scroll position
    """
    global _persistent_driver
    if _persistent_driver is None:
        return "Error: No active browser session."

    try:
        if direction == "bottom":
            _persistent_driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        elif direction == "top":
            _persistent_driver.execute_script("window.scrollTo(0, 0);")
        elif direction == "up":
            _persistent_driver.execute_script(f"window.scrollBy(0, -{amount});")
        else:  # down
            _persistent_driver.execute_script(f"window.scrollBy(0, {amount});")

        time.sleep(0.5)
        scroll_pos = _persistent_driver.execute_script("return window.pageYOffset;")
        page_height = _persistent_driver.execute_script("return document.body.scrollHeight;")
        return f"✅ Scrolled {direction}. Position: {scroll_pos}px / {page_height}px total"
    except Exception as e:
        return f"Error scrolling: {str(e)}"


@function_tool()
def browser_select_option(css_selector: str, value: str = "", visible_text: str = "") -> str:
    """
    Select an option from a dropdown (<select>) element in the active browser session.
    Provide either value (the option's value attribute) or visible_text (what the user sees).

    Args:
        css_selector: CSS selector for the <select> element
        value: The value attribute of the option to select
        visible_text: The visible text of the option to select

    Returns:
        Selection result
    """
    global _persistent_driver
    if _persistent_driver is None:
        return "Error: No active browser session."

    try:
        from selenium.webdriver.support.ui import Select
        from selenium.webdriver.common.by import By

        element = _persistent_driver.find_element(By.CSS_SELECTOR, css_selector)
        select = Select(element)

        if visible_text:
            select.select_by_visible_text(visible_text)
            return f"✅ Selected '{visible_text}' in {css_selector}"
        elif value:
            select.select_by_value(value)
            return f"✅ Selected value='{value}' in {css_selector}"
        else:
            # List available options
            options = [f"  - \"{o.text}\" (value=\"{o.get_attribute('value')}\")" for o in select.options[:15]]
            return f"Available options in {css_selector}:\n" + "\n".join(options)
    except Exception as e:
        return f"Error selecting option in '{css_selector}': {str(e)}"


@function_tool()
def browser_press_key(key: str) -> str:
    """
    Press a keyboard key in the active browser session.
    Useful for submitting forms (Enter), closing dialogs (Escape), tabbing between fields, etc.

    Args:
        key: Key to press: "enter", "escape", "tab", "backspace", "space",
             "arrow_down", "arrow_up", "arrow_left", "arrow_right",
             "f5" (refresh), "delete", or any single character

    Returns:
        Key press result
    """
    global _persistent_driver
    if _persistent_driver is None:
        return "Error: No active browser session."

    try:
        from selenium.webdriver.common.keys import Keys
        from selenium.webdriver.common.by import By

        key_map = {
            "enter": Keys.ENTER, "return": Keys.RETURN,
            "escape": Keys.ESCAPE, "esc": Keys.ESCAPE,
            "tab": Keys.TAB,
            "backspace": Keys.BACKSPACE,
            "space": Keys.SPACE,
            "delete": Keys.DELETE,
            "arrow_down": Keys.ARROW_DOWN, "down": Keys.ARROW_DOWN,
            "arrow_up": Keys.ARROW_UP, "up": Keys.ARROW_UP,
            "arrow_left": Keys.ARROW_LEFT, "left": Keys.ARROW_LEFT,
            "arrow_right": Keys.ARROW_RIGHT, "right": Keys.ARROW_RIGHT,
            "f5": Keys.F5,
            "home": Keys.HOME,
            "end": Keys.END,
            "page_down": Keys.PAGE_DOWN,
            "page_up": Keys.PAGE_UP,
        }

        selenium_key = key_map.get(key.lower(), key)
        
        # Send key to the active element (or body if none focused)
        active = _persistent_driver.switch_to.active_element
        if active:
            active.send_keys(selenium_key)
        else:
            body = _persistent_driver.find_element(By.TAG_NAME, "body")
            body.send_keys(selenium_key)

        time.sleep(0.5)
        return f"✅ Pressed key: {key}. Current URL: {_persistent_driver.current_url}"
    except Exception as e:
        return f"Error pressing key '{key}': {str(e)}"


@function_tool()
def browser_wait_for(css_selector: str, timeout: int = 10, condition: str = "visible") -> str:
    """
    Wait for an element to appear/become clickable in the active browser session.
    Use after clicking buttons that trigger AJAX/dynamic content loading.

    Args:
        css_selector: CSS selector for the element to wait for
        timeout: Maximum seconds to wait (default 10)
        condition: "visible" (element appears), "clickable" (element is clickable), "gone" (element disappears)

    Returns:
        Wait result — whether the element appeared/disappeared in time
    """
    global _persistent_driver
    if _persistent_driver is None:
        return "Error: No active browser session."

    try:
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC

        wait = WebDriverWait(_persistent_driver, timeout)

        if condition == "clickable":
            element = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, css_selector)))
            return f"✅ Element '{css_selector}' is now clickable. Text: {element.text[:50]}"
        elif condition == "gone":
            wait.until(EC.invisibility_of_element_located((By.CSS_SELECTOR, css_selector)))
            return f"✅ Element '{css_selector}' has disappeared."
        else:  # visible
            element = wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, css_selector)))
            return f"✅ Element '{css_selector}' is now visible. Text: {element.text[:50]}"
    except Exception as e:
        return f"⚠️ Element '{css_selector}' did NOT appear within {timeout}s: {str(e)}"


@function_tool()
def browser_upload_file(css_selector: str, file_path: str) -> str:
    """
    Upload a file to a file input element in the active browser session.
    Use for testing file upload vulnerabilities (webshell upload, unrestricted file type, etc.)

    Args:
        css_selector: CSS selector for the <input type="file"> element
        file_path: Absolute path to the file to upload

    Returns:
        Upload result
    """
    global _persistent_driver
    if _persistent_driver is None:
        return "Error: No active browser session."

    try:
        from selenium.webdriver.common.by import By

        # File inputs don't need to be visible — send_keys works directly
        element = _persistent_driver.find_element(By.CSS_SELECTOR, css_selector)
        element.send_keys(file_path)
        time.sleep(1)
        return f"✅ File '{os.path.basename(file_path)}' attached to {css_selector}. Click submit to upload."
    except Exception as e:
        return f"Error uploading file to '{css_selector}': {str(e)}"


@function_tool()
def browser_hover(css_selector: str) -> str:
    """
    Hover over an element in the active browser session.
    Useful for revealing dropdown menus, tooltips, or hidden navigation items.

    Args:
        css_selector: CSS selector for the element to hover over

    Returns:
        Hover result
    """
    global _persistent_driver
    if _persistent_driver is None:
        return "Error: No active browser session."

    try:
        from selenium.webdriver.common.by import By
        from selenium.webdriver.common.action_chains import ActionChains

        element = _persistent_driver.find_element(By.CSS_SELECTOR, css_selector)
        ActionChains(_persistent_driver).move_to_element(element).perform()
        time.sleep(1)
        return f"✅ Hovering over '{css_selector}'. Text: {element.text[:50] if element.text else '(no text)'}"
    except Exception as e:
        return f"Error hovering over '{css_selector}': {str(e)}"


# -----------------------------------------------------------------------------
# JS CHALLENGE/BOT-DETECTION BYPASS TOOLS
# -----------------------------------------------------------------------------

# Global store for cookies obtained by solving challenges
_challenge_cookies: Dict[str, list] = {}  # domain -> list of cookie dicts


@function_tool()
def browser_solve_challenge(url: str, max_wait: int = 30, user_agent: str = "") -> str:
    """
    Solve JavaScript-based bot-detection challenges (e.g., "One moment, please...",
    Cloudflare "Checking your browser", DDoS-Guard, ImunifyAV, OpenResty challenges).

    This tool visits the URL in a real browser, waits for the JS challenge to complete
    (auto-reload, redirect, cookie set), and returns the REAL page content after the
    challenge resolves. It also stores cookies for reuse by other tools via
    `browser_get_cookies()`.

    Use this whenever you encounter:
    - "One moment, please..." / "Checking your browser..." interstitial pages
    - JavaScript auto-reload loops (setTimeout → window.location.reload)
    - Pages that only load properly in a browser (JS rendering required)

    Args:
        url: The URL with the JS challenge
        max_wait: Maximum seconds to wait for challenge resolution (default 30)
        user_agent: Custom User-Agent string (optional; uses realistic Chrome UA by default)

    Returns:
        The resolved page content (title, HTML, forms, cookies) after bypassing the challenge.
        Cookies are also stored globally for retrieval via browser_get_cookies().
    """
    results = [f"## JS Challenge Bypass: {url}\n"]

    # Realistic browser UA if none specified
    default_ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )
    ua = user_agent or default_ua

    if _check_playwright():
        return _solve_challenge_playwright(url, max_wait, ua, results)
    elif _check_selenium():
        return _solve_challenge_selenium(url, max_wait, ua, results)
    else:
        return (
            "Error: No browser automation available. "
            "Install Selenium or Playwright to solve JS challenges."
        )


def _solve_challenge_selenium(
    url: str, max_wait: int, user_agent: str, results: list
) -> str:
    """Solve JS challenge using Selenium with persistent session."""
    global _persistent_driver, _challenge_cookies

    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.common.by import By
        from urllib.parse import urlparse

        options = Options()
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1280,1024")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option("useAutomationExtension", False)
        if user_agent:
            options.add_argument(f"--user-agent={user_agent}")

        # Close existing session if any
        if _persistent_driver is not None:
            try:
                _persistent_driver.quit()
            except:
                pass

        try:
            from webdriver_manager.chrome import ChromeDriverManager
            from selenium.webdriver.chrome.service import Service

            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=options)
        except ImportError:
            driver = webdriver.Chrome(options=options)

        # Remove webdriver flag to avoid bot detection
        driver.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument",
            {
                "source": """
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                window.chrome = {runtime: {}};
            """
            },
        )

        results.append(f"🔄 Loading URL: {url}")
        driver.get(url)
        time.sleep(2)

        initial_title = driver.title
        initial_url = driver.current_url
        results.append(f"📄 Initial title: '{initial_title}'")

        # Challenge detection keywords in title or body
        challenge_keywords = [
            "one moment",
            "please wait",
            "checking your browser",
            "just a moment",
            "ddos protection",
            "security check",
            "verifying",
            "loading",
            "cloudflare",
            "imunify",
        ]

        title_lower = initial_title.lower()
        is_challenge = any(kw in title_lower for kw in challenge_keywords)

        if not is_challenge:
            # Check body text briefly
            try:
                body_text = driver.find_element(By.TAG_NAME, "body").text.lower()
                is_challenge = any(kw in body_text[:500] for kw in challenge_keywords)
            except:
                pass

        if not is_challenge:
            results.append("ℹ️ No JS challenge detected — page loaded normally.")
        else:
            results.append(f"⚡ JS challenge detected! Waiting up to {max_wait}s for resolution...")

            # Wait for the challenge to resolve by polling title/URL changes
            resolved = False
            poll_interval = 2
            waited = 0

            while waited < max_wait:
                time.sleep(poll_interval)
                waited += poll_interval

                current_title = driver.title
                current_url = driver.current_url

                # Challenge resolved if:
                # 1. Title changed from challenge title
                # 2. URL changed (redirect after challenge)
                # 3. Challenge keywords no longer in title
                title_changed = current_title.lower() != initial_title.lower()
                url_changed = current_url != initial_url
                not any(
                    kw in current_title.lower() for kw in challenge_keywords
                )

                if title_changed or url_changed:
                    results.append(
                        f"✅ Challenge resolved after {waited}s!"
                    )
                    if title_changed:
                        results.append(f"   Title: '{initial_title}' → '{current_title}'")
                    if url_changed:
                        results.append(f"   URL: {initial_url} → {current_url}")
                    resolved = True
                    # Wait a bit more for the page to fully load
                    time.sleep(3)
                    break

                results.append(f"   ⏳ {waited}s — still '{current_title}'...")

            if not resolved:
                results.append(
                    f"⚠️ Challenge did NOT resolve after {max_wait}s. "
                    f"The page may require CAPTCHA or manual interaction."
                )

        # Extract final page state
        final_title = driver.title
        final_url = driver.current_url
        cookies = driver.get_cookies()

        results.append("\n### Final Page State")
        results.append(f"**Title:** {final_title}")
        results.append(f"**URL:** {final_url}")

        # Store cookies for reuse
        domain = urlparse(url).netloc
        _challenge_cookies[domain] = cookies

        # Format cookies for curl/tool reuse
        results.append(f"\n### Cookies ({len(cookies)} total)")
        cookie_strings = []
        for c in cookies:
            cookie_strings.append(f"{c['name']}={c['value']}")
            flags = []
            if c.get("httpOnly"):
                flags.append("HttpOnly")
            if c.get("secure"):
                flags.append("Secure")
            results.append(
                f"  {c['name']}: {c['value'][:50]}{'...' if len(c['value']) > 50 else ''}"
                f" [{', '.join(flags)}]"
            )

        # Provide curl-ready cookie string
        curl_cookie_str = "; ".join(cookie_strings)
        results.append("\n### Cookie Header (for curl_request)")
        results.append("```")
        results.append(f"Cookie: {curl_cookie_str}")
        results.append("```")

        # Extract page content
        try:
            # Get visible text
            body_text = driver.find_element(By.TAG_NAME, "body").text

            results.append("\n### Page Content (first 3000 chars)")
            results.append(body_text[:3000] if body_text else "(empty body)")

            # Extract forms
            forms = driver.find_elements(By.TAG_NAME, "form")
            if forms:
                results.append(f"\n### Forms Found: {len(forms)}")
                for i, form in enumerate(forms[:5]):
                    action = form.get_attribute("action") or "(none)"
                    method = form.get_attribute("method") or "GET"
                    inputs = form.find_elements(By.CSS_SELECTOR, "input, select, textarea")
                    input_names = []
                    for inp in inputs:
                        name = inp.get_attribute("name")
                        itype = inp.get_attribute("type") or "text"
                        if name:
                            input_names.append(f"{name}({itype})")
                    results.append(f"  Form {i+1}: {method.upper()} → {action}")
                    results.append(f"    Fields: {', '.join(input_names[:10])}")

            # Detect links
            links = driver.find_elements(By.TAG_NAME, "a")
            hrefs = []
            for link in links[:30]:
                href = link.get_attribute("href")
                if href and not href.startswith("javascript:") and href != "#":
                    hrefs.append(href)
            if hrefs:
                results.append(f"\n### Links Found: {len(hrefs)}")
                for href in hrefs[:20]:
                    results.append(f"  → {href}")

        except Exception as e:
            results.append(f"\n⚠️ Error extracting content: {e}")

        # Keep the persistent driver for further interaction
        _persistent_driver = driver
        results.append(
            "\n💡 Browser session kept open. Use `browser_get_session_html()`, "
            "`browser_click_element()`, etc. for further interaction."
        )

    except Exception as e:
        results.append(f"Error: {str(e)}{_browser_dependency_hint(e)}")

    return "\n".join(results)


def _solve_challenge_playwright(
    url: str, max_wait: int, user_agent: str, results: list
) -> str:
    """Solve JS challenge using Playwright."""
    global _challenge_cookies

    try:
        from playwright.sync_api import sync_playwright
        from urllib.parse import urlparse

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            context = browser.new_context(
                user_agent=user_agent,
                viewport={"width": 1280, "height": 1024},
            )
            page = context.new_page()

            results.append(f"🔄 Loading URL: {url}")
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            time.sleep(2)

            initial_title = page.title()
            initial_url = page.url
            results.append(f"📄 Initial title: '{initial_title}'")

            challenge_keywords = [
                "one moment", "please wait", "checking your browser",
                "just a moment", "ddos protection", "security check",
                "verifying", "loading", "cloudflare", "imunify",
            ]

            title_lower = initial_title.lower()
            is_challenge = any(kw in title_lower for kw in challenge_keywords)

            if not is_challenge:
                try:
                    body_text = page.inner_text("body")[:500].lower()
                    is_challenge = any(kw in body_text for kw in challenge_keywords)
                except:
                    pass

            if is_challenge:
                results.append(f"⚡ JS challenge detected! Waiting up to {max_wait}s...")
                resolved = False
                waited = 0

                while waited < max_wait:
                    time.sleep(2)
                    waited += 2
                    current_title = page.title()

                    if current_title.lower() != initial_title.lower() or page.url != initial_url:
                        results.append(f"✅ Challenge resolved after {waited}s!")
                        resolved = True
                        time.sleep(3)
                        break
                    results.append(f"   ⏳ {waited}s — still '{current_title}'...")

                if not resolved:
                    results.append(f"⚠️ Challenge did NOT resolve after {max_wait}s.")
            else:
                results.append("ℹ️ No JS challenge detected — page loaded normally.")

            # Extract final state
            final_title = page.title()
            final_url = page.url
            cookies = context.cookies()

            domain = urlparse(url).netloc
            _challenge_cookies[domain] = [
                {"name": c["name"], "value": c["value"],
                 "httpOnly": c.get("httpOnly", False),
                 "secure": c.get("secure", False)}
                for c in cookies
            ]

            results.append("\n### Final Page State")
            results.append(f"**Title:** {final_title}")
            results.append(f"**URL:** {final_url}")

            cookie_strings = [f"{c['name']}={c['value']}" for c in cookies]
            results.append(f"\n### Cookies ({len(cookies)} total)")
            for c in cookies[:15]:
                results.append(f"  {c['name']}: {c['value'][:50]}")

            curl_cookie_str = "; ".join(cookie_strings)
            results.append("\n### Cookie Header (for curl_request)")
            results.append("```")
            results.append(f"Cookie: {curl_cookie_str}")
            results.append("```")

            try:
                body_text = page.inner_text("body")
                results.append("\n### Page Content (first 3000 chars)")
                results.append(body_text[:3000] if body_text else "(empty body)")
            except:
                pass

            browser.close()

    except Exception as e:
        results.append(f"Error: {str(e)}")

    return "\n".join(results)


@function_tool()
def browser_get_cookies(domain: str = "") -> str:
    """
    Get cookies from a previously solved JS challenge or from the active browser session.
    Returns cookies in curl-compatible format for use with curl_request headers.

    Use this AFTER running browser_solve_challenge() to get cookies that bypass
    bot-detection for use in non-browser tools (curl, feroxbuster, gospider, etc.).

    Args:
        domain: Domain to get cookies for (e.g., "dtf.in"). If empty, returns all stored cookies.

    Returns:
        Cookie strings formatted for curl -H "Cookie: ..." usage.
    """
    global _challenge_cookies, _persistent_driver

    results = ["## Stored Browser Cookies\n"]

    # Check persistent driver first
    if _persistent_driver is not None:
        try:
            driver_cookies = _persistent_driver.get_cookies()
            if driver_cookies:
                cookie_str = "; ".join(
                    f"{c['name']}={c['value']}" for c in driver_cookies
                )
                results.append("### From Active Browser Session")
                results.append(f"**Current URL:** {_persistent_driver.current_url}")
                results.append("\n**For curl_request headers parameter:**")
                results.append("```")
                results.append(f"Cookie: {cookie_str}")
                results.append("```")
                results.append(f"\n**Individual cookies ({len(driver_cookies)}):**")
                for c in driver_cookies:
                    results.append(f"  {c['name']} = {c['value'][:60]}")
                return "\n".join(results)
        except:
            pass

    # Check stored challenge cookies
    if not _challenge_cookies:
        return "No stored cookies. Run `browser_solve_challenge(url)` first to solve a JS challenge and store cookies."

    if domain:
        cookies = _challenge_cookies.get(domain, [])
        if not cookies:
            # Try partial match
            for d, c in _challenge_cookies.items():
                if domain in d or d in domain:
                    cookies = c
                    domain = d
                    break

        if not cookies:
            available = ", ".join(_challenge_cookies.keys())
            return f"No cookies stored for '{domain}'. Available domains: {available}"

        cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
        results.append(f"### Cookies for {domain}")
        results.append("\n**For curl_request headers parameter:**")
        results.append("```")
        results.append(f"Cookie: {cookie_str}")
        results.append("```")
        for c in cookies:
            results.append(f"  {c['name']} = {c['value'][:60]}")
    else:
        for d, cookies in _challenge_cookies.items():
            cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
            results.append(f"### {d} ({len(cookies)} cookies)")
            results.append("```")
            results.append(f"Cookie: {cookie_str}")
            results.append("```\n")

    return "\n".join(results)


@function_tool()
def browser_test_client_bypass(
    url: str,
    target_api_pattern: str,
    original_status: int = 401,
    new_status: int = 200,
    new_body: str = '{"success":true}',
    wait_time: int = 3,
) -> str:
    """
    Test for client-side authorization bypasses by manipulating HTTP responses.
    Intercepts a target API request (e.g. an auth check) matching the given pattern 
    and returns a spoofed response (e.g. changing 401 to 200, or {"success":false} to true).

    Args:
        url: The URL of the application to navigate to.
        target_api_pattern: URL pattern of the API request to intercept (e.g. '**/api/user/auth**').
        original_status: The status code you expect to intercept (optional context).
        new_status: The mock status code to return to the browser (default 200).
        new_body: The mock JSON body to return to the browser (e.g. '{"success":true}').
        wait_time: Time to wait after page load.
    
    Returns:
        Test results detailing intercepted requests and page DOM changes.
    """
    results = [f"## Client-Side Bypass Test: {url}\n"]
    if not _check_playwright():
        return "Error: Playwright not installed."

    try:
        from playwright.sync_api import sync_playwright

        intercepted = []

        def handle_route(route, request):
            intercepted.append(request.url)
            route.fulfill(status=new_status, body=new_body, content_type="application/json")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            context = browser.new_context()
            page = context.new_page()

            # Set up interception route
            page.route(target_api_pattern, handle_route)

            results.append(f"Navigating to {url}")
            results.append(f"Intercepting requests matching: {target_api_pattern} -> Status {new_status}")
            
            page.goto(url, wait_until="networkidle", timeout=30000)
            import time
            time.sleep(wait_time)

            results.append(f"\n### Intercepted Requests ({len(intercepted)})")
            for req_url in intercepted:
                results.append(f"  - {req_url}")

            results.append("\n### Final Page State")
            results.append(f"URL: {page.url}")
            results.append(f"Title: {page.title()}")

            # Extract basic visible text
            try:
                body_text = page.inner_text("body")[:1000]
                results.append("\n### Page Content Fragment")
                results.append(body_text if body_text else "(empty body)")
            except:
                pass

            browser.close()
    except Exception as e:
        results.append(f"Error: {str(e)}")

    return "\n".join(results)

