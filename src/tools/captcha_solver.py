"""
Captcha Solver Tool - Automates CAPTCHA bypass during authorization flows.

Resolution order (auto mode):
  1. plaintext  — fetch <captcha_url>.txt (common CTF misconfiguration)
  2. service    — use 3rd-party API (2captcha → AntiCaptcha → CapSolver)
                  Handles: reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile, image CAPTCHAs
  3. playwright — headless Chromium screenshots the captcha element with full session
                  context, then OCR runs on the clean screenshot
  4. ocr        — plain HTTP fetch of the image + Tesseract OCR with preprocessing

Set API keys in .env:
  TWOCAPTCHA_API_KEY=...
  ANTICAPTCHA_API_KEY=...
  CAPSOLVER_API_KEY=...
"""

import io
import importlib
import logging
import os
import re
import time
import urllib.parse

import requests
from src.sdk.tool import function_tool


# ── Constants ─────────────────────────────────────────────────────────────────

_UA = "Mozilla/5.0 (CyberCoPilot/1.0)"
_MAX_CAPTCHA_ATTEMPTS = 3
_SERVICE_POLL_INTERVAL = 5  # seconds between status checks
_SERVICE_TIMEOUT = 120      # max seconds to wait for a 3rd-party solve
logger = logging.getLogger(__name__)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _preprocess_and_ocr(img_bytes: bytes) -> str:
    """
    Convert raw image bytes → cleaned captcha text via Tesseract.
    Applies scale-up + binary threshold before OCR to improve accuracy.
    Tries multiple Tesseract PSM modes and returns the longest result.
    """
    try:
        pytesseract = importlib.import_module("pytesseract")
        pil_image = importlib.import_module("PIL.Image")
    except ImportError:
        return ""

    try:
        img = getattr(pil_image, "open")(io.BytesIO(img_bytes)).convert("L")
        w, h = img.size
        # Scale up 3× so Tesseract has more pixels to work with
        img = img.resize((w * 3, h * 3), getattr(pil_image, "LANCZOS", 1))
        # Binary threshold: pixels below 140 → black, rest → white
        img = img.point(lambda x: 0 if x < 140 else 255, "1").convert("L")

        whitelist = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        best = ""
        for psm in (7, 8, 6, 13):
            cfg = f"--psm {psm} --oem 3 -c tessedit_char_whitelist={whitelist}"
            text = getattr(pytesseract, "image_to_string")(img, config=cfg).strip()
            text = re.sub(r'[^A-Za-z0-9]', '', text)
            if len(text) > len(best):
                best = text
        return best
    except Exception as e:
        logger.debug(f"OCR preprocessing error: {e}")
        return ""


# ── 3rd-party CAPTCHA service helpers ─────────────────────────────────────────

def _detect_captcha_type(page_html: str, captcha_url: str) -> dict:
    """
    Autodetect the CAPTCHA type from the registration/login page HTML.

    Returns a dict with:
      type: 'recaptcha_v2' | 'recaptcha_v3' | 'hcaptcha' | 'turnstile' | 'image'
      sitekey: (for JS CAPTCHAs) the site key extracted from HTML
      action: (for reCAPTCHA v3) the action parameter
    """
    result = {"type": "image", "sitekey": "", "action": ""}

    if not page_html:
        return result

    # reCAPTCHA v2
    m = re.search(r'data-sitekey=["\']([^"\']+)["\']', page_html)
    if m and 'g-recaptcha' in page_html.lower():
        result["type"] = "recaptcha_v2"
        result["sitekey"] = m.group(1)
        return result

    # reCAPTCHA v3 (loaded via grecaptcha.execute)
    m = re.search(r'grecaptcha\.execute\s*\(\s*["\']([^"\']+)["\']', page_html)
    if m:
        result["type"] = "recaptcha_v3"
        result["sitekey"] = m.group(1)
        # Try to find action
        action_m = re.search(r"action:\s*['\"]([^'\"]+)['\"]", page_html)
        if action_m:
            result["action"] = action_m.group(1)
        return result

    # hCaptcha
    m = re.search(r'data-sitekey=["\']([^"\']+)["\']', page_html)
    if m and ('h-captcha' in page_html.lower() or 'hcaptcha' in page_html.lower()):
        result["type"] = "hcaptcha"
        result["sitekey"] = m.group(1)
        return result

    # Cloudflare Turnstile
    m = re.search(r'class=["\'][^"\']*cf-turnstile[^"\']*["\'][^>]*data-sitekey=["\']([^"\']+)["\']', page_html)
    if m:
        result["type"] = "turnstile"
        result["sitekey"] = m.group(1)
        return result
    m = re.search(r'data-sitekey=["\']([^"\']+)["\'][^>]*class=["\'][^"\']*cf-turnstile', page_html)
    if m:
        result["type"] = "turnstile"
        result["sitekey"] = m.group(1)
        return result

    return result


def _detect_captcha_field_name(page_html: str) -> str:
    """
    Auto-detect the CAPTCHA input field name from the form HTML.
    Looks for input fields near captcha images or with captcha-related names.
    Returns the field name or 'captcha' as default.
    """
    if not page_html:
        return "captcha"

    # Common CAPTCHA field name patterns
    patterns = [
        r'<input[^>]*name=["\']([^"\']*captcha[^"\']*)["\']',
        r'<input[^>]*name=["\']([^"\']*security_code[^"\']*)["\']',
        r'<input[^>]*name=["\']([^"\']*verification[^"\']*)["\']',
        r'<input[^>]*name=["\']([^"\']*verify_code[^"\']*)["\']',
        r'<input[^>]*name=["\']([^"\']*captcha_code[^"\']*)["\']',
        r'<input[^>]*name=["\']([^"\']*answer[^"\']*)["\']',
        r'<input[^>]*name=["\']([^"\']*code[^"\']*)["\']',
        r'<input[^>]*name=["\']([^"\']*g-recaptcha-response[^"\']*)["\']',
        r'<input[^>]*name=["\']([^"\']*h-captcha-response[^"\']*)["\']',
        r'<input[^>]*name=["\']([^"\']*cf-turnstile-response[^"\']*)["\']',
    ]

    for pattern in patterns:
        m = re.search(pattern, page_html, re.IGNORECASE)
        if m:
            return m.group(1)

    return "captcha"


def _solve_via_2captcha(captcha_info: dict, captcha_url: str, page_url: str,
                        img_bytes: bytes | None = None) -> str:
    """Solve CAPTCHA using 2captcha.com API."""
    api_key = os.environ.get("TWOCAPTCHA_API_KEY", "").strip()
    if not api_key:
        return ""

    try:
        base = "https://2captcha.com/in.php"
        captcha_type = captcha_info.get("type", "image")

        if captcha_type == "recaptcha_v2":
            params = {
                "key": api_key, "method": "userrecaptcha",
                "googlekey": captcha_info["sitekey"],
                "pageurl": page_url, "json": 1,
            }
            r = requests.post(base, data=params, timeout=30)
        elif captcha_type == "recaptcha_v3":
            params = {
                "key": api_key, "method": "userrecaptcha", "version": "v3",
                "googlekey": captcha_info["sitekey"],
                "pageurl": page_url, "json": 1,
                "action": captcha_info.get("action", "verify"),
                "min_score": "0.3",
            }
            r = requests.post(base, data=params, timeout=30)
        elif captcha_type == "hcaptcha":
            params = {
                "key": api_key, "method": "hcaptcha",
                "sitekey": captcha_info["sitekey"],
                "pageurl": page_url, "json": 1,
            }
            r = requests.post(base, data=params, timeout=30)
        elif captcha_type == "turnstile":
            params = {
                "key": api_key, "method": "turnstile",
                "sitekey": captcha_info["sitekey"],
                "pageurl": page_url, "json": 1,
            }
            r = requests.post(base, data=params, timeout=30)
        else:
            # Image CAPTCHA
            if not img_bytes:
                return ""
            import base64
            params = {
                "key": api_key, "method": "base64",
                "body": base64.b64encode(img_bytes).decode(),
                "json": 1,
            }
            r = requests.post(base, data=params, timeout=30)

        resp = r.json()
        if resp.get("status") != 1:
            logger.debug(f"2captcha submit error: {resp}")
            return ""

        task_id = resp["request"]

        # Poll for result
        for _ in range(int(_SERVICE_TIMEOUT / _SERVICE_POLL_INTERVAL)):
            time.sleep(_SERVICE_POLL_INTERVAL)
            check = requests.get(
                "https://2captcha.com/res.php",
                params={"key": api_key, "action": "get", "id": task_id, "json": 1},
                timeout=15,
            ).json()
            if check.get("status") == 1:
                return check["request"]
            if check.get("request") == "ERROR_CAPTCHA_UNSOLVABLE":
                return ""

        return ""
    except Exception as e:
        logger.debug(f"2captcha error: {e}")
        return ""


def _solve_via_anticaptcha(captcha_info: dict, captcha_url: str, page_url: str,
                           img_bytes: bytes | None = None) -> str:
    """Solve CAPTCHA using anti-captcha.com API."""
    api_key = os.environ.get("ANTICAPTCHA_API_KEY", "").strip()
    if not api_key:
        return ""

    try:
        captcha_type = captcha_info.get("type", "image")
        task = {}

        if captcha_type == "recaptcha_v2":
            task = {
                "type": "RecaptchaV2TaskProxyless",
                "websiteURL": page_url,
                "websiteKey": captcha_info["sitekey"],
            }
        elif captcha_type == "recaptcha_v3":
            task = {
                "type": "RecaptchaV3TaskProxyless",
                "websiteURL": page_url,
                "websiteKey": captcha_info["sitekey"],
                "minScore": 0.3,
                "pageAction": captcha_info.get("action", "verify"),
            }
        elif captcha_type == "hcaptcha":
            task = {
                "type": "HCaptchaTaskProxyless",
                "websiteURL": page_url,
                "websiteKey": captcha_info["sitekey"],
            }
        elif captcha_type == "turnstile":
            task = {
                "type": "TurnstileTaskProxyless",
                "websiteURL": page_url,
                "websiteKey": captcha_info["sitekey"],
            }
        else:
            if not img_bytes:
                return ""
            import base64
            task = {
                "type": "ImageToTextTask",
                "body": base64.b64encode(img_bytes).decode(),
            }

        r = requests.post(
            "https://api.anti-captcha.com/createTask",
            json={"clientKey": api_key, "task": task},
            timeout=30,
        ).json()

        if r.get("errorId", 1) != 0:
            logger.debug(f"AntiCaptcha submit error: {r}")
            return ""

        task_id = r["taskId"]

        for _ in range(int(_SERVICE_TIMEOUT / _SERVICE_POLL_INTERVAL)):
            time.sleep(_SERVICE_POLL_INTERVAL)
            check = requests.post(
                "https://api.anti-captcha.com/getTaskResult",
                json={"clientKey": api_key, "taskId": task_id},
                timeout=15,
            ).json()
            if check.get("status") == "ready":
                sol = check.get("solution", {})
                return (
                    sol.get("gRecaptchaResponse")
                    or sol.get("token")
                    or sol.get("text")
                    or ""
                )
            if check.get("errorId", 0) != 0:
                return ""

        return ""
    except Exception as e:
        logger.debug(f"AntiCaptcha error: {e}")
        return ""


def _solve_via_capsolver(captcha_info: dict, captcha_url: str, page_url: str,
                         img_bytes: bytes | None = None) -> str:
    """Solve CAPTCHA using capsolver.com API."""
    api_key = os.environ.get("CAPSOLVER_API_KEY", "").strip()
    if not api_key:
        return ""

    try:
        captcha_type = captcha_info.get("type", "image")
        task = {}

        if captcha_type == "recaptcha_v2":
            task = {
                "type": "ReCaptchaV2TaskProxyLess",
                "websiteURL": page_url,
                "websiteKey": captcha_info["sitekey"],
            }
        elif captcha_type == "recaptcha_v3":
            task = {
                "type": "ReCaptchaV3TaskProxyLess",
                "websiteURL": page_url,
                "websiteKey": captcha_info["sitekey"],
                "pageAction": captcha_info.get("action", "verify"),
            }
        elif captcha_type == "hcaptcha":
            task = {
                "type": "HCaptchaTaskProxyLess",
                "websiteURL": page_url,
                "websiteKey": captcha_info["sitekey"],
            }
        elif captcha_type == "turnstile":
            task = {
                "type": "AntiTurnstileTaskProxyLess",
                "websiteURL": page_url,
                "websiteKey": captcha_info["sitekey"],
            }
        else:
            if not img_bytes:
                return ""
            import base64
            task = {
                "type": "ImageToTextTask",
                "body": base64.b64encode(img_bytes).decode(),
            }

        r = requests.post(
            "https://api.capsolver.com/createTask",
            json={"clientKey": api_key, "task": task},
            timeout=30,
        ).json()

        if r.get("errorId", 1) != 0:
            logger.debug(f"CapSolver submit error: {r}")
            return ""

        task_id = r.get("taskId", "")
        if not task_id:
            # CapSolver sometimes returns solution immediately
            sol = r.get("solution", {})
            return (
                sol.get("gRecaptchaResponse")
                or sol.get("token")
                or sol.get("text")
                or ""
            )

        for _ in range(int(_SERVICE_TIMEOUT / _SERVICE_POLL_INTERVAL)):
            time.sleep(_SERVICE_POLL_INTERVAL)
            check = requests.post(
                "https://api.capsolver.com/getTaskResult",
                json={"clientKey": api_key, "taskId": task_id},
                timeout=15,
            ).json()
            if check.get("status") == "ready":
                sol = check.get("solution", {})
                return (
                    sol.get("gRecaptchaResponse")
                    or sol.get("token")
                    or sol.get("text")
                    or ""
                )
            if check.get("errorId", 0) != 0:
                return ""

        return ""
    except Exception as e:
        logger.debug(f"CapSolver error: {e}")
        return ""


def _solve_via_service(captcha_info: dict, captcha_url: str, page_url: str,
                       img_bytes: bytes | None = None) -> tuple[str, str]:
    """
    Try all configured 3rd-party CAPTCHA services in order.
    Returns (solved_text, service_name) or ("", "").
    """
    for solver, name in [
        (_solve_via_2captcha, "2captcha"),
        (_solve_via_anticaptcha, "AntiCaptcha"),
        (_solve_via_capsolver, "CapSolver"),
    ]:
        result = solver(captcha_info, captcha_url, page_url, img_bytes)
        if result:
            return result, name
    return "", ""


def _solve_via_playwright(captcha_url: str, cookies_dict: dict, page_url: str = "") -> str:
    """
    Use a headless Playwright browser to screenshot the captcha and OCR it.

    If `page_url` is provided the browser navigates there first (so the server
    sets the proper session cookie), then locates the <img src="*captcha*"> element
    and screenshots just that element.  Otherwise it navigates directly to
    `captcha_url` and screenshots the whole page.

    Returns the solved text, or "" on any failure.
    """
    try:
        sync_playwright = getattr(importlib.import_module("playwright.sync_api"), "sync_playwright")
    except ImportError:
        return ""

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()

            # Inject cookies so the server honours the existing session
            if cookies_dict and captcha_url.startswith("http"):
                parsed = urllib.parse.urlparse(captcha_url)
                domain = parsed.netloc
                context.add_cookies([
                    {"name": k, "value": v, "domain": domain, "path": "/"}
                    for k, v in cookies_dict.items()
                ])

            page = context.new_page()

            if page_url:
                # Navigate to the page that contains the captcha image so the
                # server can renew the session and the <img> is rendered in context.
                page.goto(page_url, wait_until="networkidle", timeout=30000)
                # Wait for the captcha <img> to appear and its src to be set
                try:
                    page.wait_for_selector("img[src*='captcha']", timeout=8000)
                except Exception:
                    pass
                captcha_el = page.query_selector("img[src*='captcha']")
                if captcha_el:
                    # Scroll element into view and wait for it to be fully loaded
                    captcha_el.scroll_into_view_if_needed()
                    page.wait_for_load_state("networkidle", timeout=5000)
                    img_bytes = captcha_el.screenshot()
                else:
                    # Fallback: screenshot the full viewport
                    img_bytes = page.screenshot(full_page=False)
            else:
                # Navigate directly to the captcha image URL and screenshot the <img> tag
                page.goto(captcha_url, wait_until="load", timeout=15000)
                page.wait_for_load_state("networkidle", timeout=5000)
                img_el = page.query_selector("img")
                img_bytes = img_el.screenshot() if img_el else page.screenshot(full_page=False)

            browser.close()

        return _preprocess_and_ocr(img_bytes or b"")

    except Exception as e:
        logger.debug(f"Playwright captcha solve failed: {e}")
        return ""


def _solve_via_ocr(captcha_url: str, cookies_dict: dict, headers: dict) -> str:
    """
    Fetch the captcha image via requests and OCR it with preprocessing.
    Returns solved text or "" on failure.
    """
    try:
        r = requests.get(captcha_url, headers=headers, cookies=cookies_dict, timeout=15)
        if r.status_code != 200:
            return ""
        return _preprocess_and_ocr(r.content)
    except Exception as e:
        logger.debug(f"HTTP OCR captcha solve failed: {e}")
        return ""


def _fetch_captcha_image(captcha_url: str, cookies_dict: dict, headers: dict) -> bytes:
    """Fetch raw captcha image bytes for 3rd-party service submission."""
    try:
        r = requests.get(captcha_url, headers=headers, cookies=cookies_dict, timeout=15)
        if r.status_code == 200 and len(r.content) > 100:
            return r.content
    except Exception:
        pass
    return b""


def _has_any_service_key() -> bool:
    """Return True if at least one 3rd-party CAPTCHA API key is configured."""
    return bool(
        os.environ.get("TWOCAPTCHA_API_KEY", "").strip()
        or os.environ.get("ANTICAPTCHA_API_KEY", "").strip()
        or os.environ.get("CAPSOLVER_API_KEY", "").strip()
    )


# ── Public tool ───────────────────────────────────────────────────────────────

@function_tool()
def solve_captcha(
    captcha_url: str,
    extraction_method: str = "auto",
    cookies_string: str = "",
    page_url: str = "",
    page_html: str = "",
) -> str:
    """
    Attempt to solve a CAPTCHA at the given URL.

    Resolution order (when extraction_method='auto'):
      1. plaintext  — try fetching <captcha_url>.txt (common CTF misconfiguration)
      2. service    — use 3rd-party API (2captcha → AntiCaptcha → CapSolver)
                      Auto-detects reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile, or image CAPTCHAs
      3. playwright — headless Chromium screenshots the captcha element + OCR
      4. ocr        — plain HTTP fetch of the image + Tesseract with preprocessing

    Args:
        captcha_url: URL of the captcha image endpoint (e.g. http://target.com/captcha?len=5).
                     For JS CAPTCHAs (reCAPTCHA etc.) this can be the page URL itself.
        extraction_method: 'auto' | 'plaintext' | 'service' | 'playwright' | 'ocr'  (default: 'auto')
        cookies_string: Session cookies as "name=value; name2=value2".
        page_url: Optional — the page that *contains* the captcha <img> (e.g.
                  http://target.com/register).  When provided, Playwright navigates
                  here first so the server sets/renews session cookies.
        page_html: Optional — the raw HTML of the page containing the CAPTCHA.
                   Used to auto-detect the CAPTCHA type (reCAPTCHA, hCaptcha, Turnstile)
                   and the form field name. If not provided, will be fetched automatically.

    Returns:
        Solver output.  On success always contains the line:
            "  [+] CAPTCHA Value: <text>"
        so callers can extract it with: re.search(r"CAPTCHA Value:\\s*(.+)", output)

        Also includes:
            "  [+] CAPTCHA Field: <field_name>"
        so callers know which form field to populate.
    """
    out = [f"=== Captcha Solver: {captcha_url}"]

    headers = {"User-Agent": _UA}
    cookies_dict = {}
    if cookies_string:
        for part in cookies_string.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies_dict[k.strip()] = v.strip()

    method = extraction_method.lower()

    # ── Fetch page HTML if not provided (needed for detection) ────────────────
    if not page_html and page_url:
        try:
            r = requests.get(page_url, headers=headers, cookies=cookies_dict, timeout=15)
            if r.status_code == 200:
                page_html = r.text
        except Exception:
            pass

    # ── Detect CAPTCHA type and field name ────────────────────────────────────
    captcha_info = _detect_captcha_type(page_html, captcha_url)
    captcha_field = _detect_captcha_field_name(page_html)

    if captcha_info["type"] != "image":
        out.append(f"  [*] Detected CAPTCHA type: {captcha_info['type']}")
        out.append(f"  [*] Site key: {captcha_info['sitekey'][:30]}...")
    out.append(f"  [+] CAPTCHA Field: {captcha_field}")

    actual_page_url = page_url or captcha_url

    # ── 1. Plaintext bypass ───────────────────────────────────────────────────
    if method in ("auto", "plaintext") and captcha_info["type"] == "image":
        base = captcha_url.split("?")[0]
        txt_url = base if base.endswith(".txt") else base + ".txt"
        try:
            r = requests.get(txt_url, headers=headers, cookies=cookies_dict, timeout=10)
            body = r.text.strip()
            if r.status_code == 200 and body and len(body) < 50:
                out.append(f"  [+] Found plaintext captcha leak at {txt_url}!")
                out.append(f"  [+] CAPTCHA Value: {body}")
                return "\n".join(out)
            else:
                out.append(f"  [-] No plaintext leak found at {txt_url}.")
        except Exception as e:
            out.append(f"  [-] Plaintext check error: {e}")

        if method == "plaintext":
            return "\n".join(out)

    # ── 2. 3rd-party CAPTCHA service ──────────────────────────────────────────
    if method in ("auto", "service"):
        if _has_any_service_key():
            out.append("  [*] Attempting 3rd-party CAPTCHA service...")

            # For image CAPTCHAs, fetch the image bytes first
            img_bytes = None
            if captcha_info["type"] == "image":
                img_bytes = _fetch_captcha_image(captcha_url, cookies_dict, headers)
                if not img_bytes:
                    out.append("  [-] Could not fetch captcha image for service submission.")
                else:
                    out.append(f"  [*] Fetched captcha image ({len(img_bytes)} bytes)")

            solved, service_name = _solve_via_service(
                captcha_info, captcha_url, actual_page_url, img_bytes
            )
            if solved:
                out.append(f"  [+] Solved by {service_name}!")
                out.append(f"  [+] CAPTCHA Value: {solved}")
                return "\n".join(out)
            else:
                out.append("  [-] All configured CAPTCHA services failed or returned no result.")
        else:
            out.append("  [-] No CAPTCHA service API keys configured in .env")
            if captcha_info["type"] != "image":
                out.append(f"  [!] This is a {captcha_info['type']} CAPTCHA — requires a solving service.")
                out.append("  [!] Set TWOCAPTCHA_API_KEY, ANTICAPTCHA_API_KEY, or CAPSOLVER_API_KEY in .env")
                out.append("  [BAIL] CAPTCHA cannot be solved automatically without a service API key.")
                out.append("  [BAIL] Alternative: Skip registration and try other attack paths (default creds, SQLi bypass, password reset flow).")
                return "\n".join(out)

        if method == "service":
            return "\n".join(out)

    # ── 3. Playwright screenshot + OCR (image CAPTCHAs only) ──────────────────
    if method in ("auto", "playwright") and captcha_info["type"] == "image":
        out.append("  [*] Attempting Playwright screenshot + OCR...")
        text = _solve_via_playwright(captcha_url, cookies_dict, page_url=page_url)
        if text:
            out.append("  [+] Playwright OCR Successful!")
            out.append(f"  [+] CAPTCHA Value: {text}")
            return "\n".join(out)
        else:
            out.append("  [-] Playwright OCR failed (Playwright not installed or no result).")

        if method == "playwright":
            return "\n".join(out)

    # ── 4. Plain HTTP fetch + OCR (image CAPTCHAs only) ───────────────────────
    if method in ("auto", "ocr") and captcha_info["type"] == "image":
        out.append("  [*] Attempting HTTP fetch + Tesseract OCR...")
        try:
            importlib.import_module("pytesseract")
        except ImportError:
            out.append("  [!] pytesseract not installed. Run: pip install pytesseract Pillow")
            out.append("  [BAIL] CAPTCHA cannot be solved — install tesseract or configure a service API key.")
            return "\n".join(out)

        text = _solve_via_ocr(captcha_url, cookies_dict, headers)
        if text:
            out.append("  [+] OCR Successful!")
            out.append(f"  [+] CAPTCHA Value: {text}")
            return "\n".join(out)
        else:
            out.append("  [-] OCR failed to extract any characters.")

    # ── No method succeeded ───────────────────────────────────────────────────
    out.append("")
    out.append("  [BAIL] All CAPTCHA solving methods failed.")
    out.append("  [BAIL] Recommendations:")
    out.append("    1. Configure a CAPTCHA service: set TWOCAPTCHA_API_KEY in .env")
    out.append("    2. Skip registration and try: default credentials, SQLi auth bypass,")
    out.append("       password reset flow, or other entry points.")
    out.append("  Note: Do NOT retry registration — CAPTCHA will regenerate and fail again.")

    return "\n".join(out)
