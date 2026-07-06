"""
Bug Bounty Report Formatter — HackerOne & Bugcrowd Submission-Ready Output

Converts confirmed findings + evidence into professional, submission-ready reports
formatted exactly to HackerOne and Bugcrowd's expectations. Also computes proper
CVSS 3.1 vector strings and generates self-contained PoC curl commands.

Usage:
    from src.sdk.bb_report_formatter import get_formatter

    formatter = get_formatter()

    # Build a report for one finding
    report = formatter.format_finding(
        title="SSRF to AWS Cloud Metadata",
        vulnerability_type="ssrf",
        severity="critical",
        endpoint="https://target.com/api/fetch?url=",
        parameter="url",
        steps_to_reproduce=[
            "Navigate to https://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/",
            "Observe the response contains IAM role names",
            "Fetch https://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME",
            "Observe AWS STS credentials in the response",
        ],
        expected_result="The server should reject internal IP addresses",
        actual_result="The server fetches and returns the AWS IMDS response containing IAM credentials",
        poc_request="curl 'https://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/' -H 'Authorization: Bearer YOUR_TOKEN'",
        impact="An attacker can retrieve AWS IAM role credentials and assume the role, gaining full access to all AWS services the role can access including S3 buckets, EC2 instances, and RDS databases.",
        remediation="Implement a strict allowlist of permitted external domains. Block all requests to RFC1918 private addresses, 169.254.x.x (link-local), and 127.x.x.x (loopback) at the DNS resolution level.",
        evidence="HTTP/1.1 200 OK\\n{\\\"role\\\": \\\"ec2-prod-role\\\", \\\"SecretAccessKey\\\": \\\"xxxx\\\"}",
        platform="hackerone",
    )
    print(report)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from loguru import logger


# ─────────────────────────────────────────────────────────────────────────────
# CVSS 3.1 Calculator
# ─────────────────────────────────────────────────────────────────────────────

# CVSS 3.1 lookup tables
_CVSS_TABLES = {
    # Attack Vector: AV
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    # Attack Complexity: AC
    "AC": {"L": 0.77, "H": 0.44},
    # Privileges Required: PR (scope unchanged)
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},
    # Privileges Required: PR (scope changed)
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.50},
    # User Interaction: UI
    "UI": {"N": 0.85, "R": 0.62},
    # CIA impact
    "C": {"N": 0.00, "L": 0.22, "H": 0.56},
    "I": {"N": 0.00, "L": 0.22, "H": 0.56},
    "A": {"N": 0.00, "L": 0.22, "H": 0.56},
}


@dataclass
class CVSSVector:
    """CVSS 3.1 Base Score parameters."""
    av: str = "N"   # Attack Vector: N/A/L/P
    ac: str = "L"   # Attack Complexity: L/H
    pr: str = "N"   # Privileges Required: N/L/H
    ui: str = "N"   # User Interaction: N/R
    s: str = "U"    # Scope: U/C
    c: str = "H"    # Confidentiality: N/L/H
    i: str = "H"    # Integrity: N/L/H
    a: str = "N"    # Availability: N/L/H

    @property
    def vector_string(self) -> str:
        return f"CVSS:3.1/AV:{self.av}/AC:{self.ac}/PR:{self.pr}/UI:{self.ui}/S:{self.s}/C:{self.c}/I:{self.i}/A:{self.a}"

    @property
    def score(self) -> float:
        """Calculate CVSS 3.1 Base Score."""
        av = _CVSS_TABLES["AV"][self.av]
        ac = _CVSS_TABLES["AC"][self.ac]
        pr_table = "PR_C" if self.s == "C" else "PR_U"
        pr = _CVSS_TABLES[pr_table][self.pr]
        ui = _CVSS_TABLES["UI"][self.ui]

        c = _CVSS_TABLES["C"][self.c]
        i = _CVSS_TABLES["I"][self.i]
        a = _CVSS_TABLES["A"][self.a]

        # ISC sub
        iss = 1 - (1 - c) * (1 - i) * (1 - a)

        if self.s == "U":
            isc = 6.42 * iss
        else:
            isc = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

        if isc <= 0:
            return 0.0

        # Exploitability sub
        esc = 8.22 * av * ac * pr * ui

        if self.s == "U":
            base = min(isc + esc, 10)
        else:
            base = min(1.08 * (isc + esc), 10)

        # Round up to nearest 0.1
        import math
        return math.ceil(base * 10) / 10

    @property
    def severity_label(self) -> str:
        s = self.score
        if s >= 9.0:
            return "Critical"
        elif s >= 7.0:
            return "High"
        elif s >= 4.0:
            return "Medium"
        elif s > 0:
            return "Low"
        return "None"


# ─────────────────────────────────────────────────────────────────────────────
# Pre-defined CVSS vectors for common vulnerability types
# ─────────────────────────────────────────────────────────────────────────────

_VULN_CVSS_DEFAULTS: dict[str, CVSSVector] = {
    "ssrf_cloud": CVSSVector(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="N"),   # 10.0
    "ssrf_blind": CVSSVector(av="N", ac="L", pr="L", ui="N", s="C", c="L", i="N", a="N"),   # 5.0
    "ssrf": CVSSVector(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="L", a="N"),          # 9.3
    "rce": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),           # 9.8
    "sql_injection": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"), # 9.8
    "sqli": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),          # 9.8
    "stored_xss_admin": CVSSVector(av="N", ac="L", pr="L", ui="N", s="C", c="H", i="H", a="N"), # 9.0
    "stored_xss": CVSSVector(av="N", ac="L", pr="L", ui="R", s="C", c="L", i="L", a="N"),   # 5.4
    "reflected_xss": CVSSVector(av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"), # 6.1
    "xss": CVSSVector(av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"),           # 6.1
    "idor_write": CVSSVector(av="N", ac="L", pr="L", ui="N", s="U", c="H", i="H", a="N"),   # 8.1
    "idor_read": CVSSVector(av="N", ac="L", pr="L", ui="N", s="U", c="H", i="N", a="N"),    # 6.5
    "idor": CVSSVector(av="N", ac="L", pr="L", ui="N", s="U", c="H", i="N", a="N"),          # 6.5
    "bola": CVSSVector(av="N", ac="L", pr="L", ui="N", s="U", c="H", i="N", a="N"),          # 6.5
    "mass_assignment_admin": CVSSVector(av="N", ac="L", pr="L", ui="N", s="U", c="H", i="H", a="H"),  # 8.8
    "mass_assignment": CVSSVector(av="N", ac="L", pr="L", ui="N", s="U", c="L", i="H", a="N"), # 7.1
    "jwt_bypass": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),   # 9.1
    "jwt": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),           # 9.1
    "cors": CVSSVector(av="N", ac="L", pr="N", ui="R", s="U", c="H", i="N", a="N"),          # 6.5
    "open_redirect": CVSSVector(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="L", a="N"), # 6.1
    "password_reset_poisoning": CVSSVector(av="N", ac="L", pr="N", ui="R", s="U", c="H", i="H", a="N"), # 8.1
    "race_condition_payment": CVSSVector(av="N", ac="H", pr="L", ui="N", s="U", c="N", i="H", a="N"),  # 5.3
    "race_condition": CVSSVector(av="N", ac="H", pr="L", ui="N", s="U", c="N", i="H", a="N"),           # 5.3
    "path_traversal_cred": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"),    # 7.5
    "path_traversal": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"),          # 7.5
    "ssti": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),           # 9.8
    "xxe_blind": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"),     # 7.5
    "xxe": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="L", a="N"),            # 8.2
    "csrf": CVSSVector(av="N", ac="L", pr="N", ui="R", s="U", c="N", i="H", a="N"),           # 6.5
    "http_smuggling": CVSSVector(av="N", ac="H", pr="N", ui="N", s="C", c="H", i="H", a="N"), # 8.7
    "subdomain_takeover": CVSSVector(av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"), # 6.1
    "info_disclosure_cred": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"), # 9.8
    "info_disclosure": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"), # 7.5
    "business_logic": CVSSVector(av="N", ac="L", pr="L", ui="N", s="U", c="N", i="H", a="N"), # 6.5
    "prototype_pollution": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="H", a="N"), # 8.2
    "deserialization": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"), # 9.8
    "crlf": CVSSVector(av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"),           # 6.1
    "default": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="L", a="N"),         # 6.5
}


def resolve_cvss(vulnerability_type: str, provided_cvss: Optional[CVSSVector] = None) -> CVSSVector:
    """Return the best CVSS vector for a given vuln type."""
    if provided_cvss:
        return provided_cvss
    vt = vulnerability_type.lower().replace(" ", "_").replace("-", "_")
    # Try longest match first
    for key in sorted(_VULN_CVSS_DEFAULTS, key=len, reverse=True):
        if key in vt:
            return _VULN_CVSS_DEFAULTS[key]
    return _VULN_CVSS_DEFAULTS["default"]


# ─────────────────────────────────────────────────────────────────────────────
# Impact templates by severity
# ─────────────────────────────────────────────────────────────────────────────

_IMPACT_PREFIXES: dict[str, str] = {
    "critical": (
        "An unauthenticated attacker can fully compromise "
    ),
    "high": (
        "An attacker with a standard user account can "
    ),
    "medium": (
        "An attacker can "
    ),
    "low": (
        "A limited-scope attacker can "
    ),
}

# Vulnerability type → impact narrative template
_IMPACT_NARRATIVES: dict[str, str] = {
    "ssrf": (
        "make the server issue requests to internal services, including cloud instance metadata "
        "(169.254.169.254). This exposes AWS/GCP/Azure IAM credentials, enabling full cloud "
        "account takeover, data exfiltration from S3/databases, and lateral movement to internal services."
    ),
    "sql_injection": (
        "extract the entire database contents including all user passwords (hashed or plaintext), "
        "PII, payment information, and application secrets. Depending on database privileges, "
        "this may also allow reading local files or executing OS commands."
    ),
    "rce": (
        "execute arbitrary OS commands on the server as the application user. This enables "
        "reading all application secrets and database credentials, pivoting to internal "
        "services, and establishing persistent access."
    ),
    "idor": (
        "read or modify data belonging to any other user on the platform without their "
        "knowledge. This includes personal information, private messages, financial records, "
        "and account credentials."
    ),
    "stored_xss": (
        "execute JavaScript in the browser of every user who views the affected page. "
        "This enables stealing session cookies, accessing localStorage tokens, performing "
        "actions on behalf of the user, and spreading the attack to admin users."
    ),
    "reflected_xss": (
        "execute JavaScript in the victim's browser when they click a crafted link. "
        "This enables session hijacking, credential theft, and performing arbitrary "
        "actions on behalf of the victim."
    ),
    "jwt": (
        "forge valid authentication tokens for any user on the platform, including administrators, "
        "without knowing their credentials. The attacker gains full, persistent access to all "
        "accounts."
    ),
    "mass_assignment": (
        "set protected fields (role, admin status, subscription tier) during account creation "
        "or profile updates, granting themselves administrative privileges or premium access "
        "without authorization."
    ),
    "race_condition": (
        "trigger a state-changing action multiple times in a single logical operation — "
        "for example, spending a coupon more than once, double-spending credits, or "
        "obtaining paid features for free."
    ),
    "cors": (
        "make credentialed cross-origin requests from any attacker-controlled website, "
        "reading sensitive authenticated API responses (profile data, tokens, payment info) "
        "and performing authenticated actions on behalf of any user who visits the attacker's site."
    ),
    "path_traversal": (
        "read arbitrary files from the server filesystem, including application configuration "
        "files containing database credentials, API keys, private SSH keys, and user data "
        "outside the web root."
    ),
    "ssti": (
        "execute arbitrary code in the template engine context, which typically leads to "
        "full OS command execution. This exposes all server data, credentials, and enables "
        "persistent backdoor installation."
    ),
    "business_logic": (
        "bypass intended business constraints — for example, purchasing items at zero or "
        "negative cost, accessing premium features without payment, or repeatedly using "
        "single-use resources."
    ),
    "http_smuggling": (
        "poison the HTTP request pipeline, causing the backend server to interpret "
        "attacker-controlled prefix data as belonging to the next user's request. "
        "This enables session hijacking, WAF bypass, and cache poisoning."
    ),
    "open_redirect": (
        "redirect users from a trusted domain to an attacker-controlled site. "
        "When chained with OAuth, this enables stealing authorization codes and tokens, "
        "leading to account takeover without the user's password."
    ),
    "info_disclosure": (
        "access sensitive application data such as API keys, database credentials, "
        "internal hostnames, or user PII that should not be publicly accessible. "
        "Active credentials found during this test were confirmed to provide access to backend systems."
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Remediation templates
# ─────────────────────────────────────────────────────────────────────────────

_REMEDIATIONS: dict[str, str] = {
    "ssrf": (
        "1. Implement an allowlist of permitted external domains — reject all other destinations at the application layer. "
        "2. Block requests to RFC1918 private ranges (10.x, 172.16.x, 192.168.x), link-local (169.254.x.x), and loopback (127.x.x.x) at DNS resolution time. "
        "3. Disable support for non-HTTP(S) protocols (gopher://, file://, dict://). "
        "4. Enable IMDSv2 (token-required) on AWS EC2 instances to limit IMDS access to processes with a valid token."
    ),
    "sql_injection": (
        "1. Use parameterized queries (prepared statements) for all database interactions — never interpolate user input into query strings. "
        "2. Apply input validation and reject characters not required for the field's purpose. "
        "3. Run the database user with minimum required privileges (no FILE, no EXECUTE, no CREATE). "
        "4. Enable WAF rules for SQL injection patterns as a defense-in-depth measure."
    ),
    "idor": (
        "1. Implement authorization checks on the server side for every object access request — verify the requesting user owns or has permission for the requested object ID. "
        "2. Do not rely on object IDs being unguessable as a security control. "
        "3. Use indirect references (map session-specific tokens to actual IDs server-side) for sensitive objects. "
        "4. Add automated tests that verify cross-user object access is rejected."
    ),
    "stored_xss": (
        "1. Apply context-sensitive output encoding for all user-supplied content. "
        "2. Implement a strict Content-Security-Policy that prevents inline script execution and restricts script sources to known-safe origins. "
        "3. Mark all session cookies with HttpOnly and Secure flags. "
        "4. Apply input validation to reject HTML tags in fields that do not require markup."
    ),
    "reflected_xss": (
        "1. Apply HTML entity encoding to all user-supplied input before reflecting it in HTML responses. "
        "2. Implement a Content-Security-Policy header that prevents inline script execution. "
        "3. Use the X-XSS-Protection: 1; mode=block header as a defense-in-depth measure for older browsers."
    ),
    "jwt": (
        "1. Explicitly validate the 'alg' header field — reject tokens with alg:none or unexpected algorithms. "
        "2. For RS256: never use the public key as an HMAC secret. Keep private key strictly server-side. "
        "3. Validate the 'jku'/'x5u' header against a strict allowlist — reject any URL not pre-approved. "
        "4. Use a strong, randomly generated secret (minimum 256 bits) for HS256 tokens. "
        "5. Implement short token expiry and refresh token rotation."
    ),
    "mass_assignment": (
        "1. Explicitly define which fields are allowed in each API request (allowlist approach). "
        "2. Never bind raw request bodies directly to model objects — use Data Transfer Objects (DTOs) with explicit field mappings. "
        "3. In Rails: use strong_params with explicit permit() lists. In Laravel: use $fillable instead of $guarded. "
        "4. Add integration tests that verify sensitive fields (role, admin, premium) cannot be set via API."
    ),
    "race_condition": (
        "1. Implement database-level locking (SELECT FOR UPDATE, atomic transactions) for all state-changing operations. "
        "2. Use idempotency keys to detect and reject duplicate requests. "
        "3. Move coupon/credit validation and redemption into a single atomic database transaction. "
        "4. Implement server-side rate limiting that operates at the session level, not just IP level."
    ),
    "cors": (
        "1. Set a strict Access-Control-Allow-Origin header — specify the exact allowed origins rather than reflecting the request's Origin header. "
        "2. Only set Access-Control-Allow-Credentials: true for endpoints that genuinely require cross-origin credentialed access. "
        "3. Audit all API endpoints for CORS configuration — apply the most restrictive policy for sensitive endpoints (authentication, payment, profile)."
    ),
    "path_traversal": (
        "1. Use chrooted file system access or an abstraction layer that constrains file access to a permitted directory. "
        "2. Validate and normalize file paths — reject any path containing '../', './', or URL-encoded equivalents before processing. "
        "3. Never accept file paths directly from user input — use a file ID that maps to a server-side path. "
        "4. Serve static files through a dedicated file server (nginx) that only has access to the public directory."
    ),
    "ssti": (
        "1. Never pass user-supplied data directly to template rendering functions. "
        "2. Use a sandboxed template environment that disables access to Python/Java internals. "
        "3. Apply strict input validation and reject template syntax characters ({{, }}, ${, <%>) in user inputs. "
        "4. Use template rendering in a restricted subprocess with no access to file system or OS modules."
    ),
    "business_logic": (
        "1. Validate all financial values server-side — reject negative quantities, zero prices, and currencies that differ from the session's expected currency. "
        "2. Re-validate pricing from the server's own price table at checkout time — never trust client-supplied prices. "
        "3. Apply idempotency controls on single-use operations (coupons, free trials, upgrades). "
        "4. Implement rate limiting on state-changing financial operations."
    ),
    "http_smuggling": (
        "1. Ensure consistency in how the front-end and back-end servers parse Transfer-Encoding and Content-Length headers. "
        "2. Upgrade to HTTP/2 end-to-end where possible — HTTP/2 is not susceptible to classic smuggling. "
        "3. Disable HTTP/1.1 keep-alive between the reverse proxy and backend. "
        "4. Normalize ambiguous chunked encoding at the edge before forwarding requests to the backend."
    ),
    "default": (
        "1. Apply the principle of least privilege — ensure the affected component only has access required for its function. "
        "2. Implement server-side input validation and output encoding appropriate to the context. "
        "3. Conduct a security review of similar patterns in the codebase. "
        "4. Add regression tests that confirm the vulnerability is fixed and does not re-emerge."
    ),
}


def _resolve_impact(vuln_type: str, severity: str, custom_impact: str = "") -> str:
    if custom_impact:
        return custom_impact
    prefix = _IMPACT_PREFIXES.get(severity.lower(), "An attacker can ")
    vt = vuln_type.lower().replace(" ", "_").replace("-", "_")
    for key in sorted(_IMPACT_NARRATIVES, key=len, reverse=True):
        if key in vt:
            return prefix + _IMPACT_NARRATIVES[key]
    return f"{prefix}exploit this vulnerability to compromise security controls. Impact requires analyst review."


def _resolve_remediation(vuln_type: str, custom_remediation: str = "") -> str:
    if custom_remediation:
        return custom_remediation
    vt = vuln_type.lower().replace(" ", "_").replace("-", "_")
    for key in sorted(_REMEDIATIONS, key=len, reverse=True):
        if key in vt:
            return _REMEDIATIONS[key]
    return _REMEDIATIONS["default"]


# ─────────────────────────────────────────────────────────────────────────────
# Formatter Class
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FormattedReport:
    """A formatted bug bounty submission report."""
    title: str
    platform: str
    cvss_vector: str
    cvss_score: float
    severity: str
    body: str                   # The main report content
    poc_command: str            # Self-contained PoC (curl/HTTP)
    word_count: int


class BBReportFormatter:
    """
    HackerOne / Bugcrowd submission-ready report formatter.

    Generates properly structured reports that match what programs
    expect: clear steps to reproduce, business impact, CVSS scores,
    and a self-contained PoC.
    """

    def format_finding(
        self,
        title: str,
        vulnerability_type: str,
        severity: str,
        endpoint: str,
        parameter: str = "",
        steps_to_reproduce: list[str] = None,
        expected_result: str = "",
        actual_result: str = "",
        poc_request: str = "",
        impact: str = "",
        remediation: str = "",
        evidence: str = "",
        cvss_vector: Optional[CVSSVector] = None,
        platform: str = "hackerone",
        additional_context: str = "",
        chain_description: str = "",
    ) -> FormattedReport:
        """
        Generate a submission-ready report for one confirmed finding.

        Args:
            title:               Finding title e.g., "SSRF to AWS Cloud Metadata"
            vulnerability_type:  Normalized type e.g., "ssrf", "idor", "xss"
            severity:            Critical/High/Medium/Low
            endpoint:            The vulnerable endpoint URL
            parameter:           The vulnerable parameter name
            steps_to_reproduce:  Numbered steps list
            expected_result:     What should happen (no vulnerability)
            actual_result:       What actually happens (the vulnerability)
            poc_request:         Self-contained curl command or HTTP request
            impact:              Business impact description (or auto-generated)
            remediation:         Fix recommendation (or auto-generated)
            evidence:            Raw HTTP response or output proving exploitation
            cvss_vector:         Optional pre-built CVSSVector (auto-derived if not provided)
            platform:            "hackerone" or "bugcrowd"
            additional_context:  Extra context about the vulnerability
            chain_description:   If part of a chain, describe the chain

        Returns:
            FormattedReport ready for copy-paste submission
        """
        steps_to_reproduce = steps_to_reproduce or []
        sev_lower = severity.lower()

        # Resolve CVSS
        cv = resolve_cvss(vulnerability_type, cvss_vector)
        cvss_score = cv.score
        cvss_vector_str = cv.vector_string
        computed_severity = cv.severity_label

        # Prefer provided severity if it's more specific
        final_severity = severity.capitalize() or computed_severity

        # Resolve impact and remediation
        impact_text = _resolve_impact(vulnerability_type, sev_lower, impact)
        remediation_text = _resolve_remediation(vulnerability_type, remediation)

        # Build platform-specific format
        if platform.lower() == "bugcrowd":
            body = self._format_bugcrowd(
                title=title,
                vuln_type=vulnerability_type,
                severity=final_severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector_str,
                endpoint=endpoint,
                parameter=parameter,
                steps=steps_to_reproduce,
                expected=expected_result,
                actual=actual_result,
                poc=poc_request,
                impact=impact_text,
                remediation=remediation_text,
                evidence=evidence,
                context=additional_context,
                chain=chain_description,
            )
        else:
            # Default: HackerOne
            body = self._format_hackerone(
                title=title,
                vuln_type=vulnerability_type,
                severity=final_severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector_str,
                endpoint=endpoint,
                parameter=parameter,
                steps=steps_to_reproduce,
                expected=expected_result,
                actual=actual_result,
                poc=poc_request,
                impact=impact_text,
                remediation=remediation_text,
                evidence=evidence,
                context=additional_context,
                chain=chain_description,
            )

        return FormattedReport(
            title=title,
            platform=platform,
            cvss_vector=cvss_vector_str,
            cvss_score=cvss_score,
            severity=final_severity,
            body=body,
            poc_command=poc_request,
            word_count=len(body.split()),
        )

    def _format_hackerone(self, **kw) -> str:
        """Generate HackerOne-formatted report body."""
        steps_md = "\n".join(
            f"{i}. {step}" for i, step in enumerate(kw["steps"], 1)
        ) if kw["steps"] else "1. [Steps not provided — add reproduction steps]"

        evidence_block = ""
        if kw["evidence"]:
            evidence_block = f"""

### Evidence / Response

```
{kw['evidence'][:3000]}
```"""

        chain_block = ""
        if kw["chain"]:
            chain_block = f"""

### Attack Chain

{kw['chain']}"""

        context_block = ""
        if kw["context"]:
            context_block = f"""

### Additional Context

{kw['context']}"""

        return f"""## Summary

{kw['title']} — {kw['severity']} severity vulnerability affecting `{kw['endpoint']}`.

**CVSS 3.1 Score**: {kw['cvss_score']} ({kw['severity']})
**Vector**: `{kw['cvss_vector']}`
**Vulnerable Parameter**: `{kw['parameter'] or '(see steps to reproduce)'}`

## Description

{_vuln_description(kw['vuln_type'])}

## Steps to Reproduce

{steps_md}

## Expected Behavior

{kw['expected'] or 'The server should reject or sanitize the attacker-controlled input before processing.'}

## Observed Behavior (Vulnerability)

{kw['actual'] or 'The server processes the attacker-controlled input unsafely, producing the vulnerability described above.'}

## Proof of Concept

```
{kw['poc'] or '[Provide curl command or HTTP request here]'}
```{evidence_block}{chain_block}{context_block}

## Impact

{kw['impact']}

## Severity Justification

- **CVSS 3.1 Score**: {kw['cvss_score']} — {kw['severity']}
- **Vector**: {kw['cvss_vector']}
- This rating reflects the ability to {_severity_justification(kw['vuln_type'], kw['severity'])}

## Recommended Fix

{kw['remediation']}

---
*Report generated by Cyber-CoPilot Bug Bounty Framework*
"""

    def _format_bugcrowd(self, **kw) -> str:
        """Generate Bugcrowd-formatted report body."""
        steps_md = "\n".join(
            f"Step {i}: {step}" for i, step in enumerate(kw["steps"], 1)
        ) if kw["steps"] else "Step 1: [Add reproduction steps]"

        return f"""**Title**: {kw['title']}

**Target**: {kw['endpoint']}

**Vulnerability Type**: {kw['vuln_type'].replace('_', ' ').title()}

**Severity**: {kw['severity']} (CVSS {kw['cvss_score']})

**CVSS Vector**: {kw['cvss_vector']}

---

**Description**

{_vuln_description(kw['vuln_type'])}

**Steps to Reproduce**

{steps_md}

**Expected Result**: {kw['expected'] or 'Input should be validated and rejected.'}

**Actual Result**: {kw['actual'] or 'Input is processed unsafely.'}

**Proof of Concept**

```
{kw['poc'] or '[Add PoC command here]'}
```

**Impact**

{kw['impact']}

**Remediation**

{kw['remediation']}

**CVSS Justification**: Score {kw['cvss_score']} — {kw['severity']}. {_severity_justification(kw['vuln_type'], kw['severity'])}

---
*Report generated by Cyber-CoPilot Bug Bounty Framework*
"""

    def format_multi_finding_summary(
        self,
        target: str,
        findings: list[dict],
        chains: list[dict] = None,
        program_name: str = "",
    ) -> str:
        """
        Generate a full assessment summary with all findings, CVSS scores, and chains.

        Args:
            target:       Target hostname/domain
            findings:     List of finding dicts with keys: title, severity, endpoint, vuln_type
            chains:       Optional list of chain opportunities
            program_name: Bug bounty program name

        Returns:
            Executive summary markdown document
        """
        chains = chains or []
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        findings_table = "| # | Severity | Type | Endpoint | CVSS |\n|---|----------|------|----------|------|\n"
        for i, f in enumerate(findings, 1):
            cv = resolve_cvss(f.get("vuln_type", ""), None)
            sev = f.get("severity", "medium").capitalize()
            findings_table += (
                f"| {i} | **{sev}** | {f.get('vuln_type', 'unknown')} "
                f"| `{f.get('endpoint', 'N/A')}` | {cv.score} |\n"
            )

        chain_section = ""
        if chains:
            chain_section = "\n## 🔗 Attack Chains\n\n"
            for ch in chains:
                chain_section += (
                    f"### {ch.get('title', 'Chain')}\n"
                    f"- **Combined Severity**: {ch.get('combined_severity', 'High')}\n"
                    f"- **Typical Bounty**: {ch.get('bounty_range', 'Varies')}\n"
                    f"- {ch.get('description', '')}\n\n"
                )

        return f"""# 🎯 Bug Bounty Assessment — {target}
{f'**Program**: {program_name}' if program_name else ''}

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {sev_counts['critical']} |
| 🟠 High     | {sev_counts['high']} |
| 🟡 Medium   | {sev_counts['medium']} |
| 🟢 Low      | {sev_counts['low']} |
| ℹ️ Info      | {sev_counts.get('info', 0)} |

**Total Findings**: {len(findings)}

## Findings Summary

{findings_table}{chain_section}
---
*Assessment by Cyber-CoPilot Bug Bounty Framework*
"""

    def calculate_cvss(
        self,
        av: str = "N", ac: str = "L", pr: str = "N",
        ui: str = "N", s: str = "U",
        c: str = "H", i: str = "H", a: str = "N",
    ) -> dict:
        """
        Calculate CVSS 3.1 base score from individual metric components.

        AV: N=Network, A=Adjacent, L=Local, P=Physical
        AC: L=Low, H=High
        PR: N=None, L=Low, H=High
        UI: N=None, R=Required
        S:  U=Unchanged, C=Changed
        C/I/A: N=None, L=Low, H=High

        Returns dict with score, severity, and vector string.
        """
        cv = CVSSVector(av=av, ac=ac, pr=pr, ui=ui, s=s, c=c, i=i, a=a)
        return {
            "score": cv.score,
            "severity": cv.severity_label,
            "vector": cv.vector_string,
        }


def _vuln_description(vuln_type: str) -> str:
    """Return a short technical description of the vulnerability class."""
    desc = {
        "ssrf": (
            "Server-Side Request Forgery (SSRF) occurs when an application fetches a remote resource "
            "based on a user-supplied URL without sufficient validation of the destination. "
            "An attacker can use this to make the server issue requests to internal network resources, "
            "cloud instance metadata endpoints, or other services not normally accessible from the internet."
        ),
        "sql_injection": (
            "SQL Injection occurs when user-supplied data is incorporated into a database query without "
            "proper sanitization, allowing an attacker to alter the query's logic. This can lead to "
            "unauthorized data access, data manipulation, and in some configurations, OS command execution."
        ),
        "idor": (
            "Broken Object Level Authorization (IDOR/BOLA) occurs when an application uses a "
            "user-controlled identifier to access objects without verifying that the requesting "
            "user is authorized for that specific object. An attacker can substitute their own "
            "identifier with another user's to access or modify unauthorized resources."
        ),
        "stored_xss": (
            "Stored Cross-Site Scripting occurs when user-supplied data is permanently stored on the "
            "server and subsequently rendered without proper output encoding. The malicious script "
            "executes in the browser of every user who views the affected content."
        ),
        "reflected_xss": (
            "Reflected Cross-Site Scripting occurs when user-supplied input is immediately reflected "
            "in the HTTP response without proper encoding. The script executes when a victim clicks "
            "a crafted URL containing the payload."
        ),
        "jwt": (
            "JSON Web Token (JWT) vulnerabilities allow an attacker to forge authentication tokens. "
            "Common attack vectors include algorithm confusion (RS256→HS256), accepting unsigned "
            "tokens (alg:none), exploiting the jku/x5u header injection, and brute-forcing weak secrets."
        ),
        "mass_assignment": (
            "Mass Assignment occurs when an API or framework automatically binds user-supplied fields "
            "to model attributes without filtering, allowing attackers to set protected fields "
            "(role, admin, premium) that should not be user-modifiable."
        ),
        "race_condition": (
            "Race Condition vulnerabilities occur when two or more concurrent operations compete to "
            "access or modify shared state, and the application does not properly serialize these "
            "operations. This can allow an action to execute multiple times before its guard condition "
            "is updated."
        ),
        "cors": (
            "A CORS misconfiguration allows an attacker's website to make credentialed cross-origin "
            "requests to the application's API and read the responses. When combined with sensitive "
            "endpoints and Access-Control-Allow-Credentials: true, this enables complete data theft "
            "for any user who visits the attacker's page."
        ),
        "path_traversal": (
            "Path Traversal (also known as Local File Inclusion) occurs when user-supplied input "
            "is used to construct a file system path without sufficient sanitization, allowing "
            "attackers to access files outside the intended directory by using '../' sequences."
        ),
        "ssti": (
            "Server-Side Template Injection occurs when user input is embedded into a template "
            "without sanitization, allowing an attacker to inject template directives that are "
            "evaluated server-side. In most template engines, this leads to arbitrary OS command execution."
        ),
        "business_logic": (
            "Business Logic vulnerabilities occur when the application fails to enforce expected "
            "constraints on financial or workflow operations, allowing attackers to manipulate "
            "prices, bypass payment gates, or abuse single-use resources."
        ),
        "http_smuggling": (
            "HTTP Request Smuggling occurs when a front-end and back-end server disagree on the "
            "boundaries of HTTP requests, allowing an attacker to 'smuggle' a prefix request that "
            "is interpreted as the beginning of the next legitimate user's request."
        ),
        "default": (
            "This vulnerability allows an attacker to interact with the application in an unintended "
            "way that compromises the security properties described in the Impact section below."
        ),
    }
    vt = vuln_type.lower().replace(" ", "_").replace("-", "_")
    for key in sorted(desc, key=len, reverse=True):
        if key in vt:
            return desc[key]
    return desc["default"]


def _severity_justification(vuln_type: str, severity: str) -> str:
    """Generate a one-line severity justification."""
    j = {
        "critical": "achieve full {context} without requiring any prior authentication or user interaction.",
        "high": "significantly compromise user data, authentication, or application integrity.",
        "medium": "access information or functionality beyond what is permitted for the requesting user.",
        "low": "gather information useful for further attacks.",
    }
    context_map = {
        "ssrf": "cloud account compromise", "rce": "server compromise",
        "sql_injection": "database compromise", "jwt": "authentication bypass for all accounts",
        "default": "exploitation of the vulnerability",
    }
    vt = vuln_type.lower()
    ctx = next((v for k, v in context_map.items() if k in vt), context_map["default"])
    template = j.get(severity.lower(), j["medium"])
    return template.format(context=ctx)


# ─────────────────────────────────────────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────────────────────────────────────────

_formatter: Optional[BBReportFormatter] = None


def get_formatter() -> BBReportFormatter:
    """Get (or lazily create) the global BBReportFormatter instance."""
    global _formatter
    if _formatter is None:
        _formatter = BBReportFormatter()
    return _formatter
