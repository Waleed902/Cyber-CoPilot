"""
Surface Modeler — Target Surface → EV-Ranked Attack Queue

Analyzes recon signals from a target and produces a prioritized attack queue
where the highest Expected-Value attack class comes first. This replaces the
"run everything in phase order" approach with "bet on what actually pays."

Algorithm:
  1. Classify the target into a surface type (SaaS, API, E-commerce, etc.)
  2. Score each attack class based on observed signals
  3. Return a ranked queue with rationale and specific starting actions

Usage:
    from src.sdk.surface_modeler import get_surface_modeler

    modeler = get_surface_modeler()
    queue = modeler.build_attack_queue(
        tech_stack=["React", "Django", "PostgreSQL"],
        auth_type="jwt",
        endpoints=["/api/v1/users", "/api/v2/admin", "/api/checkout"],
        roles=["user", "admin", "viewer"],
        cloud_indicators=["AWS", "S3 URLs in responses"],
        notes="Multi-tenant SaaS, Stripe payments, OAuth Google login"
    )
    print(modeler.format_queue(queue))
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from loguru import logger


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AttackClass:
    """A prioritized attack category with starting actions."""
    name: str                       # e.g., "BOLA/IDOR on Multi-Tenant Data"
    attack_type: str                # normalized type for impact_amplifier linking
    ev_score: float                 # Expected Value score (0–100)
    rationale: str                  # Why this is high-EV for this target
    starting_actions: list[str]     # Specific first moves
    tools: list[str]                # Tools to use
    typical_bounty: str             # e.g., "$3,000–$15,000"
    skip_unless: list[str] = field(default_factory=list)  # Prerequisites to verify first


@dataclass
class SurfaceModel:
    """Complete surface analysis for one target."""
    surface_type: str               # e.g., "SaaS B2B with multi-tenant + payments"
    signals_detected: list[str]     # All signals that influenced the model
    attack_queue: list[AttackClass] # Ranked from highest to lowest EV
    skip_list: list[str]            # Attack classes to skip for this target (explain why)
    hunter_strategy: str            # Overall 1-paragraph strategy note


# ─────────────────────────────────────────────────────────────────────────────
# Signal Definitions — what patterns map to what signals
# ─────────────────────────────────────────────────────────────────────────────

# Tech stack → signals
_TECH_SIGNALS: dict[str, list[str]] = {
    # Frontend
    "react": ["spa", "api_heavy", "js_endpoints"],
    "vue": ["spa", "api_heavy", "js_endpoints"],
    "angular": ["spa", "api_heavy", "js_endpoints"],
    "next.js": ["spa", "api_heavy", "js_endpoints", "ssr"],
    "nuxt": ["spa", "api_heavy", "js_endpoints", "ssr"],
    # Backend
    "django": ["python_backend", "orm", "admin_panel_likely"],
    "flask": ["python_backend", "api_likely"],
    "fastapi": ["python_backend", "api_heavy", "openapi_likely"],
    "laravel": ["php_backend", "orm", "mass_assignment_risk"],
    "rails": ["ruby_backend", "orm", "mass_assignment_risk", "csrf_native"],
    "spring": ["java_backend", "deserialization_risk"],
    "express": ["nodejs_backend", "api_heavy"],
    "nestjs": ["nodejs_backend", "api_heavy", "jwt_likely"],
    "wordpress": ["cms", "plugin_attack_surface", "xmlrpc_present"],
    "drupal": ["cms", "plugin_attack_surface"],
    "joomla": ["cms", "plugin_attack_surface"],
    # Databases
    "mysql": ["sql_injectable"],
    "postgresql": ["sql_injectable"],
    "mongodb": ["nosql_injectable"],
    "redis": ["nosql_injectable", "rce_via_ssrf_redis"],
    "elasticsearch": ["ssrf_exfil_target"],
    # Infrastructure
    "nginx": ["reverse_proxy", "smuggling_possible", "alias_traversal_possible"],
    "apache": ["reverse_proxy", "htaccess_bypass_possible"],
    "cloudflare": ["cdn", "waf_present", "smuggling_possible"],
    "aws": ["cloud_aws", "ssrf_imds_target", "s3_bucket_target"],
    "s3": ["s3_bucket_target"],
    "gcp": ["cloud_gcp", "ssrf_imds_target"],
    "azure": ["cloud_azure", "ssrf_imds_target"],
    "kubernetes": ["k8s_api_ssrf_target"],
    "docker": ["container_escape_possible"],
    # Auth patterns
    "jwt": ["jwt_attacks", "api_key_auth"],
    "oauth": ["oauth_attacks", "redirect_uri_bypass", "csrf_on_oauth"],
    "saml": ["saml_attacks", "xml_signature_wrapping"],
    "graphql": ["graphql_attacks", "introspection_enabled", "bola_via_graphql"],
    # Payment
    "stripe": ["payment_system", "price_manipulation", "webhook_forgery"],
    "paypal": ["payment_system", "price_manipulation"],
    "braintree": ["payment_system", "price_manipulation"],
    # File handling
    "upload": ["file_upload_bypass", "stored_xss_via_upload", "rce_via_upload"],
    "s3_presigned": ["ssrf_via_presigned", "cors_via_s3"],
}

# Endpoint patterns → signals
_ENDPOINT_SIGNALS: dict[str, list[str]] = {
    r"/admin": ["admin_panel", "admin_auth_bypass"],
    r"/api/v[0-9]": ["versioned_api", "old_version_bypass"],
    r"/api/v1": ["api_v1", "old_version_bypass"],
    r"/graphql": ["graphql_attacks"],
    r"/checkout|/payment|/billing|/subscription": ["payment_system", "price_manipulation"],
    r"/upload|/file|/attachment|/document": ["file_upload_bypass"],
    r"/oauth|/auth|/sso|/login": ["oauth_attacks", "redirect_uri_bypass"],
    r"/invite|/share|/team|/organization": ["multi_tenant", "idor_tenant_isolation"],
    r"/export|/report|/download": ["ssrf_via_export", "info_disclosure"],
    r"/webhook": ["webhook_forgery", "ssrf_via_webhook"],
    r"/api/users|/api/accounts|/api/profile": ["idor", "mass_assignment_risk"],
    r"/swagger|/api-docs|/openapi": ["api_spec_exposed", "endpoint_enumeration"],
    r"\.git|\.env|\.svn": ["source_code_exposed", "credentials_exposed"],
    r"/actuator|/health|/metrics|/debug": ["debug_endpoint", "info_disclosure"],
    r"/reset|/forgot|/password": ["password_reset_poisoning"],
}

# Role signals
_ROLE_SIGNALS: dict[str, list[str]] = {
    "admin": ["admin_role_present", "privilege_escalation"],
    "owner": ["multi_tenant", "tenant_isolation"],
    "member": ["multi_tenant", "idor_member_scope"],
    "viewer": ["rbac_present", "bfla_method_tampering"],
    "guest": ["auth_bypass_possible"],
    "super": ["super_admin", "privilege_escalation"],
    "moderator": ["role_privilege_gap"],
    "manager": ["role_privilege_gap"],
}

# Auth type → signals
_AUTH_SIGNALS: dict[str, list[str]] = {
    "jwt": ["jwt_attacks", "alg_confusion_risk", "kid_path_traversal"],
    "session": ["session_fixation", "csrf_risk"],
    "oauth": ["oauth_attacks", "redirect_uri_bypass"],
    "api_key": ["api_key_leak", "header_auth"],
    "basic": ["credential_brute"],
    "saml": ["saml_attacks", "xml_signature_wrapping"],
    "none": ["missing_auth", "unauthenticated_access"],
}

# Cloud indicators → signals
_CLOUD_SIGNALS: dict[str, list[str]] = {
    "aws": ["ssrf_imds_target", "s3_bucket_target", "iam_pivot"],
    "gcp": ["ssrf_imds_gcp", "gcs_bucket_target", "service_account_pivot"],
    "azure": ["ssrf_imds_azure", "blob_storage_target", "managed_identity_pivot"],
    "s3": ["s3_bucket_target"],
    "lambda": ["serverless_event_injection"],
    "ec2": ["ssrf_imds_target"],
    "kubernetes": ["k8s_api_ssrf_target", "container_escape_possible"],
}


# ─────────────────────────────────────────────────────────────────────────────
# Attack Class Templates — base definitions, EV adjusted dynamically by signals
# ─────────────────────────────────────────────────────────────────────────────

def _build_attack_classes() -> list[dict]:
    """Define all attack classes with base EV scores."""
    return [
        # ──────────────────────────────────────────────────────────────────────
        # BOLA / IDOR
        # ──────────────────────────────────────────────────────────────────────
        {
            "name": "BOLA/IDOR — Object-Level Authorization",
            "attack_type": "idor",
            "base_ev": 60,
            "signal_boosts": {
                "multi_tenant": 30, "idor_tenant_isolation": 25,
                "versioned_api": 15, "spa": 10, "api_heavy": 10,
            },
            "signal_suppresses": {"cms": -20},
            "rationale": (
                "BOLA is the #1 bug type by volume on HackerOne. APIs with numeric or "
                "UUID identifiers and multi-tenant data separation are the highest-value targets."
            ),
            "starting_actions": [
                "Create two test accounts (Account A and Account B)",
                "With Account A: collect all IDs from API responses (user_id, org_id, project_id)",
                "With Account B's token: try accessing Account A's resources at those IDs",
                "Test: GET /api/users/{A_id}, PUT /api/users/{A_id}, DELETE /api/users/{A_id}",
                "Use two_account_authz_engine to automate cross-account tests",
            ],
            "tools": ["two_account_authz_engine", "idor_enumerate", "rest_api_fuzzing", "http_compare"],
            "typical_bounty": "$2,000–$20,000",
            "skip_unless": [],
        },
        # ──────────────────────────────────────────────────────────────────────
        # JWT Attacks
        # ──────────────────────────────────────────────────────────────────────
        {
            "name": "JWT Algorithm Confusion & Forgery",
            "attack_type": "jwt",
            "base_ev": 50,
            "signal_boosts": {
                "jwt_attacks": 35, "alg_confusion_risk": 20, "api_heavy": 10,
                "kid_path_traversal": 15,
            },
            "signal_suppresses": {"session": -30, "saml": -10},
            "rationale": (
                "JWT-based auth is ubiquitous in modern APIs. alg:none and RS256→HS256 confusion "
                "are still found regularly on H1. JWT issues are Critical and pay $5K–$25K."
            ),
            "starting_actions": [
                "Capture a valid JWT from any authenticated request",
                "Run jwt_analysis to extract header/claims/algorithm",
                "Test alg:none: modify header to {alg: 'none'}, remove signature dot",
                "Fetch public key from /.well-known/jwks.json or /api/auth/keys",
                "Try RS256→HS256 confusion using jwt_embedded_jwk with the public key",
                "Test jku/x5u header injection pointing to your JWKS endpoint",
            ],
            "tools": ["jwt_analysis", "jwt_forge", "jwt_jku_attack", "jwt_x5u_attack",
                      "jwt_kid_path_traversal", "jwt_embedded_jwk"],
            "typical_bounty": "$5,000–$25,000",
            "skip_unless": ["jwt_attacks"],
        },
        # ──────────────────────────────────────────────────────────────────────
        # Mass Assignment
        # ──────────────────────────────────────────────────────────────────────
        {
            "name": "Mass Assignment / Parameter Injection",
            "attack_type": "mass_assignment",
            "base_ev": 45,
            "signal_boosts": {
                "mass_assignment_risk": 30, "api_heavy": 15, "spa": 10,
                "admin_role_present": 20, "privilege_escalation": 15,
            },
            "signal_suppresses": {"cms": -15},
            "rationale": (
                "Rails and Laravel apps are especially vulnerable to mass assignment. "
                "Modern REST APIs with JSON bodies often accept extra fields silently. "
                "Self-assigning admin role is an instant Critical."
            ),
            "starting_actions": [
                "Intercept account registration POST body",
                "Add: role, is_admin, admin, premium, verified, confirmed, plan, permissions",
                "Intercept profile update PUT — add same extra fields",
                "Check if any field changes persist (re-fetch profile to confirm)",
                "Use rest_api_fuzzing with mass_assignment wordlist",
            ],
            "tools": ["rest_api_fuzzing", "http_request", "http_compare"],
            "typical_bounty": "$2,000–$15,000",
            "skip_unless": [],
        },
        # ──────────────────────────────────────────────────────────────────────
        # SSRF → Cloud Metadata
        # ──────────────────────────────────────────────────────────────────────
        {
            "name": "SSRF → Cloud Metadata → Credential Theft",
            "attack_type": "ssrf",
            "base_ev": 55,
            "signal_boosts": {
                "ssrf_imds_target": 35, "cloud_aws": 20, "cloud_gcp": 15, "cloud_azure": 15,
                "ssrf_via_export": 20, "ssrf_via_webhook": 20, "export_endpoint": 15,
            },
            "signal_suppresses": {},
            "rationale": (
                "SSRF to cloud metadata is P1 at virtually every cloud-hosted program. "
                "URL parameters, file exports, webhooks, and image fetch features are the "
                "most common SSRF entry points."
            ),
            "starting_actions": [
                "Find all URL-input parameters: image_url, webhook_url, export_url, fetch_url, avatar_url",
                "For each: try http://169.254.169.254/latest/meta-data/ (AWS)",
                "Use ssrf_cloud_metadata to test all cloud providers automatically",
                "If blocked: try http://169.254.169.254.nip.io (DNS rebinding bypass)",
                "If blind: use managed_oast_ssrf_validation for OOB callback confirmation",
                "If creds found: run pacu_run to assess IAM permissions",
            ],
            "tools": ["ssrf_cloud_metadata", "ssrf_imdsv2_chain", "managed_oast_ssrf_validation",
                      "ssrf_scanner", "pacu_run"],
            "typical_bounty": "$5,000–$30,000",
            "skip_unless": [],
        },
        # ──────────────────────────────────────────────────────────────────────
        # OAuth / SSO
        # ──────────────────────────────────────────────────────────────────────
        {
            "name": "OAuth / SSO Account Takeover Chains",
            "attack_type": "open_redirect",
            "base_ev": 50,
            "signal_boosts": {
                "oauth_attacks": 35, "redirect_uri_bypass": 25, "csrf_on_oauth": 15,
                "saml_attacks": 20, "xml_signature_wrapping": 15,
            },
            "signal_suppresses": {},
            "rationale": (
                "OAuth misconfiguration leads to ATO at scale. redirect_uri bypass, "
                "state parameter CSRF, and Referer token leakage are the top 3 OAuth bugs. "
                "SAML XML signature wrapping is Critical when present."
            ),
            "starting_actions": [
                "Map the OAuth flow: /authorize, /callback, /token endpoints",
                "Test redirect_uri: add extra params, extra path, subdomains",
                "Check state parameter — if absent → CSRF on OAuth flow",
                "Check if reset token leaks via Referer header to loaded scripts",
                "Run oauth_flow_test for automated redirect_uri and state tests",
                "If SAML: use saml_attacks for XML signature wrapping",
            ],
            "tools": ["oauth_flow_test", "password_reset_tester", "http_request", "browser_visit"],
            "typical_bounty": "$3,000–$20,000",
            "skip_unless": ["oauth_attacks"],
        },
        # ──────────────────────────────────────────────────────────────────────
        # Price / Business Logic Manipulation
        # ──────────────────────────────────────────────────────────────────────
        {
            "name": "Business Logic — Price & Workflow Manipulation",
            "attack_type": "business_logic",
            "base_ev": 55,
            "signal_boosts": {
                "payment_system": 35, "price_manipulation": 25,
                "multi_tenant": 10, "spa": 10,
            },
            "signal_suppresses": {"cms": -15, "blog": -20},
            "rationale": (
                "Business logic bugs pay high because scanners never find them. "
                "If the target processes payments, handles pricing, or offers "
                "subscription tiers — price manipulation is a near-certain win."
            ),
            "starting_actions": [
                "Map all checkout / upgrade / subscription flows",
                "Intercept every payment initiation request",
                "Modify: amount=0.01, quantity=-1, currency=other, plan_id=enterprise",
                "Test race conditions on payment: http2_single_packet_race with 20 concurrent requests",
                "Test coupon codes: apply same code 10 times simultaneously",
                "Try changing plan_id in upgrade request to higher tier",
            ],
            "tools": ["http_request", "http2_single_packet_race", "business_logic", "http_fuzz"],
            "typical_bounty": "$3,000–$20,000",
            "skip_unless": ["payment_system"],
        },
        # ──────────────────────────────────────────────────────────────────────
        # GraphQL
        # ──────────────────────────────────────────────────────────────────────
        {
            "name": "GraphQL — Introspection, Injection & BOLA",
            "attack_type": "idor",
            "base_ev": 55,
            "signal_boosts": {
                "graphql_attacks": 40, "introspection_enabled": 20,
                "bola_via_graphql": 20, "api_heavy": 10,
            },
            "signal_suppresses": {},
            "rationale": (
                "GraphQL has a unique attack surface: introspection exposes all types, "
                "resolvers often lack field-level authorization, and batch queries can "
                "bypass rate limits. BOLA via GraphQL is extremely common."
            ),
            "starting_actions": [
                "Run graphql_introspection to get full schema",
                "Look for admin/internal mutations and queries not shown in UI",
                "Test each query/mutation with another user's ID (BOLA)",
                "Test injection: SQLi/NoSQLi in string arguments via graphql_injection_test",
                "Check graphql_authz_replay_probe for authorization bypass on admin mutations",
                "Test batch query abuse: 100 login mutations in one request → rate limit bypass",
            ],
            "tools": ["graphql_introspection", "graphql_injection_test", "graphql_schema_inventory",
                      "graphql_authz_replay_probe"],
            "typical_bounty": "$3,000–$15,000",
            "skip_unless": ["graphql_attacks"],
        },
        # ──────────────────────────────────────────────────────────────────────
        # File Upload
        # ──────────────────────────────────────────────────────────────────────
        {
            "name": "File Upload — Content-Type Bypass & RCE",
            "attack_type": "path_traversal",
            "base_ev": 50,
            "signal_boosts": {
                "file_upload_bypass": 35, "stored_xss_via_upload": 20,
                "rce_via_upload": 20, "php_backend": 15,
            },
            "signal_suppresses": {},
            "rationale": (
                "File upload with incorrect content-type validation is common. "
                "SVG uploads → stored XSS. PHP uploads → RCE. "
                "Unrestricted file types + public serving URL = Critical."
            ),
            "starting_actions": [
                "Find all file upload endpoints (profile picture, attachment, document)",
                "Try uploading: .html (XSS), .svg (XSS), .php.jpg (RCE bypass)",
                "Change Content-Type to image/jpeg while uploading .php file",
                "Use file_upload_bypass tool for automated bypass attempts",
                "Check if uploaded file is served at a predictable URL",
                "Test path traversal in filename: ../../shell.php",
            ],
            "tools": ["http_request", "http_fuzz"],
            "typical_bounty": "$2,000–$15,000",
            "skip_unless": ["file_upload_bypass"],
        },
        # ──────────────────────────────────────────────────────────────────────
        # HTTP Request Smuggling
        # ──────────────────────────────────────────────────────────────────────
        {
            "name": "HTTP Request Smuggling",
            "attack_type": "http_smuggling",
            "base_ev": 40,
            "signal_boosts": {
                "reverse_proxy": 25, "smuggling_possible": 20,
                "cdn": 15, "waf_present": 10,
            },
            "signal_suppresses": {},
            "rationale": (
                "HTTP smuggling is rare, hard to find, and always Critical/High. "
                "Nginx + Gunicorn, Cloudflare + origin, HAProxy + backend are the "
                "most common vulnerable combinations."
            ),
            "starting_actions": [
                "Check if a reverse proxy is in front of the app (X-Forwarded-For, Via headers)",
                "Run smuggling_cl0 (CL:0 technique — works on HTTP/1.1 keep-alive)",
                "Run smuggling_te0 (TE:0 technique — chunked encoding)",
                "Test H2 downgrade via smuggling_h2_downgrade",
                "Confirm with http2_single_packet_race for H/2 synchronization attacks",
            ],
            "tools": ["smuggling_cl0", "smuggling_te0", "smuggling_h2_downgrade", "http2_single_packet_race"],
            "typical_bounty": "$5,000–$30,000",
            "skip_unless": ["reverse_proxy"],
        },
        # ──────────────────────────────────────────────────────────────────────
        # Information Disclosure
        # ──────────────────────────────────────────────────────────────────────
        {
            "name": "Credential & Secret Exposure",
            "attack_type": "info_disclosure",
            "base_ev": 45,
            "signal_boosts": {
                "source_code_exposed": 40, "credentials_exposed": 35,
                "debug_endpoint": 25, "api_spec_exposed": 20,
                "js_endpoints": 15,
            },
            "signal_suppresses": {},
            "rationale": (
                "Secret exposure in .env, .git, or JS bundles is the #1 source of "
                "Critical findings that require zero exploitation skill. "
                "Always scan before anything else."
            ),
            "starting_actions": [
                "Run: curl https://target.com/.env, /.git/config, /.svn/entries",
                "Run jsluice_extract on all JS bundles to find hardcoded keys",
                "Run github_dork_search for 'org:company api_key'",
                "Run trufflehog_repo on any exposed git repositories",
                "Check /api-docs, /swagger.json, /openapi.json, /graphql (introspection)",
                "Check /actuator/env, /actuator/health, /debug for Spring Boot/Flask",
            ],
            "tools": ["jsluice_extract", "js_secret_chain", "github_dork_search",
                      "trufflehog_repo", "git_dump"],
            "typical_bounty": "$1,000–$20,000",
            "skip_unless": [],
        },
        # ──────────────────────────────────────────────────────────────────────
        # SQL Injection
        # ──────────────────────────────────────────────────────────────────────
        {
            "name": "SQL Injection",
            "attack_type": "sql_injection",
            "base_ev": 55,
            "signal_boosts": {
                "sql_injectable": 25, "orm": 10, "api_heavy": 10,
                "old_version_bypass": 15,
            },
            "signal_suppresses": {"nosql_injectable": -10},
            "rationale": (
                "SQLi is Critical and always pays top bounty. Order-by injection "
                "bypasses most WAFs. Second-order SQLi is missed by all scanners. "
                "Prioritize search, sort, filter, and ID parameters."
            ),
            "starting_actions": [
                "Run sqli_scanner on all GET/POST parameters with user input",
                "Specifically test: sort=, order=, orderby=, filter= parameters with ORDER BY injection",
                "Test search parameters: ' OR '1'='1 and boolean-based payloads",
                "Test second-order: register with username admin'-- and trigger a function that uses it",
                "Run sqlmap_attack on confirmed injectable parameters",
                "Check for JSON body injection: {\"id\": \"1 OR 1=1\"}",
            ],
            "tools": ["sqli_scanner", "sqlmap_attack", "sqli_extract_blind", "http_request"],
            "typical_bounty": "$3,000–$20,000",
            "skip_unless": [],
        },
        # ──────────────────────────────────────────────────────────────────────
        # Race Conditions
        # ──────────────────────────────────────────────────────────────────────
        {
            "name": "Race Conditions on State-Changing Actions",
            "attack_type": "race_condition",
            "base_ev": 45,
            "signal_boosts": {
                "payment_system": 25, "price_manipulation": 20,
                "multi_tenant": 10, "api_heavy": 10,
            },
            "signal_suppresses": {"cms": -15},
            "rationale": (
                "Race conditions on payments, promotions, and upgrades are Critical "
                "findings that scanners never detect. H/2 single-packet attack makes "
                "exploitation reliable and easy to prove."
            ),
            "starting_actions": [
                "Identify all state-changing endpoints: payments, transfers, votes, upgrades, coupons",
                "For each: send 20 concurrent requests using http2_single_packet_race",
                "Check if action executes more than once (double payment, double upgrade)",
                "Check balance/state after concurrent requests — is it inconsistent?",
                "Test last-byte sync: prepare all requests but delay final byte send",
            ],
            "tools": ["http2_single_packet_race", "http_fuzz", "business_logic"],
            "typical_bounty": "$3,000–$20,000",
            "skip_unless": [],
        },
        # ──────────────────────────────────────────────────────────────────────
        # XSS (last because of lower EV vs. above for SaaS targets)
        # ──────────────────────────────────────────────────────────────────────
        {
            "name": "Cross-Site Scripting (XSS)",
            "attack_type": "reflected_xss",
            "base_ev": 35,
            "signal_boosts": {
                "spa": 10, "admin_panel": 20, "file_upload_bypass": 15,
                "js_endpoints": 10,
            },
            "signal_suppresses": {},
            "rationale": (
                "XSS has lower EV than IDOR/SSRF because it requires user interaction. "
                "Focus on stored XSS (admin-visible), DOM XSS in SPAs, and XSS "
                "in file upload (SVG). Reflected XSS without HttpOnly is still worth reporting."
            ),
            "starting_actions": [
                "Run xss_scanner on all user-input parameters",
                "Check response headers for missing Content-Security-Policy",
                "Test SVG file upload for stored XSS: <svg onload=alert(1)>",
                "Test DOM XSS: use dom_vulnerability_scanner",
                "If admin panel exists: test XSS in fields admin views (usernames, comments, reports)",
                "Run xsstrike for advanced payloads when basic payloads are filtered",
            ],
            "tools": ["xss_scanner", "xsstrike", "dom_vulnerability_scanner", "browser_xss_test",
                      "validate_xss"],
            "typical_bounty": "$500–$8,000",
            "skip_unless": [],
        },
        # ──────────────────────────────────────────────────────────────────────
        # CORS
        # ──────────────────────────────────────────────────────────────────────
        {
            "name": "CORS Misconfiguration",
            "attack_type": "cors",
            "base_ev": 30,
            "signal_boosts": {
                "api_heavy": 15, "jwt_attacks": 10, "spa": 10,
            },
            "signal_suppresses": {},
            "rationale": (
                "CORS alone is Low. Only valuable when combined with sensitive endpoints "
                "AND credentials:true is also set. Test the token/auth endpoints specifically."
            ),
            "starting_actions": [
                "Run cors_check on all API endpoints, especially /api/user, /api/token, /api/profile",
                "Specifically add: Origin: https://evil.com header to requests",
                "Check response for Access-Control-Allow-Origin: https://evil.com",
                "Check for Access-Control-Allow-Credentials: true — required for real impact",
                "If both → write PoC fetch() that exfiltrates data from attacker domain",
            ],
            "tools": ["cors_check", "http_request"],
            "typical_bounty": "$500–$5,000",
            "skip_unless": [],
        },
        # ──────────────────────────────────────────────────────────────────────
        # Deserialization
        # ──────────────────────────────────────────────────────────────────────
        {
            "name": "Deserialization RCE",
            "attack_type": "sql_injection",  # no exact match — treated as high-severity chain
            "base_ev": 35,
            "signal_boosts": {
                "java_backend": 30, "deserialization_risk": 25,
                "spring": 20, "python_backend": 10,
            },
            "signal_suppresses": {"nodejs_backend": -10},
            "rationale": (
                "Java deserialization is still found regularly in enterprise apps. "
                "Spring Boot, WebLogic, and Jenkins are highest-value targets. "
                "ysoserial payloads via OAST callback confirm blind deserialization."
            ),
            "starting_actions": [
                "Look for base64-encoded cookies or request bodies (Java serialized objects start with rO0AB)",
                "Use deser_java_ysoserial with OAST payload to test for blind deserialization",
                "Check Content-Type: application/x-java-serialized-object",
                "Test X-ViewState, rememberMe cookies, ViewState parameters",
                "Run managed_oast_ssrf_validation to confirm OOB callback",
            ],
            "tools": ["deser_java_ysoserial", "managed_oast_ssrf_validation", "http_request"],
            "typical_bounty": "$5,000–$30,000",
            "skip_unless": ["java_backend", "deserialization_risk"],
        },
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Surface Classifier
# ─────────────────────────────────────────────────────────────────────────────

_SURFACE_TYPES = {
    frozenset(["multi_tenant", "payment_system", "api_heavy"]): "SaaS B2B with payments — highest IDOR/business-logic EV",
    frozenset(["multi_tenant", "api_heavy"]): "SaaS B2B — primary targets: IDOR, mass assignment, JWT",
    frozenset(["payment_system", "spa"]): "E-commerce / DTC — primary targets: price manipulation, race conditions",
    frozenset(["cms"]): "CMS (WP/Drupal/Joomla) — primary targets: plugin CVEs, auth bypass, SQLi",
    frozenset(["graphql_attacks"]): "GraphQL API — primary targets: introspection, BOLA, injection",
    frozenset(["java_backend", "deserialization_risk"]): "Enterprise Java — primary targets: deserialization, SSRF, XXE",
    frozenset(["oauth_attacks", "saml_attacks"]): "Identity Provider / SSO — primary targets: OAuth ATO, SAML wrapping",
    frozenset(["api_heavy", "jwt_attacks"]): "REST API with JWT — primary targets: JWT confusion, mass assignment, BOLA",
    frozenset(["cloud_aws"]): "Cloud-hosted app — SSRF to IMDS is P1 priority",
}


class SurfaceModeler:
    """
    Target surface → EV-ranked attack queue generator.

    Converts recon observations into a prioritized attack plan that
    maximizes expected bounty payout per hour of testing time.
    """

    def __init__(self):
        self._attack_templates = _build_attack_classes()

    def _collect_signals(
        self,
        tech_stack: list[str],
        auth_type: str,
        endpoints: list[str],
        roles: list[str],
        cloud_indicators: list[str],
        notes: str,
    ) -> set[str]:
        """Aggregate all detection signals from all recon inputs."""
        signals: set[str] = set()

        # Tech stack signals
        for tech in tech_stack:
            t = tech.lower().strip()
            for key, sigs in _TECH_SIGNALS.items():
                if key in t:
                    signals.update(sigs)

        # Auth type
        at = auth_type.lower().strip()
        for key, sigs in _AUTH_SIGNALS.items():
            if key in at:
                signals.update(sigs)

        # Endpoints
        for ep in endpoints:
            ep_lower = ep.lower()
            for pattern, sigs in _ENDPOINT_SIGNALS.items():
                if re.search(pattern, ep_lower):
                    signals.update(sigs)

        # Roles
        for role in roles:
            r = role.lower().strip()
            for key, sigs in _ROLE_SIGNALS.items():
                if key in r:
                    signals.update(sigs)

        # Cloud indicators
        for ci in cloud_indicators:
            c = ci.lower().strip()
            for key, sigs in _CLOUD_SIGNALS.items():
                if key in c:
                    signals.update(sigs)

        # Free-text notes
        notes_lower = notes.lower()
        # Pattern match common notes
        note_mappings = {
            "multi.tenant": ["multi_tenant", "idor_tenant_isolation"],
            "saas": ["multi_tenant", "api_heavy"],
            "payment": ["payment_system", "price_manipulation"],
            "stripe|paypal|braintree": ["payment_system", "price_manipulation"],
            "oauth|sso": ["oauth_attacks", "redirect_uri_bypass"],
            "graphql": ["graphql_attacks"],
            "kubernetes|k8s": ["k8s_api_ssrf_target"],
            "aws|s3|ec2": ["cloud_aws", "ssrf_imds_target", "s3_bucket_target"],
            "gcp|google cloud": ["cloud_gcp", "ssrf_imds_gcp"],
            "azure": ["cloud_azure", "ssrf_imds_azure"],
            "nginx": ["reverse_proxy", "smuggling_possible"],
            "upload": ["file_upload_bypass"],
            "wordpress|wp": ["cms", "plugin_attack_surface"],
            "java|spring": ["java_backend", "deserialization_risk"],
        }
        for pattern, sigs in note_mappings.items():
            if re.search(pattern, notes_lower):
                signals.update(sigs)

        return signals

    def _classify_surface(self, signals: set[str]) -> str:
        """Determine the surface type label."""
        best_match = "Web Application"
        best_overlap = 0
        for sig_set, label in _SURFACE_TYPES.items():
            overlap = len(sig_set & signals)
            if overlap > best_overlap:
                best_overlap = overlap
                best_match = label
        return best_match

    def _score_attack_class(self, template: dict, signals: set[str]) -> float:
        """Calculate EV score for one attack class given observed signals."""
        score = template["base_ev"]
        for sig, boost in template["signal_boosts"].items():
            if sig in signals:
                score += boost
        for sig, penalty in template.get("signal_suppresses", {}).items():
            if sig in signals:
                score += penalty  # penalty is already negative
        # Check skip_unless — if required signals not present, reduce score
        skip_unless = template.get("skip_unless", [])
        if skip_unless and not any(s in signals for s in skip_unless):
            score -= 30  # heavily deprioritize if prerequisite signal missing
        return max(0.0, score)

    def build_attack_queue(
        self,
        tech_stack: list[str] = None,
        auth_type: str = "unknown",
        endpoints: list[str] = None,
        roles: list[str] = None,
        cloud_indicators: list[str] = None,
        notes: str = "",
    ) -> SurfaceModel:
        """
        Build a prioritized attack queue for the target.

        Args:
            tech_stack:        List of detected technologies (e.g., ["React", "Django", "PostgreSQL"])
            auth_type:         Auth mechanism (e.g., "jwt", "session", "oauth", "saml")
            endpoints:         List of discovered endpoints
            roles:             Detected user roles (e.g., ["user", "admin", "viewer"])
            cloud_indicators:  Cloud technology hints (e.g., ["AWS", "S3 URLs in responses"])
            notes:             Free-text notes from recon (tech detected, app description, etc.)

        Returns:
            SurfaceModel with a ranked attack queue
        """
        tech_stack = tech_stack or []
        endpoints = endpoints or []
        roles = roles or []
        cloud_indicators = cloud_indicators or []

        # Collect all signals
        signals = self._collect_signals(tech_stack, auth_type, endpoints, roles, cloud_indicators, notes)

        # Classify surface
        surface_type = self._classify_surface(signals)

        # Score all attack classes
        scored: list[tuple[float, AttackClass]] = []
        skip_list: list[str] = []

        for tmpl in self._attack_templates:
            ev = self._score_attack_class(tmpl, signals)
            # Check skip_unless — add to skip list if prerequisite missing
            skip_unless = tmpl.get("skip_unless", [])
            if skip_unless and not any(s in signals for s in skip_unless):
                skip_list.append(
                    f"{tmpl['name']} — skip until you confirm: {', '.join(skip_unless)}"
                )
                continue  # Skip from main queue, goes to skip list

            ac = AttackClass(
                name=tmpl["name"],
                attack_type=tmpl["attack_type"],
                ev_score=ev,
                rationale=tmpl["rationale"],
                starting_actions=tmpl["starting_actions"],
                tools=tmpl["tools"],
                typical_bounty=tmpl["typical_bounty"],
            )
            scored.append((ev, ac))

        # Sort by EV descending
        scored.sort(key=lambda x: x[0], reverse=True)
        ranked_queue = [ac for _, ac in scored]

        # Build overall strategy
        if ranked_queue:
            top3 = ", ".join(ac.name for ac in ranked_queue[:3])
            hunter_strategy = (
                f"Target classified as: {surface_type}. "
                f"Bet first on: {top3}. "
                f"Signals detected: {len(signals)} ({', '.join(sorted(signals)[:8])}{'...' if len(signals) > 8 else ''}). "
                f"Skip low-EV coverage scans until the top 3 attack classes are fully tested. "
                f"Each class has starting actions — do the first action immediately, don't plan."
            )
        else:
            hunter_strategy = "Insufficient signals to model surface. Run recon first."

        return SurfaceModel(
            surface_type=surface_type,
            signals_detected=sorted(signals),
            attack_queue=ranked_queue,
            skip_list=skip_list,
            hunter_strategy=hunter_strategy,
        )

    def format_queue(self, model: SurfaceModel, top_n: int = 5) -> str:
        """Format the attack queue as readable text for agent consumption."""
        lines = [
            f"╔═══════════════════════════════════════════════════════════╗",
            f"║  SURFACE MODEL: {model.surface_type[:50]:<50} ║",
            f"╚═══════════════════════════════════════════════════════════╝",
            "",
            f"Signals detected ({len(model.signals_detected)}): {', '.join(model.signals_detected[:10])}",
            "",
            f"🎯 STRATEGY: {model.hunter_strategy}",
            "",
            "═══ PRIORITIZED ATTACK QUEUE (highest EV first) ═══",
            "",
        ]

        for i, ac in enumerate(model.attack_queue[:top_n], 1):
            lines += [
                f"{'🥇' if i == 1 else '🥈' if i == 2 else '🥉' if i == 3 else f'{i}.'} {ac.name}",
                f"   EV Score       : {ac.ev_score:.0f}/100",
                f"   Typical Bounty : {ac.typical_bounty}",
                f"   Rationale      : {ac.rationale}",
                f"   Tools          : {', '.join(ac.tools)}",
                f"   Starting Actions:",
            ]
            for j, action in enumerate(ac.starting_actions[:3], 1):
                lines.append(f"      {j}. {action}")
            lines.append("")

        if model.skip_list:
            lines += [
                "─── SKIPPED (prerequisite signals not observed) ───",
            ]
            for s in model.skip_list:
                lines.append(f"  ⏭  {s}")

        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────────────────────────────────────────

_modeler: Optional[SurfaceModeler] = None


def get_surface_modeler() -> SurfaceModeler:
    """Get (or lazily create) the global SurfaceModeler instance."""
    global _modeler
    if _modeler is None:
        _modeler = SurfaceModeler()
    return _modeler
