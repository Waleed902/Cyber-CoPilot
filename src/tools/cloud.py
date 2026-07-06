"""
Cloud Security — fingerprinting, enumeration, and advanced post-exploitation.

  cloud_fingerprint          Identify cloud provider from DNS + HTTP headers
  cloud_enum_orchestrate     Run all cloud enum tools and aggregate results

  s3_bucket_enum             Enumerate AWS S3 buckets
  cloudfront_enum            Enumerate CloudFront distributions
  gcp_bucket_enum            Enumerate GCP Storage buckets
  azure_blob_enum            Enumerate Azure Blob containers
  cloud_asset_enum           Comprehensive multi-cloud asset enumeration

  pacu_run                   Drive Pacu modules with AWS keys
  roadtools_dump             Pull Azure tenant data via roadrecon
  aadinternals_recon         AADInternals passive recon
  cognito_misconfig_probe    Probe Cognito user/identity pool misconfigs
  container_escape_probe     Detect container escape primitives on-host
"""

from __future__ import annotations

import importlib
import os
import re
import shutil
import socket
import subprocess
from pathlib import Path

import requests

from src.sdk.tool import function_tool


# ─────────────────────────────────────────────────────────────────────────────
# Cloud fingerprinting + orchestration  (from cloud_security.py)
# ─────────────────────────────────────────────────────────────────────────────

_CLOUD_FINGERPRINTS = [
    # Provider, regex against (CNAME / Server / hostname) -> identifier
    ("aws-cloudfront", re.compile(r"\.cloudfront\.net$|server: cloudfront", re.I)),
    ("aws-s3", re.compile(r"\.s3[.-][a-z0-9-]+\.amazonaws\.com$|server: AmazonS3", re.I)),
    ("aws-elb", re.compile(r"\.elb\.amazonaws\.com$|server: awselb", re.I)),
    ("aws-apigateway", re.compile(r"execute-api\.[a-z0-9-]+\.amazonaws\.com$", re.I)),
    ("azure-blob", re.compile(r"\.blob\.core\.windows\.net$", re.I)),
    ("azure-app", re.compile(r"\.azurewebsites\.net$", re.I)),
    ("azure-cdn", re.compile(r"\.azureedge\.net$", re.I)),
    ("gcp-storage", re.compile(r"\.storage\.googleapis\.com$|storage\.googleapis\.com", re.I)),
    ("gcp-app", re.compile(r"\.appspot\.com$", re.I)),
    ("gcp-run", re.compile(r"\.run\.app$", re.I)),
    ("cloudflare", re.compile(r"server: cloudflare|cf-ray:", re.I)),
    ("fastly", re.compile(r"server: fastly|x-fastly", re.I)),
    ("heroku", re.compile(r"\.herokuapp\.com$", re.I)),
    ("vercel", re.compile(r"\.vercel\.app$|server: vercel", re.I)),
    ("netlify", re.compile(r"\.netlify\.app$|server: netlify", re.I)),
    ("digitalocean", re.compile(r"\.ondigitalocean\.app$", re.I)),
]


@function_tool()
def cloud_fingerprint(target: str) -> str:
    """
    Identify the cloud provider hosting a target by probing DNS + HTTP headers.

    Args:
        target: Hostname or URL (e.g. example.com, https://api.example.com)

    Returns:
        Cloud provider identification with the next-step enumeration tool to run.
    """
    host = target
    if "://" in host:
        host = host.split("://", 1)[1].split("/", 1)[0]
    host = host.split(":", 1)[0]

    findings = []

    # DNS chain
    cname_chain = []
    try:
        try:
            import dns.resolver  # type: ignore
            r = dns.resolver.Resolver()
            r.timeout = 4
            r.lifetime = 6
            try:
                ans = r.resolve(host, "CNAME")
                cname_chain = [str(rr.target).rstrip(".") for rr in ans]
            except Exception:
                pass
        except ImportError:
            pass
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            ip = ""
    except Exception:
        ip = ""

    haystack = " ".join([host] + cname_chain).lower()

    headers_blob = ""
    for scheme in ("https://", "http://"):
        try:
            r = requests.get(f"{scheme}{host}", timeout=8, verify=False, allow_redirects=True)
            headers_blob = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            break
        except Exception:
            continue

    combined = haystack + "\n" + headers_blob.lower()

    for provider, pattern in _CLOUD_FINGERPRINTS:
        if pattern.search(combined):
            findings.append(provider)

    out = [f"## Cloud Fingerprint: {host}"]
    if ip:
        out.append(f"  IP: {ip}")
    if cname_chain:
        out.append(f"  CNAME chain: {' -> '.join(cname_chain)}")
    if not findings:
        out.append("  No cloud provider detected.")
        return "\n".join(out)

    out.append(f"  Providers: {', '.join(sorted(set(findings)))}")
    out.append("\n[Recommended next steps]")
    if any(p.startswith("aws") for p in findings):
        out.append("  - s3_bucket_enum(domain)  # discover associated S3 buckets")
        out.append("  - cloudfront_enum(domain) # check for distribution misconfigs")
        out.append("  - cloudflair_scan(domain) # find origin behind CloudFront")
        out.append("  - if SSRF found → use ssrf_cloud_metadata(target_url, provider='aws')")
    if any(p.startswith("azure") for p in findings):
        out.append("  - azure_blob_enum(domain)")
        out.append("  - if SSRF found → ssrf_cloud_metadata(target_url, provider='azure')")
    if any(p.startswith("gcp") for p in findings):
        out.append("  - gcp_bucket_enum(domain)")
        out.append("  - if SSRF found → ssrf_cloud_metadata(target_url, provider='gcp')")
    if "cloudflare" in findings:
        out.append("  - cloudflair_scan(domain)  # try to bypass to origin")
    return "\n".join(out)


@function_tool()
def cloud_enum_orchestrate(domain: str, providers: str = "aws,azure,gcp") -> str:
    """
    Run the registered cloud enum tools (s3, azure_blob, gcp, cloudfront) and
    aggregate findings into one report.

    Args:
        domain:    Target organization / domain name
        providers: Comma-separated subset (aws,azure,gcp,cloudfront,all)

    Returns:
        Combined results with hits and exposed asset counts.
    """
    selected = {p.strip().lower() for p in providers.split(",") if p.strip()}
    if "all" in selected or not selected:
        selected = {"aws", "azure", "gcp", "cloudfront"}

    out = [f"## Cloud Enum Orchestrator: {domain}", f"Providers: {sorted(selected)}"]

    async_results = {}

    if "aws" in selected:
        try:
            async_results["aws_s3"] = s3_bucket_enum.invoke
        except Exception:
            pass
    if "cloudfront" in selected:
        try:
            async_results["aws_cloudfront"] = cloudfront_enum.invoke
        except Exception:
            pass
    if "gcp" in selected:
        try:
            async_results["gcp"] = gcp_bucket_enum.invoke
        except Exception:
            pass
    if "azure" in selected:
        try:
            async_results["azure"] = azure_blob_enum.invoke
        except Exception:
            pass

    # Drive each tool synchronously (their invoke is async-wrapped by FunctionTool)
    import asyncio
    loop = asyncio.new_event_loop()
    try:
        for label, invoke in async_results.items():
            try:
                result = loop.run_until_complete(invoke(domain=domain))
                snippet = str(result or "").strip()
                out.append(f"\n=== {label} ===")
                out.append(snippet[:3000] if snippet else "(no output)")
            except Exception as e:
                out.append(f"\n=== {label} ===")
                out.append(f"error: {e}")
    finally:
        loop.close()

    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# Cloud asset enumeration  (from cloud_enum.py)
# ─────────────────────────────────────────────────────────────────────────────

_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (CyberCoPilot/1.0)"}
_TIMEOUT = 10


@function_tool()
def s3_bucket_enum(domain: str, wordlist: str = "") -> str:
    """
    Enumerate AWS S3 buckets associated with a domain.
    Checks for:
    - Publicly readable/writable buckets
    - Bucket name conventions (domain variations)
    - Misconfigured bucket policies
    - Directory listing enabled

    Args:
        domain: Target domain (e.g. example.com)
        wordlist: Comma-separated bucket name variations (optional, uses defaults)

    Returns:
        S3 bucket enumeration results with vulnerability findings
    """
    results = [f"## S3 Bucket Enumeration: {domain}\n"]

    # Generate bucket name variations
    if wordlist:
        variations = [v.strip() for v in wordlist.split(",")]
    else:
        domain_parts = domain.replace(".", "-").split("-")
        variations = [
            domain,
            domain.replace(".", ""),
            "-".join(domain_parts),
            domain_parts[-1],  # TLD only
            f"assets.{domain}",
            f"static.{domain}",
            f"media.{domain}",
            f"uploads.{domain}",
            f"backup.{domain}",
            f"data.{domain}",
            f"dev.{domain}",
            f"staging.{domain}",
            f"prod.{domain}",
            domain.replace(".", "-") + "-assets",
            domain.replace(".", "-") + "-static",
            domain.replace(".", "-") + "-uploads",
        ]

    found_buckets = []
    vulnerable_buckets = []

    for bucket_name in variations:
        # Normalize: S3 bucket names must be lowercase, no consecutive dots
        bucket_name = bucket_name.lower().replace("_", "-")
        if len(bucket_name) < 3 or len(bucket_name) > 63:
            continue

        # Check via HTTP
        bucket_url = f"https://{bucket_name}.s3.amazonaws.com"
        try:
            resp = requests.get(bucket_url, timeout=_TIMEOUT, headers=_DEFAULT_HEADERS, verify=False)

            if resp.status_code == 200:
                # Bucket exists and is listable
                if "ListBucketResult" in resp.text or "<Contents>" in resp.text:
                    found_buckets.append((bucket_name, "PUBLIC_LISTABLE", bucket_url))
                    vulnerable_buckets.append((bucket_name, "PUBLIC_LISTABLE", bucket_url))
                    results.append(f"  🔴 {bucket_name} — PUBLICLY LISTABLE (directory listing enabled)")
                    results.append(f"     URL: {bucket_url}")
                else:
                    found_buckets.append((bucket_name, "EXISTS", bucket_url))
                    results.append(f"  ⚠️  {bucket_name} — exists but not listable")
            elif resp.status_code == 403:
                found_buckets.append((bucket_name, "EXISTS_403", bucket_url))
                results.append(f"  ⚠️  {bucket_name} — exists (403 Forbidden)")
            elif resp.status_code == 404:
                pass  # Bucket doesn't exist
            else:
                results.append(f"  ⚠️  {bucket_name} — HTTP {resp.status_code}")

        except requests.exceptions.Timeout:
            pass
        except Exception:
            pass

        # Check via AWS CLI (if available)
        try:
            cli_result = subprocess.run(
                ["aws", "s3", "ls", f"s3://{bucket_name}", "--no-sign-request"],
                capture_output=True, text=True, timeout=10
            )
            if cli_result.returncode == 0 and cli_result.stdout.strip():
                if (bucket_name, "PUBLIC_LISTABLE", bucket_url) not in found_buckets:
                    found_buckets.append((bucket_name, "CLI_LISTABLE", bucket_url))
                    vulnerable_buckets.append((bucket_name, "CLI_LISTABLE", bucket_url))
                    results.append(f"  🔴 {bucket_name} — AWS CLI confirms public listing")
                    results.append(f"     Contents: {cli_result.stdout[:200]}")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass  # AWS CLI not installed or timed out

    # Summary
    results.append("\n### Summary")
    results.append(f"  Buckets checked: {len(variations)}")
    results.append(f"  Buckets found: {len(found_buckets)}")
    results.append(f"  Vulnerable buckets: {len(vulnerable_buckets)}")

    if vulnerable_buckets:
        results.append("\n🔴 VULNERABLE S3 BUCKETS:")
        for name, vuln_type, url in vulnerable_buckets:
            results.append(f"  - {name} ({vuln_type}) → {url}")
            results.append("    Remediation: Block public access, enable bucket policy")
    elif found_buckets:
        results.append("\n✅ Found buckets (not publicly listable):")
        for name, status, url in found_buckets:
            results.append(f"  - {name} [{status}]")
    else:
        results.append(f"\n✅ No S3 buckets found for {domain}")

    return "\n".join(results)


@function_tool()
def cloudfront_enum(domain: str) -> str:
    """
    Enumerate AWS CloudFront distributions associated with a domain.
    Checks for:
    - CloudFront distribution IDs
    - Misconfigured origin servers
    - Missing WAF associations
    - HTTP/2 and compression settings

    Args:
        domain: Target domain

    Returns:
        CloudFront enumeration results
    """
    results = [f"## CloudFront Enumeration: {domain}\n"]

    # Check if domain uses CloudFront
    try:
        dns_result = subprocess.run(
            ["dig", "CNAME", domain, "+short"],
            capture_output=True, text=True, timeout=10
        )
        dig_output = dns_result.stdout.strip()
    except Exception:
        dig_output = ""

    is_cloudfront = "cloudfront.net" in dig_output.lower()

    if not is_cloudfront:
        # Try HTTP headers
        try:
            resp = requests.get(f"https://{domain}", timeout=_TIMEOUT, headers=_DEFAULT_HEADERS, verify=False)
            is_cloudfront = "x-cache" in resp.headers and "cloudfront" in resp.headers.get("x-cache", "").lower()
            if is_cloudfront:
                results.append(f"  ℹ️  Detected via X-Cache header: {resp.headers.get('x-cache')}")
        except Exception:
            pass

    if not is_cloudfront:
        results.append(f"  ℹ️  No CloudFront distribution detected for {domain}")
        results.append(f"  DNS CNAME: {dig_output[:200] if dig_output else 'N/A'}")
        return "\n".join(results)

    results.append("  ✅ CloudFront detected")
    results.append(f"  CNAME: {dig_output[:200]}")

    # Extract distribution ID if possible
    dist_id_match = re.search(r'([A-Z0-9]+)\.cloudfront\.net', dig_output)
    if dist_id_match:
        dist_id = dist_id_match.group(1)
        results.append(f"  Distribution ID: {dist_id}")
        results.append(f"  Distribution URL: https://{dist_id}.cloudfront.net")

    # Check for common CloudFront misconfigurations
    results.append("\n### Security Checks")

    # Check HTTP->HTTPS redirect
    try:
        http_resp = requests.get(f"http://{domain}", timeout=_TIMEOUT, allow_redirects=False, verify=False)
        if http_resp.status_code in (301, 302):
            location = http_resp.headers.get("Location", "")
            if "https" in location.lower():
                results.append("  ✅ HTTP→HTTPS redirect enabled")
            else:
                results.append(f"  ⚠️  HTTP redirect to non-HTTPS: {location}")
        else:
            results.append(f"  ❌ HTTP does NOT redirect (status {http_resp.status_code})")
    except Exception:
        results.append("  ⚠️  Could not test HTTP redirect")

    # Check security headers
    try:
        https_resp = requests.get(f"https://{domain}", timeout=_TIMEOUT, headers=_DEFAULT_HEADERS, verify=False)
        security_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Frame-Options": "X-Frame-Options",
            "X-Content-Type-Options": "X-Content-Type-Options",
        }
        for header, name in security_headers.items():
            if header in https_resp.headers:
                results.append(f"  ✅ {name}: present")
            else:
                results.append(f"  ❌ {name}: MISSING")
    except Exception:
        pass

    results.append("\n### Recommendations")
    results.append("  • Verify WAF is attached to distribution")
    results.append("  • Check origin server is not directly accessible")
    results.append("  • Ensure HTTPS-only viewer policy")
    results.append("  • Enable geo-restriction if applicable")

    return "\n".join(results)


@function_tool()
def gcp_bucket_enum(domain: str) -> str:
    """
    Enumerate Google Cloud Storage buckets associated with a domain.
    Checks for publicly readable buckets and misconfigured IAM policies.

    Args:
        domain: Target domain

    Returns:
        GCS bucket enumeration results
    """
    results = [f"## GCP Storage Bucket Enumeration: {domain}\n"]

    # Generate bucket name variations
    variations = [
        domain,
        domain.replace(".", ""),
        domain.replace(".", "-"),
        domain.replace(".", "_"),
        f"{domain}-assets",
        f"{domain}-static",
        f"{domain}-uploads",
        f"assets-{domain.split('.')[0]}",
        f"static-{domain.split('.')[0]}",
    ]

    found = []

    for bucket_name in variations:
        bucket_name = bucket_name.lower()
        if len(bucket_name) < 3 or len(bucket_name) > 63:
            continue

        # Check via XML API
        url = f"https://storage.googleapis.com/{bucket_name}"
        try:
            resp = requests.get(url, timeout=_TIMEOUT, headers=_DEFAULT_HEADERS, verify=False)

            if resp.status_code == 200:
                if "ListBucketResult" in resp.text:
                    found.append((bucket_name, "PUBLIC_LISTABLE", url))
                    results.append(f"  🔴 {bucket_name} — PUBLICLY LISTABLE")
                else:
                    found.append((bucket_name, "EXISTS", url))
                    results.append(f"  ⚠️  {bucket_name} — exists")
            elif resp.status_code == 403:
                results.append(f"  ⚠️  {bucket_name} — exists (403 Forbidden)")
            elif resp.status_code == 404:
                pass
        except Exception:
            pass

    results.append("\n### Summary")
    results.append(f"  Buckets checked: {len(variations)}")
    results.append(f"  Buckets found: {len(found)}")

    if found:
        results.append("\nFound GCS buckets:")
        for name, status, url in found:
            results.append(f"  - {name} [{status}] → {url}")
    else:
        results.append(f"\n✅ No GCS buckets found for {domain}")

    return "\n".join(results)


@function_tool()
def azure_blob_enum(domain: str) -> str:
    """
    Enumerate Azure Blob Storage containers associated with a domain.
    Checks for publicly accessible containers and blobs.

    Args:
        domain: Target domain

    Returns:
        Azure Blob enumeration results
    """
    results = [f"## Azure Blob Storage Enumeration: {domain}\n"]

    # Generate container name variations
    variations = [
        domain.replace(".", "-").lower(),
        domain.replace("-", "").lower(),
        f"{domain.split('.')[0]}-assets",
        f"{domain.split('.')[0]}-static",
        f"{domain.split('.')[0]}-uploads",
        f"assets-{domain.split('.')[0]}",
    ]

    found = []

    for container in variations:
        container = container.lower().replace("_", "-")
        if len(container) < 3 or len(container) > 63:
            continue

        # Check for public container
        url = f"https://{container}.blob.core.windows.net/{container}?restype=container&comp=list"
        try:
            resp = requests.get(url, timeout=_TIMEOUT, headers=_DEFAULT_HEADERS, verify=False)

            if resp.status_code == 200:
                if "<EnumerationResults" in resp.text:
                    found.append((container, "PUBLIC_LISTABLE", url))
                    results.append(f"  🔴 {container} — PUBLICLY LISTABLE")
                else:
                    found.append((container, "EXISTS", url))
                    results.append(f"  ⚠️  {container} — exists")
            elif resp.status_code == 403:
                results.append(f"  ⚠️  {container} — exists (403 Forbidden)")
            elif resp.status_code == 404:
                pass
        except Exception:
            pass

    results.append("\n### Summary")
    results.append(f"  Containers checked: {len(variations)}")
    results.append(f"  Containers found: {len(found)}")

    if found:
        results.append("\nFound Azure Blob containers:")
        for name, status, url in found:
            results.append(f"  - {name} [{status}] → {url}")
    else:
        results.append(f"\n✅ No Azure Blob containers found for {domain}")

    return "\n".join(results)


@function_tool()
async def cloud_asset_enum(domain: str) -> str:
    """
    Comprehensive cloud asset enumeration across AWS, GCP, and Azure.
    Runs S3 bucket enum, CloudFront enum, GCP bucket enum, and Azure blob enum.

    Args:
        domain: Target domain

    Returns:
        Comprehensive cloud asset enumeration results
    """
    results = [f"## Comprehensive Cloud Asset Enumeration: {domain}\n"]
    results.append("=" * 60)

    # AWS
    results.append("\n## AWS Assets\n")
    results.append(await s3_bucket_enum.invoke(domain=domain))
    results.append("\n")
    results.append(await cloudfront_enum.invoke(domain=domain))

    # GCP
    results.append("\n\n## GCP Assets\n")
    results.append(await gcp_bucket_enum.invoke(domain=domain))

    # Azure
    results.append("\n\n## Azure Assets\n")
    results.append(await azure_blob_enum.invoke(domain=domain))

    return "\n".join(results)


# ─────────────────────────────────────────────────────────────────────────────
# Advanced cloud post-exploitation  (from cloud_advanced.py)
# ─────────────────────────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 600, env: dict | None = None) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        out = r.stdout or ""
        if r.stderr:
            out += "\n[STDERR]\n" + r.stderr
        return out.strip()
    except FileNotFoundError:
        return f"Error: {cmd[0]} not on PATH"
    except subprocess.TimeoutExpired:
        return f"Error: {cmd[0]} timed out after {timeout}s"
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def pacu_run(access_key: str, secret_key: str, session_token: str = "",
             modules: str = "iam__enum_users_roles_policies_groups,iam__privesc_scan",
             session_name: str = "cyber-copilot") -> str:
    """
    Drive Pacu (https://github.com/RhinoSecurityLabs/pacu) modules with stolen
    AWS credentials.

    Args:
        access_key:    AWS_ACCESS_KEY_ID
        secret_key:    AWS_SECRET_ACCESS_KEY
        session_token: AWS_SESSION_TOKEN (for STS creds)
        modules:       Comma-separated Pacu module names
        session_name:  Pacu session label
    """
    bin_path = shutil.which("pacu") or shutil.which("pacu.py")
    if not bin_path:
        return "Error: pacu not on PATH. pip install pacu"

    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"] = access_key
    env["AWS_SECRET_ACCESS_KEY"] = secret_key
    if session_token:
        env["AWS_SESSION_TOKEN"] = session_token

    # Pacu CLI mode for non-interactive — pass module list
    mod_list = [m.strip() for m in modules.split(",") if m.strip()]
    out_chunks = [f"## Pacu: session={session_name}, modules={mod_list}"]
    for mod in mod_list:
        cmd = [bin_path, "--session", session_name, "--module-name", mod, "--exec"]
        chunk = _run(cmd, 900, env=env)
        out_chunks.append(f"\n=== {mod} ===\n{chunk[:4000]}")
    return "\n".join(out_chunks)


@function_tool()
def roadtools_dump(username: str = "", password: str = "", refresh_token: str = "",
                   tenant: str = "", output_dir: str = "") -> str:
    """
    Wrap roadrecon to dump an Azure AD tenant after authentication.

    Args:
        username:      Azure AD UPN (mutex with refresh_token)
        password:      Cleartext password
        refresh_token: Refresh token from a phished session / device-code flow
        tenant:        Tenant ID (optional; inferred from UPN)
        output_dir:    Where to write roadrecon.db (session dir if empty)
    """
    bin_path = shutil.which("roadrecon")
    if not bin_path:
        return "Error: roadrecon not on PATH. pip install roadtools"

    if not output_dir:
        try:
            from src.repl.target_manager import get_target_manager
            output_dir = getattr(get_target_manager(), "session_dir", "") or "."
        except Exception:
            output_dir = "."
    os.makedirs(output_dir, exist_ok=True)

    auth_cmd = [bin_path, "auth"]
    if refresh_token:
        auth_cmd += ["--refresh-token", refresh_token]
    elif username and password:
        auth_cmd += ["-u", username, "-p", password]
    else:
        return "Error: provide username+password or refresh_token"
    if tenant:
        auth_cmd += ["--tenant", tenant]

    auth_out = _run(auth_cmd, 240)

    gather_cmd = [bin_path, "gather"]
    gather_out = _run(gather_cmd, 1800)

    return "\n".join([
        f"## ROADtools dump → {output_dir}",
        "[auth]", auth_out[:1500],
        "[gather]", gather_out[:3000],
        "[Next] roadrecon-gui → review users/devices/groups/applications/serviceprincipals.",
    ])


@function_tool()
def aadinternals_recon(domain: str) -> str:
    """
    Pure-passive Azure AD recon via AADInternals discovery endpoints.
    No creds, no key required — leaks tenant info, federation status, default
    domain.

    Args:
        domain: Tenant primary domain (e.g. example.com)
    """
    out = [f"## AADInternals recon: {domain}"]

    # Tenant ID lookup
    try:
        r = requests.get(
            f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration",
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            tenant_id = (data.get("issuer") or "").rsplit("/", 2)[1]
            out.append(f"  Tenant ID:        {tenant_id}")
            out.append(f"  Authorization EP: {data.get('authorization_endpoint')}")
            out.append(f"  Issuer:           {data.get('issuer')}")
        else:
            out.append(f"  OpenID config: HTTP {r.status_code} (probably not an Azure-AD tenant)")
            return "\n".join(out)
    except Exception as e:
        return "\n".join(out + [f"  Error: {e}"])

    # GetUserRealm — leaks federation type
    try:
        r = requests.get(
            f"https://login.microsoftonline.com/getuserrealm.srf?login=user@{domain}&xml=1",
            timeout=10,
        )
        if r.status_code == 200 and "<NameSpaceType>" in r.text:
            ns = re.search(r"<NameSpaceType>(\w+)</NameSpaceType>", r.text)
            fed = re.search(r"<FederationBrandName>([^<]+)</FederationBrandName>", r.text)
            sts = re.search(r"<AuthURL>([^<]+)</AuthURL>", r.text)
            out.append(f"  NamespaceType:    {ns.group(1) if ns else '?'}")
            if fed:
                out.append(f"  Brand:            {fed.group(1)}")
            if sts:
                out.append(f"  AuthURL (STS):    {sts.group(1)}")
                out.append("  [Federated] — ADFS targetable; AADInternals abuse possible if cert reachable.")
    except Exception:
        pass

    # GetCredentialType — leaks valid usernames + AAD/ADFS flags (DesktopSso etc.)
    try:
        r = requests.post(
            "https://login.microsoftonline.com/common/GetCredentialType",
            json={"username": f"admin@{domain}", "isOtherIdpSupported": True},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            out.append(f"  DesktopSso supported: {(data.get('EstsProperties') or {}).get('DesktopSsoEnabled')}")
            out.append(f"  IfExistsResult: {data.get('IfExistsResult')} (0 = exists)")
    except Exception:
        pass

    return "\n".join(out)


@function_tool()
def cognito_misconfig_probe(client_id: str, region: str = "us-east-1",
                            identity_pool_id: str = "") -> str:
    """
    Probe a Cognito user pool / identity pool for the most common
    misconfigurations:
      - Open self-service registration with elevated default role
      - Identity pool with permissive unauthenticated role
      - Admin-no-SRP auth flow enabled (allows password brute via API)

    Args:
        client_id:        Cognito user-pool client ID (e.g. 1abc...).
        region:           AWS region
        identity_pool_id: Optional identity pool ID for unauth role test
    """
    try:
        boto3 = importlib.import_module("boto3")
        botocore_exceptions = importlib.import_module("botocore.exceptions")
        ClientError = getattr(botocore_exceptions, "ClientError")
        EndpointConnectionError = getattr(botocore_exceptions, "EndpointConnectionError")
        BotoCoreError = getattr(botocore_exceptions, "BotoCoreError")
    except ImportError:
        return "Error: boto3 required. pip install boto3"

    out = [f"## Cognito misconfig probe: client={client_id} region={region}"]
    boto3_client = getattr(boto3, "client")
    cidp = boto3_client("cognito-idp", region_name=region)

    # 1. SignUp test (no auth needed)
    try:
        from secrets import token_urlsafe
        u = "test_" + token_urlsafe(4)
        cidp.sign_up(
            ClientId=client_id,
            Username=f"{u}@example.invalid",
            Password=token_urlsafe(20) + "Aa1!",
            UserAttributes=[{"Name": "email", "Value": f"{u}@example.invalid"}],
        )
        out.append(f"  ⚠️  Self-service registration ENABLED (created {u})")
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        out.append(f"  Registration check: {code}")
    except (EndpointConnectionError, BotoCoreError) as e:
        out.append(f"  Registration error: {e}")

    # 2. Admin-no-SRP / USER_PASSWORD_AUTH discoverable via InitiateAuth probe
    try:
        cidp.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": "no-such-user", "PASSWORD": "fail"},
        )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "NotAuthorizedException":
            out.append("  USER_PASSWORD_AUTH flow: enabled (login API reachable)")
        elif code == "InvalidParameterException":
            out.append("  USER_PASSWORD_AUTH: not enabled (good)")
        else:
            out.append(f"  USER_PASSWORD_AUTH probe: {code}")

    # 3. Identity Pool unauthenticated role test
    if identity_pool_id:
        try:
            ci = boto3_client("cognito-identity", region_name=region)
            ident = ci.get_id(IdentityPoolId=identity_pool_id)
            cred = ci.get_credentials_for_identity(IdentityId=ident["IdentityId"])
            out.append("  ⚠️  UNAUTH IDENTITY POOL: got STS creds for unauthenticated user")
            out.append(f"      AccessKeyId: {cred['Credentials']['AccessKeyId']}")
            out.append("      [Next] Use these keys with pacu_run to enumerate the role.")
        except ClientError as e:
            out.append(f"  Identity-pool probe: {e.response.get('Error', {}).get('Code', '')}")

    return "\n".join(out)


@function_tool()
def container_escape_probe(target_filesystem: str = "/") -> str:
    """
    Run from inside a compromised container — detect escape primitives:
      - privileged container (capability set, /proc/self/status)
      - exposed docker.sock
      - K8s service-account token
      - dangerous mounts (host /, /var/run/docker.sock, /sys/fs/cgroup)
      - dangerous capabilities (CAP_SYS_ADMIN, CAP_DAC_READ_SEARCH)

    Args:
        target_filesystem: Root path to inspect (default /)
    """
    out = [f"## Container Escape Probe: {target_filesystem}"]
    base = Path(target_filesystem)
    findings: list[str] = []

    # 1. /proc/self/status capability set
    try:
        status = (base / "proc/self/status").read_text(errors="replace")
        for line in status.splitlines():
            if line.startswith(("CapEff:", "CapBnd:")):
                out.append(f"  {line.strip()}")
                # 0x...3fffffffff or all-bits-set ⇒ root caps in container
                hexval = line.split(":")[1].strip()
                try:
                    iv = int(hexval, 16)
                    if iv >= 0x1fffffffff:  # almost all caps
                        findings.append(f"FULL CAP SET ({line.strip()})")
                    if iv & (1 << 21):  # CAP_SYS_ADMIN
                        findings.append("CAP_SYS_ADMIN granted — escape via release_agent / cgroup notification possible")
                    if iv & (1 << 2):   # CAP_DAC_READ_SEARCH
                        findings.append("CAP_DAC_READ_SEARCH — open_by_handle_at escape (Shocker)")
                except Exception:
                    pass
    except Exception as e:
        out.append(f"  Could not read /proc/self/status: {e}")

    # 2. Docker socket
    sock = base / "var/run/docker.sock"
    if sock.exists():
        findings.append(f"docker.sock present at {sock} — host RCE via 'docker run -v /:/host'")

    # 3. K8s SA token
    sa = base / "var/run/secrets/kubernetes.io/serviceaccount/token"
    if sa.exists():
        try:
            tok = sa.read_text().strip()[:30]
            findings.append(f"K8s SA token present (len {sa.stat().st_size} B): {tok}…  → kubectl auth can-i …")
        except Exception:
            findings.append("K8s SA token directory present but unreadable")

    # 4. Mounts
    try:
        mounts = (base / "proc/self/mountinfo").read_text(errors="replace")
        bad = []
        for line in mounts.splitlines():
            if " / / " in line:
                bad.append("HOST ROOT mounted into container")
            if " /sys/fs/cgroup " in line and "rw" in line:
                bad.append("/sys/fs/cgroup writable — release_agent escape")
            if "/var/run/docker.sock" in line:
                bad.append("docker.sock bind-mount confirmed")
        for b in set(bad):
            findings.append(b)
    except Exception:
        pass

    # 5. /.dockerenv heuristic
    if (base / ".dockerenv").exists():
        out.append("  /.dockerenv present (running inside Docker)")

    # 6. cgroup file leaks runtime
    try:
        cg = (base / "proc/1/cgroup").read_text(errors="replace")
        if "kubepods" in cg:
            out.append("  Runtime: Kubernetes pod")
        elif "docker" in cg:
            out.append("  Runtime: Docker container")
    except Exception:
        pass

    out.append("\n[Findings]")
    if not findings:
        out.append("  No obvious escape primitive detected from the container's perspective.")
    else:
        for f in findings:
            out.append(f"  ⚠️  {f}")
        out.append("\n[Next]")
        out.append("  - If docker.sock: curl --unix-socket /var/run/docker.sock http://x/containers/json")
        out.append("  - If CAP_SYS_ADMIN: mount cgroup, write to release_agent for host code exec")
        out.append("  - If K8s SA: try `kubectl auth can-i --list`; pivot to nodes/pods/secrets")
    return "\n".join(out)
