"""
Advanced Output Parser
Structured extraction of IPs, domains, emails, tokens, hashes, URLs, and other
security-relevant data from tool output.
"""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from loguru import logger


@dataclass
class ParsedOutput:
    """Structured parsed output from a tool."""
    tool_name: str
    raw_length: int = 0
    ip_addresses: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    ports: List[Dict[str, Any]] = field(default_factory=list)
    credentials: List[Dict[str, str]] = field(default_factory=list)
    hashes: List[Dict[str, str]] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    tokens: List[Dict[str, str]] = field(default_factory=list)  # JWT, API keys, etc.
    technologies: List[Dict[str, str]] = field(default_factory=list)
    http_status_codes: List[Dict[str, Any]] = field(default_factory=list)
    files_found: List[str] = field(default_factory=list)
    
    def has_findings(self) -> bool:
        return any([
            self.ip_addresses, self.domains, self.urls, self.emails,
            self.ports, self.credentials, self.hashes, self.cves,
            self.tokens, self.technologies, self.http_status_codes,
            self.files_found
        ])
    
    def summary(self) -> str:
        parts = []
        if self.ip_addresses: parts.append(f"{len(self.ip_addresses)} IPs")
        if self.domains: parts.append(f"{len(self.domains)} domains")
        if self.urls: parts.append(f"{len(self.urls)} URLs")
        if self.emails: parts.append(f"{len(self.emails)} emails")
        if self.ports: parts.append(f"{len(self.ports)} ports")
        if self.credentials: parts.append(f"{len(self.credentials)} credentials")
        if self.hashes: parts.append(f"{len(self.hashes)} hashes")
        if self.cves: parts.append(f"{len(self.cves)} CVEs")
        if self.tokens: parts.append(f"{len(self.tokens)} tokens")
        if self.technologies: parts.append(f"{len(self.technologies)} technologies")
        return ", ".join(parts) if parts else "no structured findings"


# ─── Regex Patterns ────────────────────────────────────────────────

# IPv4
RE_IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
)

# IPv6 (simplified)
RE_IPV6 = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
    r'\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b'
)

# Domains
RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
    r'+[a-zA-Z]{2,}\b'
)

# URLs
RE_URL = re.compile(r'https?://[^\s<>"\')\]]+')

# Emails
RE_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

# Nmap-style ports
RE_PORT_NMAP = re.compile(
    r'(\d{1,5})/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.+))?',
    re.IGNORECASE
)

# CVEs
RE_CVE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)

# Common hash formats
RE_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
RE_SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
RE_NTLM = re.compile(r'\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b')

# Credential patterns
RE_CRED_COLON = re.compile(r'(?:^|\n)\s*(\S+?):(\S+?)(?:\s|$)', re.MULTILINE)
RE_CRED_EQUALS = re.compile(
    r'(?:user(?:name)?|login|email)\s*[:=]\s*["\']?(\S+?)["\']?\s+'
    r'(?:pass(?:word)?|pwd|passwd)\s*[:=]\s*["\']?(\S+?)["\']?(?:\s|$)',
    re.IGNORECASE
)

# JWT tokens
RE_JWT = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

# AWS keys
RE_AWS_ACCESS = re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}')
RE_AWS_SECRET = re.compile(r'[A-Za-z0-9/+=]{40}')

# API keys (generic)
RE_API_KEY = re.compile(
    r'(?:api[_-]?key|token|secret|authorization|bearer)\s*[:=]\s*["\']?([A-Za-z0-9_\-.]{20,})',
    re.IGNORECASE
)

# HTTP status codes from directory bruteforce
RE_HTTP_STATUS = re.compile(
    r'((?:https?://)?[^\s]+?)\s+.*?(?:Status:\s*|HTTP/[\d.]+\s+|\[)(\d{3})\]?(?:\s+.*?(\d+)(?:\s*(?:B|bytes|KB))?)?',
    re.IGNORECASE
)

# Technology detection
RE_SERVER = re.compile(r'Server:\s*(.+?)(?:\r?\n|$)', re.IGNORECASE)
RE_X_POWERED = re.compile(r'X-Powered-By:\s*(.+?)(?:\r?\n|$)', re.IGNORECASE)
RE_TECHNOLOGY = re.compile(
    r'(?:Running|Detected|Technology|Framework|CMS|Platform)\s*[:]\s*(.+?)(?:\n|$)',
    re.IGNORECASE
)

# Sensitive files
RE_SENSITIVE_FILES = re.compile(
    r'(?:^|\s)(/?(?:\.(?:git|env|htaccess|htpasswd|DS_Store|svn)|'
    r'(?:wp-config|config|database|credentials|backup|dump|admin|phpinfo|'
    r'robots\.txt|sitemap\.xml|\.well-known|crossdomain\.xml|'
    r'web\.config|applicationHost\.config|server-status|server-info)'
    r')(?:\.(?:php|bak|old|txt|sql|json|xml|yml|yaml|ini|conf|cfg|log))?)',
    re.IGNORECASE
)


class OutputParser:
    """
    Parses raw tool output into structured data.
    Auto-populates target profile and dedup engine.
    """
    
    # Common false positive IPs to skip
    SKIP_IPS = {'0.0.0.0', '127.0.0.1', '255.255.255.255', '0.0.0.0'}
    
    # Common false positive domains
    SKIP_DOMAINS = {
        'example.com', 'localhost', 'schema.org', 'www.w3.org',
        'xml.org', 'xmlns.com', 'purl.org', 'json-schema.org'
    }
    
    def parse(self, tool_name: str, output: str) -> ParsedOutput:
        """Parse tool output and extract all structured data."""
        parsed = ParsedOutput(tool_name=tool_name, raw_length=len(output))
        
        if not output or len(output) < 5:
            return parsed
        
        # Limit parsing to first 100KB for performance
        text = output[:100000]
        
        # Run all extractors
        parsed.ip_addresses = self._extract_ips(text)
        parsed.domains = self._extract_domains(text)
        parsed.urls = self._extract_urls(text)
        parsed.emails = self._extract_emails(text)
        parsed.ports = self._extract_ports(text)
        parsed.cves = self._extract_cves(text)
        parsed.hashes = self._extract_hashes(text)
        parsed.credentials = self._extract_credentials(text)
        parsed.tokens = self._extract_tokens(text)
        parsed.technologies = self._extract_technologies(text)
        parsed.http_status_codes = self._extract_http_status(text, tool_name)
        parsed.files_found = self._extract_sensitive_files(text)
        
        return parsed
    
    def _extract_ips(self, text: str) -> List[str]:
        ipv4 = set(RE_IPV4.findall(text)) - self.SKIP_IPS
        # Basic validation - skip version numbers like 1.2.3.4
        valid = []
        for ip in ipv4:
            parts = ip.split('.')
            # Skip if looks like a version  (all parts < 20 and first is < 5)
            if int(parts[0]) > 0 and not (all(int(p) < 20 for p in parts) and int(parts[0]) < 5):
                valid.append(ip)
        return sorted(set(valid))[:50]
    
    def _extract_domains(self, text: str) -> List[str]:
        domains = set()
        for match in RE_DOMAIN.findall(text):
            d = match.lower().strip('.')
            if d not in self.SKIP_DOMAINS and len(d) > 4 and '.' in d:
                # Skip common file extensions used as patterns
                if not d.endswith(('.png', '.jpg', '.css', '.js', '.svg', '.gif', '.ico')):
                    domains.add(d)
        return sorted(domains)[:100]
    
    def _extract_urls(self, text: str) -> List[str]:
        urls = set()
        for url in RE_URL.findall(text):
            # Clean trailing punctuation
            url = url.rstrip('.,;:)')
            if len(url) > 10:
                urls.add(url)
        return sorted(urls)[:100]
    
    def _extract_emails(self, text: str) -> List[str]:
        return sorted(set(RE_EMAIL.findall(text)))[:50]
    
    def _extract_ports(self, text: str) -> List[Dict]:
        ports = []
        seen = set()
        for match in RE_PORT_NMAP.finditer(text):
            port, proto, state, service = match.group(1), match.group(2), match.group(3), match.group(4)
            version = (match.group(5) or "").strip()
            key = f"{port}/{proto}"
            if key not in seen:
                seen.add(key)
                ports.append({
                    "port": int(port), "protocol": proto.lower(),
                    "state": state.lower(), "service": service,
                    "version": version
                })
        return ports
    
    def _extract_cves(self, text: str) -> List[str]:
        return sorted(set(m.upper() for m in RE_CVE.findall(text)))[:50]
    
    def _extract_hashes(self, text: str) -> List[Dict]:
        hashes = []
        seen = set()
        
        # NTLM hashes (LM:NT)
        for h in RE_NTLM.findall(text):
            if h not in seen:
                seen.add(h)
                hashes.append({"hash": h, "type": "NTLM"})
        
        # SHA-256
        for h in RE_SHA256.findall(text):
            if h not in seen and not h.startswith('0000'):
                seen.add(h)
                hashes.append({"hash": h, "type": "SHA-256"})
        
        # SHA-1
        for h in RE_SHA1.findall(text):
            if h not in seen and not h.startswith('0000') and h not in {m['hash'] for m in hashes}:
                seen.add(h)
                hashes.append({"hash": h, "type": "SHA-1"})
        
        # MD5 (last to avoid false positives from longer hashes)
        for h in RE_MD5.findall(text):
            if h not in seen and not h.startswith('0000') and h not in {m['hash'] for m in hashes}:
                seen.add(h)
                hashes.append({"hash": h, "type": "MD5"})
        
        return hashes[:30]
    
    def _extract_credentials(self, text: str) -> List[Dict]:
        creds = []
        seen = set()
        
        for match in RE_CRED_EQUALS.finditer(text):
            user, passwd = match.group(1), match.group(2)
            key = f"{user}:{passwd}"
            if key not in seen and len(user) > 1 and len(passwd) > 1:
                seen.add(key)
                creds.append({"username": user, "password": passwd})
        
        return creds[:20]
    
    def _extract_tokens(self, text: str) -> List[Dict]:
        tokens = []
        
        # JWT
        for jwt in RE_JWT.findall(text):
            tokens.append({"type": "JWT", "value": jwt[:80] + "..."})
        
        # AWS Access Keys
        for key in RE_AWS_ACCESS.findall(text):
            tokens.append({"type": "AWS_ACCESS_KEY", "value": key})
        
        # Generic API keys
        for match in RE_API_KEY.finditer(text):
            val = match.group(1)
            if len(val) >= 20:
                tokens.append({"type": "API_KEY", "value": val[:60] + "..."})
        
        return tokens[:20]
    
    def _extract_technologies(self, text: str) -> List[Dict]:
        techs = []
        seen = set()
        
        for pattern in [RE_SERVER, RE_X_POWERED, RE_TECHNOLOGY]:
            for match in pattern.finditer(text):
                tech = match.group(1).strip()
                if tech.lower() not in seen and len(tech) > 1:
                    seen.add(tech.lower())
                    # Try to split version
                    ver_match = re.match(r'(.+?)\s+([\d.]+)', tech)
                    if ver_match:
                        techs.append({"name": ver_match.group(1).strip(), "version": ver_match.group(2)})
                    else:
                        techs.append({"name": tech, "version": ""})
        
        return techs[:20]
    
    def _extract_http_status(self, text: str, tool_name: str) -> List[Dict]:
        """Extract HTTP status codes from directory bruteforce tools."""
        if tool_name not in ('gobuster_scan', 'dirsearch_scan', 'ffuf_fuzz', 'gospider_crawl'):
            return []
        
        results = []
        seen = set()
        
        for match in RE_HTTP_STATUS.finditer(text):
            path = match.group(1)
            status = int(match.group(2))
            size = match.group(3) or ""
            
            if path not in seen and status in (200, 201, 301, 302, 401, 403, 500):
                seen.add(path)
                results.append({"path": path, "status": status, "size": size})
        
        return results[:100]
    
    def _extract_sensitive_files(self, text: str) -> List[str]:
        files = set()
        for match in RE_SENSITIVE_FILES.finditer(text):
            f = match.group(1).strip()
            if len(f) > 2:
                files.add(f)
        return sorted(files)[:30]
    
    def auto_populate_profile(self, parsed: ParsedOutput, target: str):
        """Auto-populate target profile from parsed output."""
        try:
            from src.repl.profiles import get_profile_manager
            pm = get_profile_manager()
            
            for ip in parsed.ip_addresses:
                pm.add_ip(target, ip)
            
            for sub in parsed.domains:
                if target in sub or sub.endswith(f".{target}"):
                    pm.add_subdomain(target, sub)
            
            for port_info in parsed.ports:
                if port_info.get("state") == "open":
                    pm.add_port(
                        target,
                        port_info["port"],
                        port_info["protocol"],
                        port_info["service"],
                        port_info.get("version", "")
                    )
            
            for cred in parsed.credentials:
                pm.add_credential(
                    target,
                    cred["username"],
                    cred.get("password", ""),
                    parsed.tool_name
                )
            
            for tech in parsed.technologies:
                pm.add_technology(target, tech["name"], tech.get("version", ""))
                
        except Exception as e:
            logger.debug(f"Auto-populate profile failed: {e}")


# Global singleton
_parser: Optional[OutputParser] = None


def get_output_parser() -> OutputParser:
    """Get or create the global output parser."""
    global _parser
    if _parser is None:
        _parser = OutputParser()
    return _parser
