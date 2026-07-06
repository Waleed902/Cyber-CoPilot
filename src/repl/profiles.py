"""
Target Profile Manager - Remember discovered info about targets
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict
from urllib.parse import urlparse
from dataclasses import dataclass, field, fields, asdict
from loguru import logger


@dataclass
class PortInfo:
    """Information about a discovered port."""
    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    state: str = "open"


@dataclass 
class CredentialInfo:
    """Discovered credential."""
    username: str
    password: str = ""
    hash: str = ""
    source: str = ""  # Where it was found
    cracked: bool = False


@dataclass
class VulnerabilityInfo:
    """Discovered vulnerability."""
    name: str
    severity: str = "unknown"  # critical, high, medium, low, info
    cve: str = ""
    description: str = ""
    exploit_available: bool = False
    exploited: bool = False


@dataclass
class TargetProfile:
    """Complete profile of a target."""
    # Basic info
    target: str
    target_type: str = "domain"  # domain, ip, url
    created_at: str = ""
    updated_at: str = ""
    aliases: List[str] = field(default_factory=list)
    
    # Discovery results
    ip_addresses: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    ports: List[Dict] = field(default_factory=list)
    
    # DNS info
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    whois_info: Dict[str, str] = field(default_factory=dict)
    
    # Findings
    vulnerabilities: List[Dict] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)
    
    # Web info
    web_directories: List[str] = field(default_factory=list)
    web_technologies: List[str] = field(default_factory=list)
    api_endpoints: List[Dict] = field(default_factory=list)
    devtools: List[Dict] = field(default_factory=list)
    attack_paths: List[Dict] = field(default_factory=list)
    uploaded_shells: List[Dict] = field(default_factory=list)
    engagement_mode: str = "pentest"
    hypotheses: List[Dict] = field(default_factory=list)
    coverage_requirements: List[Dict] = field(default_factory=list)
    
    # Notes
    notes: List[Dict] = field(default_factory=list)
    
    # Session history
    sessions: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()


class TargetProfileManager:
    """Manages target profiles with persistent storage."""
    
    def __init__(self, base_dir: str = "./targets"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.profiles: Dict[str, TargetProfile] = {}

    def _normalize_target(self, target: str) -> str:
        """Normalize a URL/domain/IP into the host key used for alias matching."""
        target = (target or "").strip().lower()
        if not target:
            return ""
        if "://" in target:
            parsed = urlparse(target)
            return (parsed.hostname or parsed.netloc.split(":")[0]).lower()
        if ":" in target and not target.startswith("["):
            return target.split(":", 1)[0].lower()
        return target

    def _profile_safe_name(self, target: str) -> str:
        return target.replace("://", "_").replace("/", "_").replace(":", "_")

    def _profile_from_data(self, data: dict, requested_target: str = "") -> TargetProfile:
        """Build a TargetProfile while tolerating newer/older profile.json shapes."""
        known = {f.name for f in fields(TargetProfile)}
        filtered = {k: v for k, v in data.items() if k in known}
        profile = TargetProfile(**filtered)
        if requested_target:
            self._add_aliases(profile, [profile.target, requested_target])
            profile.target = requested_target
        return profile

    def _read_profile_data(self, profile_path: Path) -> dict:
        with open(profile_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}

    def _hosts_aliases_for_target(self, target: str) -> set[str]:
        """Return host/IP aliases from the OS hosts file, including untagged lines."""
        normalized = self._normalize_target(target)
        aliases = {normalized} if normalized else set()

        try:
            from src.repl import hosts_manager

            for line in hosts_manager._read_hosts():
                code = line.split("#", 1)[0].strip()
                if not code:
                    continue
                parts = code.split()
                if len(parts) < 2:
                    continue
                ip, hostnames = parts[0].lower(), [h.lower() for h in parts[1:]]
                if normalized == ip or normalized in hostnames:
                    aliases.add(ip)
                    aliases.update(hostnames)
        except Exception:
            pass

        return {a for a in aliases if a}

    def _profile_identifiers(self, data: dict) -> set[str]:
        """Collect explicit target identifiers stored in a profile."""
        values: set[str] = set()
        for key in ("target", "aliases"):
            raw = data.get(key)
            if isinstance(raw, str):
                values.add(self._normalize_target(raw))
            elif isinstance(raw, list):
                values.update(self._normalize_target(str(v)) for v in raw)
        for key in ("ip_addresses", "subdomains"):
            raw = data.get(key, [])
            if isinstance(raw, list):
                values.update(self._normalize_target(str(v)) for v in raw)
        return {v for v in values if v}

    def _profile_mentions_alias(self, data: dict, aliases: set[str]) -> bool:
        identifiers = self._profile_identifiers(data)
        if identifiers & aliases:
            return True

        # WhatWeb and curl-derived tags often keep vhosts inside strings like
        # RedirectLocation[http://connected.htb/].
        searchable: list[str] = []
        for key in ("web_technologies", "notes", "api_endpoints", "devtools", "attack_paths"):
            raw = data.get(key, [])
            if isinstance(raw, list):
                searchable.extend(json.dumps(item, sort_keys=True).lower() for item in raw)
        blob = "\n".join(searchable)
        return any(alias and re.search(rf"(?<![\w.-]){re.escape(alias)}(?![\w.-])", blob) for alias in aliases)

    def _related_profile_paths(self, target: str, extra_aliases: set[str] | None = None) -> list[Path]:
        """Find existing profiles that describe the same host/vhost as target."""
        aliases = self._hosts_aliases_for_target(target)
        aliases.update(extra_aliases or set())
        paths: list[Path] = []
        for profile_path in self.base_dir.rglob("profile.json"):
            try:
                data = self._read_profile_data(profile_path)
            except Exception:
                continue
            if self._profile_mentions_alias(data, aliases):
                paths.append(profile_path)
        return paths

    def get_related_targets(self, target: str) -> set[str]:
        """Return known aliases and prior profile targets for the same machine."""
        related = self._hosts_aliases_for_target(target)
        exact_path = self._get_profile_path(target)
        if exact_path.exists():
            try:
                related.update(self._profile_identifiers(self._read_profile_data(exact_path)))
            except Exception:
                pass
        for profile_path in self._related_profile_paths(target, related):
            try:
                related.update(self._profile_identifiers(self._read_profile_data(profile_path)))
            except Exception:
                pass
        return {self._normalize_target(r) for r in related if r}

    def targets_equivalent(self, left: str, right: str) -> bool:
        """True when two target strings are known aliases of the same machine."""
        left_norm = self._normalize_target(left)
        right_norm = self._normalize_target(right)
        if not left_norm or not right_norm:
            return False
        if left_norm == right_norm:
            return True
        return right_norm in self.get_related_targets(left_norm) or left_norm in self.get_related_targets(right_norm)

    def _add_aliases(self, profile: TargetProfile, aliases: list[str] | set[str]):
        current = {self._normalize_target(a) for a in (profile.aliases or [])}
        current.add(self._normalize_target(profile.target))
        current.update(self._normalize_target(a) for a in aliases)
        profile.aliases = sorted(a for a in current if a and a != self._normalize_target(profile.target))

    def _merge_profile_data(self, profile: TargetProfile, data: dict):
        """Merge older alias profile evidence into the active target profile."""
        self._add_aliases(profile, self._profile_identifiers(data))

        def merge_simple_list(attr: str):
            existing = getattr(profile, attr)
            seen = {json.dumps(item, sort_keys=True) for item in existing}
            for item in data.get(attr, []) or []:
                marker = json.dumps(item, sort_keys=True)
                if marker not in seen:
                    existing.append(item)
                    seen.add(marker)

        def merge_keyed_dict_list(attr: str, keys: tuple[str, ...]):
            existing = getattr(profile, attr)
            index = {
                tuple(str(item.get(k, "")) for k in keys): item
                for item in existing
                if isinstance(item, dict)
            }
            for item in data.get(attr, []) or []:
                if not isinstance(item, dict):
                    continue
                marker = tuple(str(item.get(k, "")) for k in keys)
                if marker in index and any(marker):
                    for key, value in item.items():
                        if value and not index[marker].get(key):
                            index[marker][key] = value
                else:
                    existing.append(item)
                    if any(marker):
                        index[marker] = item

        # Ports are keyed by protocol/port so the new IP's baseline scan and the
        # old IP's service scan collapse into one useful row.
        port_index = {
            (p.get("protocol", "tcp"), p.get("port")): p
            for p in profile.ports
            if isinstance(p, dict)
        }
        for port in data.get("ports", []) or []:
            if not isinstance(port, dict):
                continue
            key = (port.get("protocol", "tcp"), port.get("port"))
            existing = port_index.get(key)
            if existing:
                for field_name in ("service", "version", "state"):
                    if port.get(field_name) and not existing.get(field_name):
                        existing[field_name] = port[field_name]
            else:
                profile.ports.append(port)
                port_index[key] = port

        merge_keyed_dict_list("vulnerabilities", ("name",))
        merge_keyed_dict_list("credentials", ("username", "password", "hash"))
        merge_keyed_dict_list("attack_paths", ("name",))
        merge_keyed_dict_list("notes", ("category", "text"))

        for attr in (
            "ip_addresses", "subdomains", "web_directories", "web_technologies",
            "api_endpoints", "devtools", "uploaded_shells", "hypotheses",
            "coverage_requirements", "sessions",
        ):
            merge_simple_list(attr)

        for attr in ("dns_records", "whois_info"):
            current = getattr(profile, attr)
            for key, value in (data.get(attr, {}) or {}).items():
                current.setdefault(key, value)
    
    def _get_profile_path(self, target: str) -> Path:
        """Get the profile file path for a target."""
        target_path = Path(target)
        if target_path.exists() and target_path.is_dir():
            return target_path / "profile.json"
            
        safe_name = self._profile_safe_name(target)
        return self.base_dir / safe_name / "profile.json"
    
    def load_profile(self, target: str) -> TargetProfile:
        """Load or create a target profile."""
        if target in self.profiles:
            return self.profiles[target]
        
        profile_path = self._get_profile_path(target)
        
        requested_target = self._normalize_target(target) or target
        related_paths = []
        if profile_path.exists():
            try:
                data = self._read_profile_data(profile_path)
                related_paths = self._related_profile_paths(target, self._profile_identifiers(data))
                profile = self._profile_from_data(data, requested_target=requested_target)
                self._add_aliases(profile, self._hosts_aliases_for_target(target))
                for related_path in related_paths:
                    if related_path.resolve() == profile_path.resolve():
                        continue
                    try:
                        self._merge_profile_data(profile, self._read_profile_data(related_path))
                    except Exception as merge_error:
                        logger.debug(f"Failed to merge alias profile {related_path}: {merge_error}")
                logger.info(f"Loaded profile for {target}")
            except Exception as e:
                logger.warning(f"Failed to load profile: {e}")
                profile = TargetProfile(target=target)
        else:
            related_paths = self._related_profile_paths(target)

        if not profile_path.exists() and related_paths:
            try:
                data = self._read_profile_data(related_paths[0])
                profile = self._profile_from_data(data, requested_target=requested_target)
                self._add_aliases(profile, self._hosts_aliases_for_target(target))
                for related_path in related_paths[1:]:
                    try:
                        self._merge_profile_data(profile, self._read_profile_data(related_path))
                    except Exception as merge_error:
                        logger.debug(f"Failed to merge alias profile {related_path}: {merge_error}")
                logger.info(f"Loaded alias profile for {target} from {related_paths[0]}")
            except Exception as e:
                logger.warning(f"Failed to load alias profile: {e}")
                profile = TargetProfile(target=target)
        elif not profile_path.exists():
            profile = TargetProfile(target=target)
        
        self.profiles[target] = profile
        return profile
    
    def save_profile(self, target: str):
        """Save a target profile to disk."""
        if target not in self.profiles:
            return
        
        profile = self.profiles[target]
        profile_path = self._get_profile_path(target)
        profile_path.parent.mkdir(parents=True, exist_ok=True)

        # The REPL can keep profiles hot in memory while tools or the operator
        # update profile.json on disk. Merge disk state before saving so a later
        # registration call does not wipe notes, sessions, or artifacts captured
        # by another code path.
        if profile_path.exists():
            try:
                disk_data = self._read_profile_data(profile_path)
                if disk_data:
                    self._merge_profile_data(profile, disk_data)
            except Exception as merge_error:
                logger.debug(f"Failed to merge current disk profile before save: {merge_error}")
        
        profile.updated_at = datetime.now().isoformat()
        
        with open(profile_path, 'w', encoding='utf-8') as f:
            json.dump(asdict(profile), f, indent=2)
        
        logger.info(f"Saved profile for {target}")

    def register_aliases(self, target: str, aliases: list[str] | set[str]) -> TargetProfile:
        """
        Record host/IP aliases for a target and merge any matching historical profile.

        This is intentionally independent from the OS hosts file. HTB users often
        cannot write /etc/hosts without sudo, but the workspace should still know
        that a rotated IP and a stable vhost are the same machine.
        """
        normalized_aliases = {self._normalize_target(a) for a in aliases}
        normalized_aliases = {a for a in normalized_aliases if a}

        # If the profile is already loaded, enrich it. Otherwise start from any
        # historical profile that mentions the supplied aliases.
        if target in self.profiles:
            profile = self.profiles[target]
        else:
            related_paths = self._related_profile_paths(target, normalized_aliases | {self._normalize_target(target)})
            if related_paths:
                try:
                    profile = self._profile_from_data(
                        self._read_profile_data(related_paths[0]),
                        requested_target=self._normalize_target(target) or target,
                    )
                    for related_path in related_paths[1:]:
                        self._merge_profile_data(profile, self._read_profile_data(related_path))
                    self.profiles[target] = profile
                except Exception as e:
                    logger.debug(f"Failed to seed alias profile for {target}: {e}")
                    profile = self.load_profile(target)
            else:
                profile = self.load_profile(target)

        self._add_aliases(profile, normalized_aliases | {target})
        for related_path in self._related_profile_paths(target, normalized_aliases | self._profile_identifiers(asdict(profile))):
            try:
                self._merge_profile_data(profile, self._read_profile_data(related_path))
            except Exception as merge_error:
                logger.debug(f"Failed to merge alias profile {related_path}: {merge_error}")
        self.save_profile(target)
        return profile
    
    def add_port(self, target: str, port: int, protocol: str = "tcp", 
                 service: str = "", version: str = ""):
        """Add a discovered port."""
        profile = self.load_profile(target)
        
        # Check if port already exists
        for p in profile.ports:
            if p["port"] == port and p["protocol"] == protocol:
                p["service"] = service or p.get("service", "")
                p["version"] = version or p.get("version", "")
                self.save_profile(target)
                return
        
        profile.ports.append({
            "port": port,
            "protocol": protocol,
            "service": service,
            "version": version,
            "state": "open"
        })
        self.save_profile(target)
    
    def add_subdomain(self, target: str, subdomain: str):
        """Add a discovered subdomain."""
        profile = self.load_profile(target)
        if subdomain not in profile.subdomains:
            profile.subdomains.append(subdomain)
            self.save_profile(target)
    
    def add_ip_address(self, target: str, ip: str):
        """Add a discovered IP address."""
        profile = self.load_profile(target)
        if ip not in profile.ip_addresses:
            profile.ip_addresses.append(ip)
            self.save_profile(target)
    
    def add_vulnerability(self, target: str, name: str, severity: str = "unknown",
                         cve: str = "", description: str = "", verified: bool = False):
        """Add a discovered vulnerability."""
        profile = self.load_profile(target)
        
        vuln = {
            "name": name,
            "severity": severity,
            "cve": cve,
            "description": description,
            "verified": verified,
            "discovered_at": datetime.now().isoformat()
        }
        
        # Check if already exists
        for v in profile.vulnerabilities:
            if v["name"] == name:
                v.update({
                    "severity": severity,
                    "cve": cve,
                    "description": description,
                    "verified": verified,
                    "updated_at": datetime.now().isoformat()
                })
                self.save_profile(target)
                return
        
        profile.vulnerabilities.append(vuln)
        self.save_profile(target)
    
    def add_credential(self, target: str, username: str, password: str = "",
                       hash: str = "", source: str = ""):
        """Add a discovered credential."""
        profile = self.load_profile(target)
        
        cred = {
            "username": username,
            "password": password,
            "hash": hash,
            "source": source,
            "discovered_at": datetime.now().isoformat()
        }
        
        profile.credentials.append(cred)
        self.save_profile(target)
    
    def add_note(self, target: str, note: str, category: str = "general"):
        """Add a note to the target."""
        profile = self.load_profile(target)
        profile.notes.append({
            "text": note,
            "category": category,
            "timestamp": datetime.now().isoformat()
        })
        self.save_profile(target)

    def add_web_directory(self, target: str, path: str):
        """Add a discovered web path/directory (e.g. '/admin', '/.git/')."""
        if not path:
            return
        profile = self.load_profile(target)

        # Normalise: accept either a bare path or a full URL
        _path = path.strip()
        if "://" in _path:
            try:
                import urllib.parse
                _path = urllib.parse.urlparse(_path).path or "/"
            except Exception:
                pass
        if not _path.startswith("/"):
            _path = "/" + _path

        if _path not in profile.web_directories:
            profile.web_directories.append(_path)
            self.save_profile(target)

    def add_web_technology(self, target: str, tech: str):
        """Add a discovered web technology tag (e.g. 'nginx', 'WordPress')."""
        if not tech:
            return
        profile = self.load_profile(target)
        # Strip ANSI escape codes (WhatWeb outputs terminal colours)
        import re as _re
        _t = _re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', tech).strip()
        if not _t:
            return
        # Also strip from existing entries on first encounter (one-time cleanup)
        profile.web_technologies = [
            _re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', t).strip()
            for t in profile.web_technologies if _re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', t).strip()
        ]
        if _t not in profile.web_technologies:
            profile.web_technologies.append(_t)
            self.save_profile(target)

    def add_api_endpoint(self, target: str, url: str, method: str = "",
                         source: str = "", notes: str = ""):
        """Persist an API endpoint or route discovered during recon."""
        if not url:
            return
        profile = self.load_profile(target)
        endpoint = {
            "url": url.strip(),
            "method": method.upper().strip(),
            "source": source,
            "notes": notes[:500],
            "discovered_at": datetime.now().isoformat(),
        }
        for existing in profile.api_endpoints:
            if existing.get("url") == endpoint["url"] and existing.get("method", "") == endpoint["method"]:
                if notes and not existing.get("notes"):
                    existing["notes"] = endpoint["notes"]
                    self.save_profile(target)
                return
        profile.api_endpoints.append(endpoint)
        self.save_profile(target)

    def add_devtool(self, target: str, name: str, url: str = "", risk: str = "info",
                    evidence: str = "", next_step: str = ""):
        """Persist exposed development/admin tooling such as MCP Inspector or Jupyter."""
        if not name:
            return
        profile = self.load_profile(target)
        entry = {
            "name": name.strip(),
            "url": url.strip(),
            "risk": risk.lower().strip() or "info",
            "evidence": evidence[:500],
            "next_step": next_step[:500],
            "discovered_at": datetime.now().isoformat(),
        }
        for existing in profile.devtools:
            if existing.get("name") == entry["name"] and existing.get("url") == entry["url"]:
                existing.update({k: v for k, v in entry.items() if v})
                self.save_profile(target)
                return
        profile.devtools.append(entry)
        self.save_profile(target)

    def add_attack_path(self, target: str, name: str, steps: List[str],
                        confidence: str = "medium", status: str = "candidate"):
        """Persist a multi-step attack path so later sessions can resume it."""
        if not name or not steps:
            return
        profile = self.load_profile(target)
        entry = {
            "name": name.strip(),
            "steps": [s.strip() for s in steps if s and s.strip()],
            "confidence": confidence.lower().strip() or "medium",
            "status": status.lower().strip() or "candidate",
            "updated_at": datetime.now().isoformat(),
        }
        for existing in profile.attack_paths:
            if existing.get("name") == entry["name"]:
                existing.update(entry)
                self.save_profile(target)
                return
        profile.attack_paths.append(entry)
        self.save_profile(target)

    def add_uploaded_shell(self, target: str, entry: Dict):
        """Persist enough shell/upload metadata to replay or validate it later."""
        profile = self.load_profile(target)
        clean = {
            "filename": str(entry.get("filename", "")).strip(),
            "url": str(entry.get("url", "")).strip(),
            "payload_path": str(entry.get("payload_path", "")).strip(),
            "payload_body": str(entry.get("payload_body", ""))[:4000],
            "upload_url": str(entry.get("upload_url", "")).strip(),
            "upload_field": str(entry.get("upload_field", "")).strip(),
            "cookies_ref": str(entry.get("cookies_ref", ""))[:500],
            "verification_command": str(entry.get("verification_command", ""))[:1000],
            "source_tool": str(entry.get("source_tool", "")).strip(),
            "notes": str(entry.get("notes", ""))[:1000],
            "recorded_at": datetime.now().isoformat(),
        }
        if not (clean["filename"] or clean["url"] or clean["payload_path"]):
            return
        for existing in profile.uploaded_shells:
            same_name = clean["filename"] and existing.get("filename") == clean["filename"]
            same_url = clean["url"] and existing.get("url") == clean["url"]
            if same_name or same_url:
                existing.update({k: v for k, v in clean.items() if v})
                existing["updated_at"] = datetime.now().isoformat()
                self.save_profile(target)
                return
        profile.uploaded_shells.append(clean)
        self.save_profile(target)

    def set_engagement_mode(self, target: str, mode: str):
        """Set the assessment behavior mode for the target."""
        if not mode:
            return
        profile = self.load_profile(target)
        profile.engagement_mode = mode.strip().lower()
        self.save_profile(target)

    def set_hypotheses(self, target: str, hypotheses: List[Dict]):
        """Replace the persisted hypothesis queue for a target."""
        profile = self.load_profile(target)
        profile.hypotheses = hypotheses or []
        self.save_profile(target)

    def set_coverage_requirements(self, target: str, requirements: List[Dict]):
        """Replace the persisted coverage checklist for a target."""
        profile = self.load_profile(target)
        profile.coverage_requirements = requirements or []
        self.save_profile(target)
    
    def add_session(self, target: str, session_id: str):
        """Link a session to this target."""
        profile = self.load_profile(target)
        if session_id not in profile.sessions:
            profile.sessions.append(session_id)
            self.save_profile(target)
    
    def get_summary(self, target: str) -> str:
        """Get a summary of the target profile."""
        profile = self.load_profile(target)
        
        summary = f"""
═══════════════════════════════════════════════════════════
TARGET PROFILE: {profile.target}
═══════════════════════════════════════════════════════════
Created: {profile.created_at}
Updated: {profile.updated_at}

📡 NETWORK
───────────────────────────────────────────────────────────
IPs: {', '.join(profile.ip_addresses) or 'None discovered'}
Open Ports: {len(profile.ports)}
"""
        if profile.ports:
            for p in profile.ports[:10]:
                summary += f"  • {p['port']}/{p['protocol']} - {p.get('service', 'unknown')} {p.get('version', '')}\n"
            if len(profile.ports) > 10:
                summary += f"  ... and {len(profile.ports) - 10} more\n"

        summary += f"""
🌐 SUBDOMAINS ({len(profile.subdomains)})
───────────────────────────────────────────────────────────
"""
        if profile.subdomains:
            for s in profile.subdomains[:10]:
                summary += f"  • {s}\n"
            if len(profile.subdomains) > 10:
                summary += f"  ... and {len(profile.subdomains) - 10} more\n"

        summary += f"""
⚠️  VULNERABILITIES ({len(profile.vulnerabilities)})
───────────────────────────────────────────────────────────
"""
        if profile.vulnerabilities:
            for v in profile.vulnerabilities[:5]:
                summary += f"  • [{v.get('severity', 'unknown').upper()}] {v['name']}\n"

        summary += f"""
🔑 CREDENTIALS ({len(profile.credentials)})
───────────────────────────────────────────────────────────
"""
        if profile.credentials:
            for c in profile.credentials[:5]:
                pwd = c.get('password', '')[:8] + '...' if c.get('password') else '[hash]'
                summary += f"  • {c['username']}:{pwd}\n"

        summary += f"""
📁 SESSIONS: {len(profile.sessions)}
═══════════════════════════════════════════════════════════
"""
        return summary


    def get_context_brief(self, target: str, max_subdomains: int = 20, max_ports: int = 30) -> str:
        """
        Return a compact, agent-readable context string for injection into handoff tasks.
        Covers: IPs, open ports/services, subdomains, vulnerabilities, credentials, web dirs, technologies.
        Sub-agents receiving this MUST skip recon they already have data for.
        """
        profile = self.load_profile(target)

        # Only build sections that actually have data
        sections: list[str] = []

        if profile.ip_addresses:
            sections.append(f"IPs: {', '.join(profile.ip_addresses)}")

        if profile.ports:
            port_lines = []
            for p in profile.ports[:max_ports]:
                svc = p.get('service', '')
                ver = p.get('version', '')
                label = f"{p['port']}/{p.get('protocol','tcp')}"
                if svc:
                    label += f" ({svc}{' ' + ver if ver else ''})"
                port_lines.append(label)
            extra = len(profile.ports) - max_ports
            tail = f" +{extra} more" if extra > 0 else ""
            sections.append(f"Open ports: {', '.join(port_lines)}{tail}")

        if profile.subdomains:
            shown = profile.subdomains[:max_subdomains]
            extra = len(profile.subdomains) - max_subdomains
            tail = f" +{extra} more" if extra > 0 else ""
            sections.append(f"Subdomains ({len(profile.subdomains)} total): {', '.join(shown)}{tail}")

        if profile.vulnerabilities:
            vuln_lines = []
            for v in profile.vulnerabilities:
                sev = v.get('severity', 'unknown').upper()
                cve = f" [{v['cve']}]" if v.get('cve') else ""
                vuln_lines.append(f"[{sev}] {v['name']}{cve}")
            sections.append(f"Known vulnerabilities: {'; '.join(vuln_lines)}")

        if profile.credentials:
            cred_lines = []
            for c in profile.credentials[:5]:
                pwd = c.get('password', '')
                entry = c['username'] + (f":{pwd}" if pwd else " (hash only)")
                cred_lines.append(entry)
            sections.append(f"Credentials: {', '.join(cred_lines)}")
            
        scope_notes = [n['text'] for n in profile.notes if n.get('category') == 'scope']
        if scope_notes:
            sections.append("Target Scope Details:\n" + "\n".join(scope_notes))

        context_notes = [
            n for n in profile.notes
            if n.get('category') in {'database', 'extraction', 'exploitation', 'finding'}
        ]
        if context_notes:
            note_lines = []
            for n in context_notes[:8]:
                category = n.get('category', 'note')
                note_lines.append(f"[{category}] {n.get('text', '')[:500]}")
            sections.append("Operational notes:\n" + "\n".join(note_lines))

        if profile.web_technologies:
            sections.append(f"Web stack: {', '.join(profile.web_technologies[:10])}")

        if profile.web_directories:
            shown = profile.web_directories[:15]
            sections.append(f"Discovered paths: {', '.join(shown)}")

        if profile.api_endpoints:
            shown = []
            for e in profile.api_endpoints[:15]:
                method = e.get("method") or "ANY"
                shown.append(f"{method} {e.get('url')}")
            sections.append(f"API endpoints: {'; '.join(shown)}")

        if profile.devtools:
            shown = []
            for d in profile.devtools[:8]:
                label = d.get("name", "devtool")
                url = d.get("url", "")
                next_step = d.get("next_step", "")
                shown.append(f"{label} at {url}" + (f" -> {next_step}" if next_step else ""))
            sections.append(f"Exposed dev/admin tooling: {'; '.join(shown)}")

        if profile.attack_paths:
            paths = []
            for p in profile.attack_paths[:5]:
                steps = " -> ".join(p.get("steps", [])[:6])
                paths.append(f"{p.get('name')} ({p.get('confidence','medium')}): {steps}")
            sections.append(f"Candidate attack paths: {'; '.join(paths)}")

        if profile.sessions:
            artifact_lines = []
            interesting_names = {
                "enumeration.json",
                "schema.json",
                "full_schema.json",
                "all_tables.json",
                "creds_partial.json",
                "members_dump_fast.json",
                "members_full_dump.json",
                "members_complete.json",
            }
            for session_id in profile.sessions[-3:]:
                session_dir = self.base_dir / self._profile_safe_name(target) / f"session_{session_id}"
                if not session_dir.exists():
                    continue
                found = [
                    p.name for p in session_dir.iterdir()
                    if p.is_file() and p.name in interesting_names and p.stat().st_size > 0
                ]
                if found:
                    artifact_lines.append(f"session_{session_id}: {', '.join(sorted(found))}")
            if artifact_lines:
                sections.append("Session artifacts:\n" + "\n".join(artifact_lines))

        if profile.uploaded_shells:
            shells = []
            for shell in profile.uploaded_shells[:8]:
                label = shell.get("filename") or shell.get("url") or shell.get("payload_path")
                route = shell.get("upload_url") or shell.get("source_tool") or ""
                verify = shell.get("verification_command") or shell.get("url") or ""
                shells.append(
                    f"{label}"
                    + (f" via {route}" if route else "")
                    + (f" verify={verify}" if verify else "")
                )
            sections.append(f"Uploaded shells/artifacts: {'; '.join(shells)}")

        if profile.engagement_mode:
            sections.append(f"Engagement mode: {profile.engagement_mode}")

        if profile.hypotheses:
            rows = []
            for h in profile.hypotheses[:5]:
                rows.append(
                    f"{h.get('name')} [{h.get('status','candidate')}] "
                    f"score={h.get('score')} tools={', '.join(h.get('next_tools', [])[:4])}"
                )
            sections.append(f"Active hypotheses: {'; '.join(rows)}")

        if profile.coverage_requirements:
            pending = [
                c.get("requirement", "")
                for c in profile.coverage_requirements
                if c.get("status", "pending") != "done"
            ][:6]
            if pending:
                sections.append(f"Pending coverage: {'; '.join(pending)}")

        if profile.dns_records:
            rec_parts = []
            for rtype, vals in list(profile.dns_records.items())[:4]:
                rec_parts.append(f"{rtype}: {', '.join(vals[:3])}")
            sections.append(f"DNS: {'; '.join(rec_parts)}")

        if not sections:
            return ""  # No recon data yet — let sub-agent do its own recon

        return "[EXISTING RECON DATA — do NOT re-run these checks]\n" + "\n".join(sections)


# Global instance
_profile_manager: Optional[TargetProfileManager] = None


def get_profile_manager() -> TargetProfileManager:
    """Get or create the global profile manager."""
    global _profile_manager
    if _profile_manager is None:
        _profile_manager = TargetProfileManager()
    return _profile_manager
