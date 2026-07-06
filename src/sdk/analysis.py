"""
Finding Analysis Utilities
Merged from: confidence.py, dedup.py, diff_analyzer.py

Provides:
- ConfidenceScore / confidence scoring for findings
- FindingsDeduplicator / deduplication of overlapping findings
- DifferentialAnalyzer / LLM-based differential response comparison
"""

from __future__ import annotations

import hashlib
import textwrap
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from loguru import logger

# ─── TYPE_CHECKING guard to avoid circular imports ───────────────────────────
if TYPE_CHECKING:
    pass  # no runtime imports

# ─────────────────────────────────────────────────────────────────────────────
# CONFIDENCE SCORING  (was confidence.py)
# ─────────────────────────────────────────────────────────────────────────────


class ConfidenceLevel(Enum):
    """Confidence level enumeration"""
    CONFIRMED = "CONFIRMED"    # 90-100 points
    HIGH = "HIGH"              # 70-89 points
    MEDIUM = "MEDIUM"          # 50-69 points
    LOW = "LOW"                # 0-49 points


@dataclass
class ConfidenceScore:
    """
    Vulnerability confidence scoring system.
    
    Example scoring:
    - SQLi detected by scanner: +20 automated
    - Boolean-based verification: +30 manual
    - Database version extracted: +50 exploitation
    Total: 100 = CONFIRMED
    """
    
    automated_detection: int = 0    # 0-20 points: Tool detected the vulnerability
    manual_verification: int = 0     # 0-30 points: Response analysis confirmed behavior
    exploitation_proof: int = 0      # 0-50 points: Actual exploitation succeeded
    
    # Metadata
    vulnerability_type: str = ""
    target: str = ""
    parameter: str = ""
    evidence: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    
    @property
    def total(self) -> int:
        """Calculate total confidence score (0-100)"""
        score = self.automated_detection + self.manual_verification + self.exploitation_proof
        return min(100, max(0, score))  # Clamp to 0-100
    
    @property
    def level(self) -> ConfidenceLevel:
        """Get confidence level based on total score"""
        if self.total >= 90:
            return ConfidenceLevel.CONFIRMED
        elif self.total >= 70:
            return ConfidenceLevel.HIGH
        elif self.total >= 50:
            return ConfidenceLevel.MEDIUM
        else:
            return ConfidenceLevel.LOW
    
    @property
    def is_reportable(self) -> bool:
        """Only report findings with 70+ confidence (HIGH or CONFIRMED)"""
        return self.total >= 70
    
    @property
    def requires_validation(self) -> bool:
        """Check if finding needs more validation"""
        return self.total < 70
    
    def add_evidence(self, evidence: str):
        """Add evidence to the score"""
        self.evidence.append(evidence)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        return {
            "total_score": self.total,
            "level": self.level.value,
            "is_reportable": self.is_reportable,
            "breakdown": {
                "automated_detection": self.automated_detection,
                "manual_verification": self.manual_verification,
                "exploitation_proof": self.exploitation_proof
            },
            "vulnerability_type": self.vulnerability_type,
            "target": self.target,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "timestamp": self.timestamp.isoformat()
        }
    
    def __str__(self) -> str:
        """String representation"""
        return f"{self.level.value} ({self.total}/100) - {self.vulnerability_type}"


def score_sqli_finding(
    error_detected: bool = False,
    boolean_verified: bool = False,
    time_delay_confirmed: bool = False,
    data_extracted: bool = False
) -> ConfidenceScore:
    """
    Score SQL Injection finding based on validation steps.
    
    Args:
        error_detected: SQL error messages found
        boolean_verified: Boolean-based blind SQLi confirmed
        time_delay_confirmed: Time-based blind SQLi confirmed
        data_extracted: Actual data extraction succeeded
    
    Returns:
        ConfidenceScore with appropriate scoring
    """
    score = ConfidenceScore(vulnerability_type="sql_injection")
    
    # Automated detection (0-20)
    if error_detected:
        score.automated_detection = 20
        score.add_evidence("SQL error messages detected")
    
    # Manual verification (0-30)
    if boolean_verified:
        score.manual_verification = 30
        score.add_evidence("Boolean-based blind SQLi verified (true/false response difference)")
    elif time_delay_confirmed:
        score.manual_verification = 30
        score.add_evidence("Time-based blind SQLi verified (sleep/delay executed)")
    
    # Exploitation proof (0-50)
    if data_extracted:
        score.exploitation_proof = 50
        score.add_evidence("Database version/data successfully extracted")
    elif time_delay_confirmed:
        score.exploitation_proof = 40  # Time delay is strong proof
    elif boolean_verified:
        score.exploitation_proof = 25  # Boolean is moderate proof
    
    return score


def score_xss_finding(
    payload_reflected: bool = False,
    payload_unencoded: bool = False,
    js_executed: bool = False,
    dom_modified: bool = False
) -> ConfidenceScore:
    """
    Score XSS finding based on validation steps.
    
    Args:
        payload_reflected: Payload appears in response
        payload_unencoded: Payload is not HTML-encoded
        js_executed: JavaScript actually executed in browser
        dom_modified: DOM was modified by payload
    
    Returns:
        ConfidenceScore with appropriate scoring
    """
    score = ConfidenceScore(vulnerability_type="xss")
    
    # Automated detection (0-20)
    if payload_reflected:
        score.automated_detection = 20
        score.add_evidence("XSS payload reflected in response")
    
    # Manual verification (0-30)
    if payload_unencoded:
        score.manual_verification = 30
        score.add_evidence("Payload reflected without HTML encoding")
    
    # Exploitation proof (0-50)
    if js_executed and dom_modified:
        score.exploitation_proof = 50
        score.add_evidence("JavaScript executed in browser and modified DOM")
    elif js_executed:
        score.exploitation_proof = 40
        score.add_evidence("JavaScript executed in browser")
    elif payload_unencoded:
        score.exploitation_proof = 20  # Likely exploitable but not proven
    
    return score


def score_ssrf_finding(
    internal_ip_accepted: bool = False,
    localhost_accessed: bool = False,
    callback_received: bool = False,
    internal_service_exposed: bool = False
) -> ConfidenceScore:
    """
    Score SSRF finding based on validation steps.
    
    Args:
        internal_ip_accepted: Server accepts internal IP ranges
        localhost_accessed: Localhost access confirmed
        callback_received: External callback server received request
        internal_service_exposed: Internal service data retrieved
    
    Returns:
        ConfidenceScore with appropriate scoring
    """
    score = ConfidenceScore(vulnerability_type="ssrf")
    
    # Automated detection (0-20)
    if internal_ip_accepted or localhost_accessed:
        score.automated_detection = 20
        score.add_evidence("Internal/localhost URLs accepted")
    
    # Manual verification (0-30)
    if callback_received:
        score.manual_verification = 30
        score.add_evidence("Callback received from target server")
    
    # Exploitation proof (0-50)
    if internal_service_exposed:
        score.exploitation_proof = 50
        score.add_evidence("Internal service data successfully retrieved")
    elif callback_received:
        score.exploitation_proof = 35
        score.add_evidence("Server made outbound request (confirmed SSRF)")
    
    return score


def score_command_injection_finding(
    special_chars_accepted: bool = False,
    time_delay_triggered: bool = False,
    command_executed: bool = False,
    output_captured: bool = False
) -> ConfidenceScore:
    """Score Command Injection finding"""
    score = ConfidenceScore(vulnerability_type="command_injection")
    
    if special_chars_accepted:
        score.automated_detection = 20
        score.add_evidence("Special characters (;|&) accepted")
    
    if time_delay_triggered:
        score.manual_verification = 30
        score.add_evidence("Time delay triggered via sleep/ping")
    
    if output_captured:
        score.exploitation_proof = 50
        score.add_evidence("Command output captured in response")
    elif command_executed:
        score.exploitation_proof = 40
        score.add_evidence("Command execution confirmed")
    
    return score


def score_path_traversal_finding(
    traversal_chars_accepted: bool = False,
    file_signatures_found: bool = False,
    file_content_retrieved: bool = False,
    sensitive_file_accessed: bool = False
) -> ConfidenceScore:
    """Score Path Traversal/LFI finding"""
    score = ConfidenceScore(vulnerability_type="path_traversal")
    
    if traversal_chars_accepted:
        score.automated_detection = 20
        score.add_evidence("Path traversal characters (../) accepted")
    
    if file_signatures_found:
        score.manual_verification = 30
        score.add_evidence("Known file signatures detected in response")
    
    if sensitive_file_accessed:
        score.exploitation_proof = 50
        score.add_evidence("Sensitive file content successfully retrieved")
    elif file_content_retrieved:
        score.exploitation_proof = 35
        score.add_evidence("File content retrieved")
    
    return score


# Global confidence tracker
_confidence_scores: List[ConfidenceScore] = []


def register_confidence_score(score: ConfidenceScore):
    """Register a confidence score for tracking"""
    _confidence_scores.append(score)


def get_reportable_findings() -> List[ConfidenceScore]:
    """Get only findings with 70+ confidence (reportable)"""
    return [s for s in _confidence_scores if s.is_reportable]


def get_all_scores() -> List[ConfidenceScore]:
    """Get all confidence scores"""
    return _confidence_scores


def get_scores_by_level(level: ConfidenceLevel) -> List[ConfidenceScore]:
    """Get scores by confidence level"""
    return [s for s in _confidence_scores if s.level == level]


def clear_scores():
    """Clear all tracked scores"""
    global _confidence_scores
    _confidence_scores = []

# ─────────────────────────────────────────────────────────────────────────────
# FINDINGS DEDUPLICATOR  (was dedup.py)
# NOTE: SHA-256 (truncated to 16 hex chars) is used for fingerprint keys.
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class UnifiedFinding:
    """A deduplicated finding with confidence scoring."""
    id: str
    title: str
    category: str  # port, subdomain, vulnerability, credential, directory, technology, cve
    severity: str = "info"  # critical, high, medium, low, info
    confidence: float = 0.0  # 0.0 - 1.0
    sources: List[str] = field(default_factory=list)  # Tools that reported this
    first_seen: str = ""
    last_seen: str = ""
    data: Dict[str, Any] = field(default_factory=dict)  # Raw data
    related_findings: List[str] = field(default_factory=list)  # IDs of related findings
    false_positive: bool = False
    validated: bool = False
    
    def __post_init__(self):
        if not self.first_seen:
            self.first_seen = datetime.now().isoformat()
        self.last_seen = datetime.now().isoformat()


class FindingsDeduplicator:
    """
    Central deduplication engine for all discoveries.
    Merges findings from multiple tools, assigns confidence scores,
    and maintains a single source of truth.
    """
    
    def __init__(self):
        self.findings: Dict[str, UnifiedFinding] = {}  # id -> finding
        self._index_by_category: Dict[str, List[str]] = {}  # category -> [ids]
        self._index_by_target: Dict[str, List[str]] = {}  # target_key -> [ids]
    
    def _generate_id(self, category: str, key: str) -> str:
        """Generate a deterministic finding ID (SHA-256 truncated to 16 chars)."""
        raw = f"{category}:{key}".lower().strip()
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
    
    def _normalize_vuln_name(self, name: str) -> str:
        """Normalize vulnerability names for matching."""
        name = name.lower().strip()
        # Common aliases
        aliases = {
            "sqli": "sql_injection",
            "sql injection": "sql_injection", 
            "sql-injection": "sql_injection",
            "xss": "cross_site_scripting",
            "cross-site scripting": "cross_site_scripting",
            "cross site scripting": "cross_site_scripting",
            "reflected xss": "cross_site_scripting_reflected",
            "stored xss": "cross_site_scripting_stored",
            "dom xss": "cross_site_scripting_dom",
            "csrf": "cross_site_request_forgery",
            "ssrf": "server_side_request_forgery",
            "ssti": "server_side_template_injection",
            "template injection": "server_side_template_injection",
            "lfi": "local_file_inclusion",
            "local file inclusion": "local_file_inclusion",
            "rfi": "remote_file_inclusion",
            "rce": "remote_code_execution",
            "remote code execution": "remote_code_execution",
            "command injection": "os_command_injection",
            "cmd injection": "os_command_injection",
            "os command injection": "os_command_injection",
            "idor": "insecure_direct_object_reference",
            "open redirect": "open_redirect",
            "directory traversal": "path_traversal",
            "path traversal": "path_traversal",
            "xxe": "xml_external_entity",
            "nosql injection": "nosql_injection",
            "nosqli": "nosql_injection",
            "jwt": "jwt_vulnerability",
            "broken authentication": "broken_authentication",
            "weak password": "weak_credentials",
            "default credentials": "default_credentials",
            "default password": "default_credentials",
            "info disclosure": "information_disclosure",
            "information disclosure": "information_disclosure",
            "directory listing": "directory_listing",
            "cors": "cors_misconfiguration",
            "clickjacking": "clickjacking",
            "host header injection": "host_header_injection",
        }
        
        for alias, canonical in aliases.items():
            if alias in name:
                return canonical
        
        return name.replace(" ", "_").replace("-", "_")
    
    def add_port(self, port: int, protocol: str, service: str, 
                 version: str, source_tool: str, target: str = "") -> UnifiedFinding:
        """Add or merge a port finding."""
        key = f"{target}:{port}/{protocol}"
        fid = self._generate_id("port", key)
        
        if fid in self.findings:
            existing = self.findings[fid]
            if source_tool not in existing.sources:
                existing.sources.append(source_tool)
            # Update with richer data
            if service and not existing.data.get("service"):
                existing.data["service"] = service
            if version and not existing.data.get("version"):
                existing.data["version"] = version
            existing.confidence = min(1.0, len(existing.sources) * 0.35)
            existing.last_seen = datetime.now().isoformat()
            return existing
        
        finding = UnifiedFinding(
            id=fid,
            title=f"Port {port}/{protocol} - {service or 'unknown'}",
            category="port",
            severity="info",
            confidence=0.35,
            sources=[source_tool],
            data={
                "port": port,
                "protocol": protocol,
                "service": service,
                "version": version,
                "target": target
            }
        )
        self._store(finding, target)
        return finding
    
    def add_subdomain(self, subdomain: str, source_tool: str, 
                      target: str = "") -> UnifiedFinding:
        """Add or merge a subdomain finding."""
        subdomain = subdomain.lower().strip()
        fid = self._generate_id("subdomain", subdomain)
        
        if fid in self.findings:
            existing = self.findings[fid]
            if source_tool not in existing.sources:
                existing.sources.append(source_tool)
            existing.confidence = min(1.0, len(existing.sources) * 0.3)
            existing.last_seen = datetime.now().isoformat()
            return existing
        
        finding = UnifiedFinding(
            id=fid,
            title=subdomain,
            category="subdomain",
            severity="info",
            confidence=0.3,
            sources=[source_tool],
            data={"subdomain": subdomain, "target": target}
        )
        self._store(finding, target)
        return finding
    
    def add_vulnerability(self, name: str, severity: str, source_tool: str,
                          target: str = "", cve: str = "", url: str = "",
                          description: str = "", evidence: str = "") -> UnifiedFinding:
        """Add or merge a vulnerability finding."""
        normalized = self._normalize_vuln_name(name)
        
        # Use CVE as key if available (strongest dedup signal)
        if cve:
            key = f"{target}:{cve}"
        else:
            key = f"{target}:{normalized}:{url}" if url else f"{target}:{normalized}"
        
        fid = self._generate_id("vulnerability", key)
        
        if fid in self.findings:
            existing = self.findings[fid]
            if source_tool not in existing.sources:
                existing.sources.append(source_tool)
            # Upgrade severity if higher
            existing.severity = self._higher_severity(existing.severity, severity)
            # Increase confidence
            existing.confidence = min(1.0, len(existing.sources) * 0.3 + (0.2 if cve else 0))
            existing.last_seen = datetime.now().isoformat()
            if evidence and evidence not in existing.data.get("evidence", []):
                existing.data.setdefault("evidence", []).append(evidence[:500])
            return existing
        
        finding = UnifiedFinding(
            id=fid,
            title=name,
            category="vulnerability",
            severity=severity.lower(),
            confidence=0.3 + (0.2 if cve else 0),
            sources=[source_tool],
            data={
                "name": normalized,
                "original_name": name,
                "cve": cve,
                "url": url,
                "description": description,
                "evidence": [evidence[:500]] if evidence else [],
                "target": target
            }
        )
        self._store(finding, target)
        return finding
    
    def add_credential(self, username: str, password: str = "", hash_val: str = "",
                       source_tool: str = "", target: str = "") -> UnifiedFinding:
        """Add or merge a credential finding."""
        key = f"{target}:{username}:{hash_val or password}"
        fid = self._generate_id("credential", key)
        
        if fid in self.findings:
            existing = self.findings[fid]
            if source_tool and source_tool not in existing.sources:
                existing.sources.append(source_tool)
            # Update with cracked password if new
            if password and not existing.data.get("password"):
                existing.data["password"] = password
            existing.confidence = min(1.0, len(existing.sources) * 0.4)
            existing.last_seen = datetime.now().isoformat()
            return existing
        
        finding = UnifiedFinding(
            id=fid,
            title=f"Credential: {username}",
            category="credential",
            severity="high",
            confidence=0.4,
            sources=[source_tool] if source_tool else [],
            data={
                "username": username,
                "password": password,
                "hash": hash_val,
                "target": target
            }
        )
        self._store(finding, target)
        return finding
    
    def add_directory(self, path: str, status_code: int, source_tool: str,
                      target: str = "") -> UnifiedFinding:
        """Add or merge a discovered directory/endpoint."""
        key = f"{target}:{path}"
        fid = self._generate_id("directory", key)
        
        if fid in self.findings:
            existing = self.findings[fid]
            if source_tool not in existing.sources:
                existing.sources.append(source_tool)
            existing.confidence = min(1.0, len(existing.sources) * 0.35)
            existing.last_seen = datetime.now().isoformat()
            return existing
        
        finding = UnifiedFinding(
            id=fid,
            title=f"{path} [{status_code}]",
            category="directory",
            severity="info",
            confidence=0.35,
            sources=[source_tool],
            data={"path": path, "status_code": status_code, "target": target}
        )
        self._store(finding, target)
        return finding
    
    def add_technology(self, tech: str, version: str, source_tool: str,
                       target: str = "") -> UnifiedFinding:
        """Add or merge a discovered technology."""
        key = f"{target}:{tech.lower()}"
        fid = self._generate_id("technology", key)
        
        if fid in self.findings:
            existing = self.findings[fid]
            if source_tool not in existing.sources:
                existing.sources.append(source_tool)
            if version and not existing.data.get("version"):
                existing.data["version"] = version
            existing.confidence = min(1.0, len(existing.sources) * 0.3)
            existing.last_seen = datetime.now().isoformat()
            return existing
        
        finding = UnifiedFinding(
            id=fid,
            title=f"{tech} {version}".strip(),
            category="technology",
            severity="info",
            confidence=0.3,
            sources=[source_tool],
            data={"technology": tech, "version": version, "target": target}
        )
        self._store(finding, target)
        return finding
    
    def _store(self, finding: UnifiedFinding, target: str = ""):
        """Store finding and update indices."""
        self.findings[finding.id] = finding
        
        # Category index
        cat = finding.category
        self._index_by_category.setdefault(cat, [])
        if finding.id not in self._index_by_category[cat]:
            self._index_by_category[cat].append(finding.id)
        
        # Target index
        if target:
            self._index_by_target.setdefault(target, [])
            if finding.id not in self._index_by_target[target]:
                self._index_by_target[target].append(finding.id)
    
    def _higher_severity(self, a: str, b: str) -> str:
        """Return the higher severity."""
        order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
        return a if order.get(a.lower(), 0) >= order.get(b.lower(), 0) else b
    
    # ─── Query Methods ───────────────────────────────────────────
    
    def get_by_category(self, category: str) -> List[UnifiedFinding]:
        """Get all findings of a category."""
        ids = self._index_by_category.get(category, [])
        return [self.findings[fid] for fid in ids if fid in self.findings]
    
    def get_by_target(self, target: str) -> List[UnifiedFinding]:
        """Get all findings for a target."""
        ids = self._index_by_target.get(target, [])
        return [self.findings[fid] for fid in ids if fid in self.findings]
    
    def get_by_severity(self, severity: str) -> List[UnifiedFinding]:
        """Get all findings of a severity level."""
        return [f for f in self.findings.values() if f.severity == severity.lower()]
    
    def get_high_confidence(self, threshold: float = 0.6) -> List[UnifiedFinding]:
        """Get findings with confidence above threshold."""
        return [f for f in self.findings.values() if f.confidence >= threshold]
    
    def get_confirmed_by_tools(self, min_tools: int = 2) -> List[UnifiedFinding]:
        """Get findings confirmed by multiple tools."""
        return [f for f in self.findings.values() if len(f.sources) >= min_tools]
    
    def get_vulnerabilities(self, min_severity: str = "low") -> List[UnifiedFinding]:
        """Get vulnerability findings at or above a severity level."""
        order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        threshold = order.get(min_severity.lower(), 0)
        return [
            f for f in self.get_by_category("vulnerability")
            if order.get(f.severity, 0) >= threshold
        ]
    
    def mark_false_positive(self, finding_id: str):
        """Mark a finding as false positive."""
        if finding_id in self.findings:
            self.findings[finding_id].false_positive = True
            self.findings[finding_id].confidence = 0.0
    
    def mark_validated(self, finding_id: str):
        """Mark a finding as validated (confirmed exploitable)."""
        if finding_id in self.findings:
            self.findings[finding_id].validated = True
            self.findings[finding_id].confidence = 1.0
    
    # ─── Statistics ──────────────────────────────────────────────
    
    def get_stats(self, target: str = None) -> Dict:
        """Get deduplication statistics."""
        findings = self.get_by_target(target) if target else list(self.findings.values())
        
        total = len(findings)
        by_category = {}
        by_severity = {}
        total_sources = 0
        duplicates_merged = 0
        
        for f in findings:
            by_category[f.category] = by_category.get(f.category, 0) + 1
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            total_sources += len(f.sources)
            if len(f.sources) > 1:
                duplicates_merged += len(f.sources) - 1
        
        return {
            "total_unique": total,
            "total_raw_reports": total_sources,
            "duplicates_merged": duplicates_merged,
            "by_category": by_category,
            "by_severity": by_severity,
            "high_confidence": len([f for f in findings if f.confidence >= 0.6]),
            "multi_tool_confirmed": len([f for f in findings if len(f.sources) >= 2]),
            "validated": len([f for f in findings if f.validated]),
            "false_positives": len([f for f in findings if f.false_positive])
        }
    
    def get_summary_table(self, target: str = None) -> str:
        """Get a formatted text summary."""
        stats = self.get_stats(target)
        findings = self.get_by_target(target) if target else list(self.findings.values())
        
        lines = [
            "╔═══════════════════════════════════════════════════════════════╗",
            "║              📊 FINDINGS DEDUPLICATION REPORT                 ║",
            "╚═══════════════════════════════════════════════════════════════╝",
            "",
            f"  Total Unique Findings: {stats['total_unique']}",
            f"  Raw Reports Received:  {stats['total_raw_reports']}",
            f"  Duplicates Merged:     {stats['duplicates_merged']}",
            f"  High Confidence (>60%): {stats['high_confidence']}",
            f"  Multi-Tool Confirmed:  {stats['multi_tool_confirmed']}",
            f"  Validated:             {stats['validated']}",
            f"  False Positives:       {stats['false_positives']}",
            "",
            "By Category:",
        ]
        
        for cat, count in sorted(stats['by_category'].items()):
            icon = {
                "port": "🔌", "subdomain": "🌐", "vulnerability": "⚠️",
                "credential": "🔑", "directory": "📁", "technology": "🛠️"
            }.get(cat, "📋")
            lines.append(f"  {icon} {cat}: {count}")
        
        lines.append("\nBy Severity:")
        sev_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = stats['by_severity'].get(sev, 0)
            if count > 0:
                lines.append(f"  {sev_icons.get(sev, '⚪')} {sev.upper()}: {count}")
        
        # Show high-confidence vulnerabilities
        high_conf = [f for f in findings 
                     if f.category == "vulnerability" and f.confidence >= 0.6 
                     and not f.false_positive]
        if high_conf:
            lines.append("\n🎯 High-Confidence Vulnerabilities:")
            for f in sorted(high_conf, key=lambda x: x.confidence, reverse=True)[:10]:
                tools = ", ".join(f.sources)
                lines.append(
                    f"  [{f.severity.upper()}] {f.title} "
                    f"(confidence: {f.confidence:.0%}, sources: {tools})"
                )
        
        return "\n".join(lines)


# Global singleton
_dedup: Optional[FindingsDeduplicator] = None


def get_deduplicator() -> FindingsDeduplicator:
    """Get or create the global deduplicator."""
    global _dedup
    if _dedup is None:
        _dedup = FindingsDeduplicator()
    return _dedup


def reset_deduplicator():
    """Reset the deduplicator."""
    global _dedup
    _dedup = FindingsDeduplicator()

# ─────────────────────────────────────────────────────────────────────────────
# DIFFERENTIAL RESPONSE ANALYZER  (was diff_analyzer.py)
# ─────────────────────────────────────────────────────────────────────────────

if TYPE_CHECKING:
    pass


@dataclass
class DiffFinding:
    """Represents a confirmed finding from differential analysis."""
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    finding_type: str      # e.g. "SQL Error Disclosure", "Auth Bypass", "IDOR"
    payload_type: str      # e.g. "sqli", "idor", "auth"
    summary: str           # 1-2 sentence human-readable explanation
    evidence: str          # Diff excerpt or explanation
    confidence: float      # 0.0 – 1.0
    tags: list[str] = field(default_factory=list)


_SYSTEM_PROMPT = textwrap.dedent("""
    You are a web application security researcher analyzing HTTP response diffs.
    You will be given a baseline response and an injected response from the same endpoint.
    Your job is to determine whether the difference is security-significant.

    Rules:
    - Focus only on meaningful security changes, not cosmetic ones (whitespace, timestamps, nonces).
    - If the injected response leaks data, discloses errors, or behaves differently in a
      suspicious way, that is a finding.
    - If the difference is insignificant, respond with {"significant": false}.

    Respond ONLY with valid JSON matching this schema:
    {
      "significant": true/false,
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "finding_type": "<short description>",
      "summary": "<1-2 sentences>",
      "evidence": "<relevant excerpt or explanation>",
      "confidence": 0.0-1.0,
      "tags": ["<tag1>", ...]
    }
""").strip()

_USER_PROMPT_TEMPLATE = textwrap.dedent("""
    Payload type: {payload_type}
    Endpoint: {endpoint}

    --- BASELINE RESPONSE (status {baseline_status}) ---
    {baseline}

    --- INJECTED RESPONSE (payload: {payload}, status {injected_status}) ---
    {injected}

    Is there a security-significant difference?
""").strip()


class DifferentialAnalyzer:
    """
    LLM-powered semantic diff engine for HTTP responses.

    Wraps any OpenAI-compatible async client. Defaults to the live configured
    runtime model unless a cheaper override is provided explicitly.
    """

    def __init__(
        self,
        client,
        model: Optional[str] = None,
        max_response_chars: int = 3000,
    ):
        from src.sdk.key_manager import get_key_manager

        self._client = client
        self._model = model or get_key_manager().get_model()
        self._max_chars = max_response_chars

    def _truncate(self, text: str) -> str:
        if not text:
            return "(empty)"
        text = str(text)
        if len(text) > self._max_chars:
            half = self._max_chars // 2
            return text[:half] + "\n...[truncated]...\n" + text[-half:]
        return text

    async def compare(
        self,
        baseline: str,
        injected: str,
        payload_type: str = "unknown",
        payload: str = "",
        endpoint: str = "",
        baseline_status: int = 0,
        injected_status: int = 0,
    ) -> Optional[DiffFinding]:
        """
        Semantically compare baseline vs injected response.

        Returns a DiffFinding if significant, otherwise None.
        """
        user_msg = _USER_PROMPT_TEMPLATE.format(
            payload_type=payload_type,
            endpoint=endpoint or "(unknown)",
            baseline=self._truncate(baseline),
            injected=self._truncate(injected),
            payload=payload or "(injected)",
            baseline_status=baseline_status or "?",
            injected_status=injected_status or "?",
        )

        try:
            response = await self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.0,
                max_tokens=512,
                response_format={"type": "json_object"},
            )

            import json
            raw = response.choices[0].message.content or "{}"
            data = json.loads(raw)

            if not data.get("significant", False):
                return None

            return DiffFinding(
                severity=data.get("severity", "MEDIUM"),
                finding_type=data.get("finding_type", "Unknown Difference"),
                payload_type=payload_type,
                summary=data.get("summary", ""),
                evidence=data.get("evidence", ""),
                confidence=float(data.get("confidence", 0.5)),
                tags=data.get("tags", []),
            )

        except Exception as e:
            logger.warning(f"DifferentialAnalyzer.compare failed: {e}")
            return None

    async def bulk_compare(
        self,
        baseline: str,
        probes: list[dict],
        payload_type: str = "unknown",
        endpoint: str = "",
        baseline_status: int = 200,
    ) -> list[DiffFinding]:
        """
        Compare baseline against multiple probe results in bulk.

        Args:
            baseline: Baseline response body
            probes: List of dicts with keys: injected, payload, status
            payload_type: Type of injection being tested
            endpoint: URL being tested
            baseline_status: HTTP status of baseline

        Returns:
            List of confirmed findings
        """
        import asyncio

        tasks = [
            self.compare(
                baseline=baseline,
                injected=p.get("injected", ""),
                payload_type=payload_type,
                payload=p.get("payload", ""),
                endpoint=endpoint,
                baseline_status=baseline_status,
                injected_status=p.get("status", 0),
            )
            for p in probes
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings = []
        for r in results:
            if isinstance(r, DiffFinding):
                findings.append(r)
            elif isinstance(r, Exception):
                logger.debug(f"bulk_compare item error: {r}")
        return findings
