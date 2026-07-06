import hashlib
from enum import IntEnum
from dataclasses import dataclass
from typing import List, Optional, Set

class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class Confidence(IntEnum):
    TENTATIVE = 1
    FIRM = 2
    CERTAIN = 3

@dataclass
class Finding:
    tool: str
    description: str
    severity: Severity
    confidence: Confidence
    evidence: str
    remediation_hints: Optional[str] = None

    @property
    def threat_score(self) -> int:
        """
        Computes an absolute threat score for priority sorting.
        Severity carries high magnitude (* 10) while confidence adds nuance.
        For example: HIGH (3) * 10 + FIRM (2) = 32.
        """
        return (int(self.severity) * 10) + int(self.confidence)

    def fingerprint(self) -> str:
        """SHA1 of (description[:120], severity) — tool-agnostic dedup key.

        Two findings are duplicates if they describe the same issue at the same
        severity regardless of which tool produced them.
        """
        key = f"{self.description[:120].lower().strip()}|{int(self.severity)}"
        return hashlib.sha1(key.encode("utf-8", errors="ignore")).hexdigest()


class IntelligenceBus:
    """
    Acts as the core routing layer for all tool findings.
    Collects, ranks, and filters security events across the framework.
    """
    def __init__(self):
        self._findings: List[Finding] = []
        self._fingerprints: Set[str] = set()

    def register_finding(self, finding: Finding):
        """Register a finding — silently drops exact duplicates (same issue + severity).

        When a duplicate is detected the existing finding's confidence is upgraded
        if the new finding has higher confidence (multiple tools confirming = more
        certain), and the new evidence is appended to the existing record.
        """
        fp = finding.fingerprint()

        if fp in self._fingerprints:
            # Upgrade confidence and append evidence on the existing finding
            for existing in self._findings:
                if existing.fingerprint() == fp:
                    if finding.confidence > existing.confidence:
                        existing.confidence = finding.confidence
                    if finding.evidence and finding.evidence not in (existing.evidence or ""):
                        existing.evidence = (
                            (existing.evidence or "") + f"\n[{finding.tool}] {finding.evidence}"
                        ).strip()
                    break
            return  # do not append a duplicate entry

        self._fingerprints.add(fp)
        self._findings.append(finding)

        # Cross-session correlation via vector memory
        try:
            from src.sdk.memory import get_memory
            from loguru import logger
            mem = get_memory()
            if mem:
                similar = mem.search(finding.description, limit=3)
                if similar:
                    logger.debug(f"IntelligenceBus: Found {len(similar)} correlated historical findings")
        except Exception:
            pass
        
    def get_prioritized_findings(self) -> List[Finding]:
        """Returns all findings natively sorted by threat score (descending)."""
        return sorted(self._findings, key=lambda f: f.threat_score, reverse=True)
        
    def filter_findings(self, tool: str = None, min_severity: Severity = None) -> List[Finding]:
        """Returns filtered findings based on criteria."""
        results = self.get_prioritized_findings()
        
        if tool:
            results = [f for f in results if f.tool == tool]
            
        if min_severity is not None:
            results = [f for f in results if f.severity >= min_severity]
            
        return results
