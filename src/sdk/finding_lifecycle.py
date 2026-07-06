"""
Evidence-first finding lifecycle for bug bounty work.

Agents can register weak signals as candidates, promote them only with concrete
evidence, group duplicates, and ask for attack-chain opportunities.  This keeps
the framework offensive in practice while avoiding noisy theoretical reports.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from src.sdk.asset_correlation import get_correlator


_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _norm(value: str) -> str:
    return (value or "").strip().lower()


def _fingerprint(title: str, target: str, endpoint: str, parameter: str) -> str:
    base = "|".join([_norm(title), _norm(target), _norm(endpoint), _norm(parameter)])
    return hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]


def _evidence_quality(evidence: str) -> tuple[int, list[str]]:
    text = evidence or ""
    lower = text.lower()
    score = 0
    signals: list[str] = []

    if re.search(r"\bhttp/\d(?:\.\d)?\b|\b(?:get|post|put|patch|delete)\s+/", text, re.I):
        score += 20
        signals.append("raw HTTP request/response")
    if any(marker in lower for marker in ("confirmed", "validated", "poc", "proof", "executed", "sleep", "callback")):
        score += 25
        signals.append("validation marker")
    if any(marker in lower for marker in ("baseline", "negative control", "benign", "false condition", "control")):
        score += 20
        signals.append("negative control")
    if re.search(r"\b(200|201|302|401|403|500)\b", text):
        score += 10
        signals.append("observable status/result")
    if len(text.strip()) >= 80:
        score += 15
        signals.append("substantial evidence")
    if any(marker in lower for marker in ("screenshot", ".png", ".jpg", "response diff", "timing delta")):
        score += 10
        signals.append("visual/diff artifact")

    return min(score, 100), signals


@dataclass
class LifecycleFinding:
    title: str
    target: str
    severity: str
    endpoint: str = ""
    parameter: str = ""
    category: str = ""
    status: str = "candidate"
    confidence: int = 20
    evidence: list[str] = field(default_factory=list)
    validation_notes: str = ""
    impact: str = ""
    remediation: str = ""
    scope_source: str = ""
    cwe: str = ""
    cvss: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    duplicate_of: str = ""
    fingerprint: str = ""

    def __post_init__(self) -> None:
        self.severity = _norm(self.severity) or "info"
        if not self.fingerprint:
            self.fingerprint = _fingerprint(self.title, self.target, self.endpoint, self.parameter)

    @property
    def reportable(self) -> bool:
        return self.status == "confirmed" and self.confidence >= 70 and bool(self.evidence)


class FindingLifecycle:
    def __init__(self, storage_path: str = ".memory/finding_lifecycle.json"):
        self.storage_path = Path(storage_path)
        self.findings: list[LifecycleFinding] = []
        self._load()

    def _load(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            data = json.loads(self.storage_path.read_text(encoding="utf-8"))
            self.findings = [LifecycleFinding(**item) for item in data.get("findings", [])]
        except Exception:
            self.findings = []

    def _save(self) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.storage_path.write_text(
            json.dumps({"findings": [asdict(f) for f in self.findings]}, indent=2),
            encoding="utf-8",
        )

    def add_candidate(
        self,
        title: str,
        target: str,
        severity: str,
        endpoint: str = "",
        parameter: str = "",
        category: str = "",
        evidence: str = "",
        scope_source: str = "",
    ) -> LifecycleFinding:
        fp = _fingerprint(title, target, endpoint, parameter)
        existing = next((f for f in self.findings if f.fingerprint == fp), None)
        if existing:
            if evidence:
                existing.evidence.append(evidence)
            existing.updated_at = datetime.now().isoformat()
            self._save()
            return existing

        quality, _signals = _evidence_quality(evidence)
        finding = LifecycleFinding(
            title=title,
            target=target,
            severity=severity,
            endpoint=endpoint,
            parameter=parameter,
            category=category,
            confidence=max(20, min(60, quality)),
            evidence=[evidence] if evidence else [],
            scope_source=scope_source,
            fingerprint=fp,
        )
        self.findings.append(finding)
        self._save()
        return finding

    def promote(
        self,
        fingerprint: str,
        evidence: str,
        validation_notes: str = "",
        impact: str = "",
        remediation: str = "",
        cwe: str = "",
        cvss: str = "",
    ) -> tuple[bool, str, Optional[LifecycleFinding]]:
        finding = next((f for f in self.findings if f.fingerprint == fingerprint), None)
        if not finding:
            return False, f"No candidate found for fingerprint {fingerprint}", None

        quality, signals = _evidence_quality(evidence)
        if quality < 70:
            finding.evidence.append(evidence)
            finding.confidence = max(finding.confidence, quality)
            finding.validation_notes = validation_notes or finding.validation_notes
            finding.updated_at = datetime.now().isoformat()
            self._save()
            return (
                False,
                "Evidence is still below reportable threshold. Need validation proof plus a control/diff. "
                f"Current evidence quality: {quality}/100 ({', '.join(signals) or 'no strong signals'}).",
                finding,
            )

        finding.status = "confirmed"
        finding.confidence = max(finding.confidence, quality)
        finding.evidence.append(evidence)
        finding.validation_notes = validation_notes or finding.validation_notes
        finding.impact = impact or finding.impact
        finding.remediation = remediation or finding.remediation
        finding.cwe = cwe or finding.cwe
        finding.cvss = cvss or finding.cvss
        finding.updated_at = datetime.now().isoformat()
        
        # Log to Asset Correlator
        try:
            correlator = get_correlator()
            correlator.add_vulnerability(
                target=finding.target,
                vuln_type=finding.title,
                severity=finding.severity,
                confidence=finding.confidence
            )
        except Exception:
            pass
            
        self._save()

        # ── Real-time escalation + chain analysis ────────────────────────────
        escalation_hint = ""
        chain_hint = ""
        try:
            from src.sdk.impact_amplifier import get_amplifier
            amplifier = get_amplifier()
            amp_result = amplifier.amplify(
                finding_title=finding.title,
                severity=finding.severity,
                endpoint=finding.endpoint,
                evidence=evidence[:300],
                category=finding.category,
                top_n=3,
            )
            if amp_result.escalation_steps:
                top = amp_result.escalation_steps[0]
                escalation_hint = (
                    f"\n\n⚡ TOP ESCALATION: {top.title}\n"
                    f"   → {top.test}\n"
                    f"   Expected Severity: {top.expected_severity} | Bounty: {top.bounty_range}"
                )
        except Exception:
            pass

        try:
            from src.sdk.impact_amplifier import get_amplifier
            amplifier = get_amplifier()
            all_confirmed = [f for f in self.findings if f.status == "confirmed"]
            chains = amplifier.chain_from_findings(all_confirmed)
            fully_ready = [c for c in chains if "FULLY" in c.get("status", "")]
            if fully_ready:
                chain_hint = (
                    f"\n\n🔗 CHAIN READY: {fully_ready[0]['title']} "
                    f"→ {fully_ready[0]['combined_severity']} ({fully_ready[0]['bounty_range']})"
                )
            elif chains:
                partial = chains[0]
                chain_hint = (
                    f"\n\n🔍 CHAIN PARTIAL: {partial['title']} — {partial.get('status', '')}"
                )
        except Exception:
            pass

        msg = (
            f"Confirmed {finding.title} at {finding.confidence}/100 confidence"
            + escalation_hint
            + chain_hint
        )
        return True, msg, finding

    def reportable(self, target: str = "") -> list[LifecycleFinding]:
        wanted = _norm(target)
        items = [f for f in self.findings if f.reportable]
        if wanted:
            items = [f for f in items if _norm(f.target) == wanted or _norm(f.target).endswith(f".{wanted}")]
        return sorted(items, key=lambda f: (_SEVERITY_ORDER.get(f.severity, 0), f.confidence), reverse=True)

    def chain_opportunities(self, target: str = "") -> list[dict[str, str]]:
        """Return all chain opportunities using the full ImpactAmplifier chain matrix."""
        findings = self.reportable(target) or self.findings
        chains: list[dict[str, str]] = []

        # ── Use ImpactAmplifier chain matrix (richer than the 6 hardcoded recipes) ──
        try:
            from src.sdk.impact_amplifier import get_amplifier
            amplifier = get_amplifier()
            amp_chains = amplifier.chain_from_findings(findings)
            for ch in amp_chains:
                chains.append({
                    "chain": ch["title"],
                    "rationale": ch["description"],
                    "combined_severity": ch["combined_severity"],
                    "bounty_range": ch.get("bounty_range", ""),
                    "status": ch.get("status", ""),
                    "next_step": (
                        "FULLY CHAINABLE — document in report and upgrade severity."
                        if "FULLY" in ch.get("status", "")
                        else f"Confirm the missing component: {ch.get('status', '')}"
                    ),
                })
        except Exception:
            # Fallback to original 6-recipe system if amplifier unavailable
            def has(*needles: str) -> list[LifecycleFinding]:
                return [
                    f for f in findings
                    if any(n in f.title.lower() or n in f.category.lower() for n in needles)
                ]
            recipes = [
                (("open redirect", "redirect"), ("oauth", "sso"), "Open redirect can strengthen OAuth/SSO account-takeover testing."),
                (("cors",), ("token", "api key", "sensitive"), "CORS misconfiguration plus sensitive data exposure may create data theft impact."),
                (("ssrf",), ("metadata", "cloud", "aws", "gcp", "azure"), "SSRF plus cloud metadata exposure can escalate to cloud credential compromise."),
                (("idor", "bola"), ("mass assignment", "privilege"), "IDOR/BOLA plus mass assignment can become privilege escalation."),
                (("subdomain takeover",), ("cookie", "session"), "Subdomain takeover plus broad cookie scope can become account takeover."),
                (("xss",), ("csrf", "session"), "XSS plus weak session/CSRF controls can become account takeover."),
            ]
            for left, right, rationale in recipes:
                left_hits = has(*left)
                right_hits = has(*right)
                if left_hits and right_hits:
                    chains.append({
                        "chain": f"{left_hits[0].title} + {right_hits[0].title}",
                        "rationale": rationale,
                        "next_step": "Validate the combined impact with the lowest-risk proof that demonstrates boundary crossing.",
                    })

        return chains[:20]

    def markdown_report(self, target: str = "") -> str:
        findings = self.reportable(target)
        wanted = _norm(target)
        observations = [f for f in self.findings if not f.reportable]
        if wanted:
            observations = [
                f for f in observations
                if _norm(f.target) == wanted or _norm(f.target).endswith(f".{wanted}")
            ]
        observations = sorted(
            observations,
            key=lambda f: (_SEVERITY_ORDER.get(f.severity, 0), f.confidence),
            reverse=True,
        )
        if not findings and not observations:
            return "# Bug Bounty Findings\n\nNo reportable findings or observations yet."

        lines = ["# Bug Bounty Findings", ""]
        if findings:
            for idx, finding in enumerate(findings, 1):
                lines.extend([
                    f"## F-{idx:03d}: {finding.title}",
                    f"- Severity: {finding.severity.upper()}",
                    f"- Target: {finding.target}",
                    f"- Endpoint: {finding.endpoint or '(not specified)'}",
                    f"- Parameter: {finding.parameter or '(not specified)'}",
                    f"- Confidence: {finding.confidence}/100",
                    f"- Scope source: {finding.scope_source or '(not recorded)'}",
                    "",
                    "### Impact",
                    finding.impact or "Impact needs analyst completion.",
                    "",
                    "### Evidence",
                    finding.evidence[-1][:3000],
                    "",
                    "### Remediation",
                    finding.remediation or "Apply input validation, authorization checks, and least-privilege controls appropriate to the issue.",
                    "",
                ])
        else:
            lines.append("No confirmed reportable findings yet.")
            lines.append("")

        if observations:
            lines.extend([
                "## Candidates and Observations",
                "These items are not confirmed vulnerabilities yet. Keep LOW/INFO hardening findings visible, and promote exploitability claims only after validation.",
                "",
            ])
            for idx, finding in enumerate(observations, 1):
                evidence = finding.evidence[-1][:1600] if finding.evidence else "(no evidence captured)"
                lines.extend([
                    f"### C-{idx:03d}: {finding.title}",
                    f"- Status: {finding.status}",
                    f"- Severity: {finding.severity.upper()}",
                    f"- Target: {finding.target}",
                    f"- Endpoint: {finding.endpoint or '(not specified)'}",
                    f"- Parameter: {finding.parameter or '(not specified)'}",
                    f"- Confidence: {finding.confidence}/100",
                    "",
                    "Evidence:",
                    evidence,
                    "",
                ])
        return "\n".join(lines)


_finding_lifecycle: Optional[FindingLifecycle] = None


def get_finding_lifecycle() -> FindingLifecycle:
    global _finding_lifecycle
    if _finding_lifecycle is None:
        _finding_lifecycle = FindingLifecycle()
    return _finding_lifecycle
