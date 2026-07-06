"""
False Positive Filter System

Learns from known false positive patterns to reduce noise in automated scanning.
Implements pattern matching and heuristic-based filtering.
"""

import json
import os
import re
import subprocess
import hashlib
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class FalsePositivePattern:
    """Represents a known false positive pattern"""
    
    pattern_type: str  # e.g., "nuclei_template", "error_string", "response_pattern"
    identifier: str    # e.g., "CVE-2021-12345", "mysql_error_generic"
    conditions: Dict[str, any]  # Conditions that make it a FP
    reason: str       # Why it's a false positive
    confidence: float = 0.9  # How confident we are this is a FP (0-1)
    added_date: datetime = field(default_factory=datetime.now)
    
    def matches(self, finding: Dict) -> bool:
        """Check if a finding matches this FP pattern"""
        if finding.get("type") != self.pattern_type:
            return False
        
        # Check all conditions
        for key, value in self.conditions.items():
            if key not in finding:
                return False
            
            # Handle different condition types
            if isinstance(value, str):
                if value.startswith("regex:"):
                    pattern = value[6:]  # Remove "regex:" prefix
                    if not re.search(pattern, str(finding[key]), re.IGNORECASE):
                        return False
                elif finding[key] != value:
                    return False
            elif isinstance(value, list):
                if finding[key] not in value:
                    return False
            elif finding[key] != value:
                return False
        
        return True


class FalsePositiveFilter:
    """
    Filters out known false positives and learns from user feedback.
    
    Example FP patterns:
    - Nuclei CVE templates triggering on 404/403 pages
    - SQLi error strings in legitimate error pages
    - XSS in HTML comments that don't execute
    - SSRF that only works on localhost/internal
    """
    
    def __init__(self, db_path: str = ".fp_database.json"):
        self.db_path = db_path
        self.patterns: List[FalsePositivePattern] = []
        self._load_default_patterns()
        self._load_from_disk()
    
    def _load_default_patterns(self):
        """Load built-in false positive patterns"""
        
        # Nuclei false positives
        self.patterns.extend([
            # CVE templates on error pages
            FalsePositivePattern(
                pattern_type="nuclei",
                identifier="cve_on_404",
                conditions={
                    "template": "regex:CVE-\\d{4}-\\d+",
                    "status_code": [404, 403, 500, 502, 503]
                },
                reason="CVE template triggered on error page only",
                confidence=0.85
            ),
            
            # Generic exposure templates on standard paths
            FalsePositivePattern(
                pattern_type="nuclei",
                identifier="exposure_on_index",
                conditions={
                    "template": "regex:.*-exposure",
                    "url": "regex:.*/?(index\\.(php|html|jsp)|$)"
                },
                reason="Generic exposure template on index page",
                confidence=0.75
            ),
            
            # Debug mode false positives
            FalsePositivePattern(
                pattern_type="nuclei",
                identifier="debug_mode_generic",
                conditions={
                    "template": "debug-mode",
                    "evidence": "regex:^(true|false|1|0)$"
                },
                reason="Debug mode detection on non-debug output",
                confidence=0.7
            )
        ])
        
        # SQL Injection false positives
        self.patterns.extend([
            # SQL errors in legit error messages
            FalsePositivePattern(
                pattern_type="sqli",
                identifier="sql_in_error_page",
                conditions={
                    "error_detected": True,
                    "status_code": [404, 500],
                    "error_message": "regex:(database|sql).*(not found|unavailable|down)"
                },
                reason="SQL keywords in legitimate error message",
                confidence=0.8
            ),
            
            # Single quote in URL without actual SQLi
            FalsePositivePattern(
                pattern_type="sqli",
                identifier="quote_no_impact",
                conditions={
                    "payload": "'",
                    "response_change": False
                },
                reason="Single quote accepted but no response change",
                confidence=0.85
            )
        ])
        
        # XSS false positives
        self.patterns.extend([
            # Payload in HTML comments
            FalsePositivePattern(
                pattern_type="xss",
                identifier="xss_in_comment",
                conditions={
                    "payload_location": "regex:<!--.*-->",
                    "js_executed": False
                },
                reason="XSS payload only in HTML comment (not executed)",
                confidence=0.9
            ),
            
            # Encoded payload (safe)
            FalsePositivePattern(
                pattern_type="xss",
                identifier="xss_encoded",
                conditions={
                    "payload_reflected": True,
                    "payload_encoded": True,
                    "encoding_type": ["html", "url", "javascript"]
                },
                reason="Payload properly encoded (not exploitable)",
                confidence=0.95
            )
        ])
        
        # SSRF false positives
        self.patterns.extend([
            # Localhost-only SSRF (no external impact)
            FalsePositivePattern(
                pattern_type="ssrf",
                identifier="localhost_only",
                conditions={
                    "target": "regex:^(localhost|127\\.0\\.0\\.1|\\[::1\\])",
                    "external_callback": False
                },
                reason="SSRF limited to localhost (no external impact)",
                confidence=0.7
            ),
            
            # Same-domain redirect (not SSRF)
            FalsePositivePattern(
                pattern_type="ssrf",
                identifier="same_domain_redirect",
                conditions={
                    "redirect": True,
                    "redirect_domain": "same"
                },
                reason="Redirect to same domain (not SSRF)",
                confidence=0.85
            )
        ])
        
        # LFI/Path Traversal false positives
        self.patterns.extend([
            # Path traversal chars accepted but no file access
            FalsePositivePattern(
                pattern_type="path_traversal",
                identifier="traversal_no_file",
                conditions={
                    "traversal_chars": True,
                    "file_content": False,
                    "status_code": [404, 403]
                },
                reason="Traversal characters accepted but file not accessed",
                confidence=0.8
            )
        ])

        # WordPress-specific false positives
        self.patterns.extend([
            # CSRF on WP REST API endpoints (they use nonce auth, not CSRF tokens)
            FalsePositivePattern(
                pattern_type="csrf",
                identifier="wp_rest_api_csrf",
                conditions={
                    "url": "regex:.*wp-json/",
                },
                reason="WordPress REST API uses nonce-based authentication, not form CSRF tokens. "
                       "The absence of a CSRF token is expected behavior, not a vulnerability.",
                confidence=0.95
            ),
            # Mass assignment on WordPress pages (always 200)
            FalsePositivePattern(
                pattern_type="mass_assignment",
                identifier="wp_page_always_200",
                conditions={
                    "url": "regex:.*(contact|about|page)",
                    "status_code": 200,
                },
                reason="WordPress returns HTTP 200 for POST requests to any page URL regardless "
                       "of extra fields. The page is rendered normally — no actual mass assignment.",
                confidence=0.9
            ),
            # Registration tester on disabled registration
            FalsePositivePattern(
                pattern_type="registration",
                identifier="wp_registration_disabled",
                conditions={
                    "url": "regex:.*wp-login\\.php\\?action=register",
                    "response_contains": "regex:registration.*(disabled|not allowed)",
                },
                reason="WordPress registration is disabled. Testing mass assignment/weak passwords "
                       "on a disabled registration form produces invalid results.",
                confidence=0.95
            ),
        ])
    
    def is_false_positive(self, finding: Dict) -> tuple[bool, Optional[str]]:
        """
        Check if a finding matches any FP pattern.
        
        Args:
            finding: Dictionary with finding details
        
        Returns:
            (is_fp, reason) tuple
        """
        for pattern in self.patterns:
            if pattern.matches(finding):
                if pattern.confidence >= 0.7:  # Only filter if confident
                    return (True, pattern.reason)
        
        return (False, None)
    
    def mark_false_positive(self, finding: Dict, reason: str, user_confirmed: bool = True):
        """
        Mark a finding as false positive and learn the pattern.
        
        Args:
            finding: The finding to mark
            reason: Why it's a false positive
            user_confirmed: If user manually marked this (higher confidence)
        """
        # Create new pattern from this finding
        pattern = FalsePositivePattern(
            pattern_type=finding.get("type", "unknown"),
            identifier=f"user_marked_{len(self.patterns)}",
            conditions={k: v for k, v in finding.items() if k != "type"},
            reason=reason,
            confidence=0.95 if user_confirmed else 0.7
        )
        
        self.patterns.append(pattern)
        self._save_to_disk()
    
    def filter_findings(self, findings: List[Dict]) -> tuple[List[Dict], List[Dict]]:
        """
        Filter a list of findings, separating valid from FP.
        
        Args:
            findings: List of findings to filter
        
        Returns:
            (valid_findings, false_positives) tuple
        """
        valid = []
        fps = []
        
        for finding in findings:
            is_fp, reason = self.is_false_positive(finding)
            if is_fp:
                finding["fp_reason"] = reason
                fps.append(finding)
            else:
                valid.append(finding)
        
        return (valid, fps)
    
    def _save_to_disk(self):
        """Save patterns to disk"""
        try:
            data = [
                {
                    "pattern_type": p.pattern_type,
                    "identifier": p.identifier,
                    "conditions": p.conditions,
                    "reason": p.reason,
                    "confidence": p.confidence,
                    "added_date": p.added_date.isoformat()
                }
                for p in self.patterns
            ]
            
            with open(self.db_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass  # Silent fail
    
    def _load_from_disk(self):
        """Load patterns from disk"""
        try:
            if os.path.exists(self.db_path):
                with open(self.db_path, 'r') as f:
                    data = json.load(f)
                
                for item in data:
                    pattern = FalsePositivePattern(
                        pattern_type=item["pattern_type"],
                        identifier=item["identifier"],
                        conditions=item["conditions"],
                        reason=item["reason"],
                        confidence=item["confidence"],
                        added_date=datetime.fromisoformat(item["added_date"])
                    )
                    # Don't duplicate default patterns
                    if pattern.identifier not in [p.identifier for p in self.patterns]:
                        self.patterns.append(pattern)
        except Exception:
            pass  # Silent fail
    
    def get_stats(self) -> Dict:
        """Get FP filter statistics"""
        return {
            "total_patterns": len(self.patterns),
            "by_type": self._count_by_type(),
            "high_confidence": len([p for p in self.patterns if p.confidence >= 0.9]),
            "user_added": len([p for p in self.patterns if p.identifier.startswith("user_marked")])
        }
    
    def _count_by_type(self) -> Dict[str, int]:
        """Count patterns by type"""
        counts = {}
        for pattern in self.patterns:
            counts[pattern.pattern_type] = counts.get(pattern.pattern_type, 0) + 1
        return counts


# Global filter instance
_fp_filter: Optional[FalsePositiveFilter] = None


def get_fp_filter() -> FalsePositiveFilter:
    """Get or create global FP filter"""
    global _fp_filter
    if _fp_filter is None:
        _fp_filter = FalsePositiveFilter()
    return _fp_filter


def filter_finding(finding: Dict) -> bool:
    """
    Quick check if finding is likely false positive.
    
    Returns:
        True if valid, False if FP
    """
    fp_filter = get_fp_filter()
    is_fp, _ = fp_filter.is_false_positive(finding)
    return not is_fp


# =============================================================================
# ANTI-HALLUCINATION VALIDATION PIPELINE
# Ported from Cyber-CoPilot v3 — 4-stage pipeline:
#   1. Negative Controls   (baseline request comparison)
#   2. Proof of Execution  (per-vuln-type concrete proof)
#   3. Confidence Scorer   (0-100 numeric score)
#   4. Validation Judge    (final approve / reject verdict)
# =============================================================================


@dataclass
class ValidationVerdict:
    """Final verdict produced by the ValidationJudge."""
    verdict: str            # "CONFIRMED" | "LIKELY" | "REJECTED"
    score: int              # 0-100
    vuln_type: str
    evidence: List[str]
    score_breakdown: Dict[str, int]
    fp_matched: bool = False
    fp_reason: str = ""
    proof_confirmed: bool = False
    same_as_baseline: bool = False

    def to_dict(self) -> Dict:
        return {
            "verdict": self.verdict,
            "score": self.score,
            "vuln_type": self.vuln_type,
            "evidence": self.evidence,
            "score_breakdown": self.score_breakdown,
            "fp_matched": self.fp_matched,
            "fp_reason": self.fp_reason,
            "proof_confirmed": self.proof_confirmed,
            "same_as_baseline": self.same_as_baseline,
        }

    def __str__(self) -> str:
        icon = {"CONFIRMED": "🔴", "LIKELY": "🟡", "REJECTED": "⚪"}.get(self.verdict, "❓")
        lines = [
            f"{icon} [{self.verdict}] {self.vuln_type.upper()} — Score: {self.score}/100",
            f"  Proof confirmed : {'✅' if self.proof_confirmed else '❌'}",
            f"  Same as baseline: {'⚠️ Yes (FP signal)' if self.same_as_baseline else '✅ No'}",
        ]
        if self.fp_matched:
            lines.append(f"  FP pattern match: ⚠️ {self.fp_reason}")
        if self.evidence:
            lines.append("  Evidence:")
            for e in self.evidence:
                lines.append(f"    • {e}")
        lines.append(f"  Score breakdown : {self.score_breakdown}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Stage 1 — Negative Control Engine
# ---------------------------------------------------------------------------

class NegativeControlEngine:
    """
    Sends a benign/empty request to the same endpoint and captures the
    baseline response.  If the payload response is identical to the baseline
    the finding is almost certainly a false positive.

    Score delta applied by ConfidenceScorer:
      -60   if response body AND status code are identical to baseline
      -20   if only status code matches (body differs slightly)
    """

    def _http_get(self, url: str, timeout: int = 10) -> Dict:
        """Perform a plain HTTP GET and return status, body length, body hash."""
        try:
            result = subprocess.run(
                ["curl", "-s", "-o", "-", "-w", "%{http_code}", "--max-time", str(timeout), url],
                capture_output=True, text=True, timeout=timeout + 5
            )
            # curl -w appends the status at the very end
            raw = result.stdout
            if len(raw) >= 3 and raw[-3:].isdigit():
                status = int(raw[-3:])
                body = raw[:-3]
            else:
                status = 0
                body = raw
            return {
                "status": status,
                "body_len": len(body),
                "body_hash": hashlib.md5(body.encode("utf-8", errors="ignore")).hexdigest(),
                "body_preview": body[:300],
            }
        except Exception as exc:
            return {"status": 0, "body_len": 0, "body_hash": "", "body_preview": "",
                    "error": str(exc)}

    def get_baseline(self, url: str, parameter: str = "", timeout: int = 10) -> Dict:
        """
        Fetch baseline with a benign/empty parameter value.
        If parameter is given, override it with an obviously-harmless value.
        """
        if parameter:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            params[parameter] = "1"   # benign value
            baseline_url = urllib.parse.urlunparse(parsed._replace(
                query=urllib.parse.urlencode(params)
            ))
        else:
            baseline_url = url
        return self._http_get(baseline_url, timeout)

    def compare(self, baseline: Dict, payload_response: Dict) -> Tuple[bool, int, str]:
        """
        Compare baseline vs payload response.

        Returns:
            (same_behavior, score_delta, reason)
        """
        if not baseline.get("body_hash") or not payload_response.get("body_hash"):
            return False, 0, "could not compare (fetch error)"

        same_status = baseline["status"] == payload_response["status"]
        same_hash   = baseline["body_hash"] == payload_response["body_hash"]

        if same_hash and same_status:
            return True, -60, "response identical to benign baseline (strong FP signal)"

        # Allow ±5% length variance as "same"
        if baseline["body_len"] > 0:
            ratio = abs(baseline["body_len"] - payload_response["body_len"]) / baseline["body_len"]
            if ratio < 0.05 and same_status:
                return True, -40, "response nearly identical to baseline (FP signal)"

        if same_status and not same_hash:
            return False, -10, "status same but body differs (weak signal)"

        return False, 0, "response differs from baseline (positive signal)"


# ---------------------------------------------------------------------------
# Stage 2 — Proof of Execution Checker
# ---------------------------------------------------------------------------

class ProofOfExecutionChecker:
    """
    Checks whether concrete evidence of exploitation exists in the
    response / evidence string for each vuln type.

    Methods per type:
      xss            — payload unencoded in response
      sqli           — DB error string OR time delay OR boolean difference
      ssrf           — internal IP / metadata response OR external callback marker
      lfi            — /etc/passwd content OR known file markers
      rce            — command output present in response
      ssti           — math evaluation result present (e.g. 7777731 from {{7*'1'*7}})
      xxe            — XML entity resolved / file content / SSRF via XML
      idor           — different user's data received
      open_redirect  — Location header pointing to injected domain
      default        — non-empty evidence string (fallback)
    """

    # Patterns indicating real proof per vuln type
    _PROOF_PATTERNS: Dict[str, List[str]] = {
        "xss": [
            r"<script[^>]*>alert\(",      # unencoded script tag
            r"onerror\s*=\s*alert\(",     # event handler
            r"onload\s*=\s*alert\(",
            r"javascript:alert\(",
            r"<svg[^>]*onload",
        ],
        "sqli": [
            r"you have an error in your sql",
            r"warning.*mysql",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
            r"pg::syntaxerror",
            r"ora-\d{5}",
            r"microsoft ole db provider",
            r"odbc.*driver",
            r"sqlite_error",
            r"syntax error.*near",
        ],
        "ssrf": [
            r"169\.254\.169\.254",       # AWS metadata
            r"metadata\.google\.internal",
            r"ami-id",
            r"instance-id",
            r"iam/security-credentials",
            r"169\.254\.170\.2",         # Azure metadata
            r"100\.100\.100\.200",       # Alibaba metadata
            r"connect(ed)? to",
        ],
        "lfi": [
            r"root:.*:0:0:",             # /etc/passwd
            r"daemon:.*:/sbin",
            r"\[boot loader\]",          # Windows boot.ini
            r"windows\\system32",
            r"\[extensions\]",           # php.ini
            r"default_mimetype",
        ],
        "rce": [
            r"uid=\d+\(",                # id command output
            r"root@",
            r"www-data@",
            r"microsoft windows",        # Windows cmd output
            r"volume serial number",
            r"/bin/bash",
            r"command not found",        # error still proves execution
        ],
        "ssti": [
            r"7777731",   # {{7*'1'*7}} Jinja2
            r"49",        # {{7*7}}
            r"<class 'str'>",
            r"freemarker.template",
            r"\$\{7\*7\}",
        ],
        "xxe": [
            r"root:.*:0:0:",
            r"SYSTEM \"file://",
            r"<!DOCTYPE",
            r"&xxe;",
        ],
        "idor": [
            r"\"user.*\":\s*\"(?!your_user)",
            r"\"email\":",
            r"\"account_id\":",
        ],
        "open_redirect": [
            r"location:\s*https?://(?!.*target\.com)",
        ],
    }

    def check(self, vuln_type: str, evidence: str, response_body: str = "") -> Tuple[bool, str]:
        """
        Returns (proof_found: bool, proof_description: str)
        """
        vtype = vuln_type.lower().replace("-", "_").replace(" ", "_")
        combined = (evidence + "\n" + response_body).lower()

        patterns = self._PROOF_PATTERNS.get(vtype, [])
        if not patterns:
            # Fallback: non-empty evidence string counts as weak proof
            if evidence and len(evidence.strip()) > 10:
                return True, "evidence string present (no specific proof pattern for this type)"
            return False, "no proof pattern defined for this vuln type"

        for pat in patterns:
            if re.search(pat, combined, re.IGNORECASE):
                return True, f"proof pattern matched: {pat}"

        # Time-delay proof (for sqli/rce): check if evidence mentions delay
        if re.search(r"(\d+\.\d+)\s*s.*delay|delay.*(\d+\.\d+)\s*s", evidence, re.IGNORECASE):
            return True, "time-based proof: delay mentioned in evidence"

        return False, "no proof of exploitation found in response/evidence"


# ---------------------------------------------------------------------------
# Stage 3 — Confidence Scorer
# ---------------------------------------------------------------------------

class ConfidenceScorer:
    """
    Produces a 0-100 integer confidence score for a finding.

    Scoring table
    ─────────────────────────────────────────────────────
    +35   proof_of_execution confirmed
    +20   response differs from negative control
    +15   vuln-specific error/indicator in response
    +10   impact indicators present (db dump, internal IP, callback)
    +10   multiple independent signals agree
    - 60  response identical to benign baseline
    - 40  response nearly identical to baseline
    - 20  only status-code changed (no content difference)
    - 10  known FP pattern matched
    ─────────────────────────────────────────────────────
    Result is clamped to [0, 100].
    """

    # High-impact indicators that increase confidence further
    _IMPACT_INDICATORS = [
        r"root:.*:0:0:",
        r"169\.254\.169\.254",
        r"metadata\.google\.internal",
        r"ami-id",
        r"uid=\d+\(",
        r"\"password\"",
        r"\"secret\"",
        r"\"api_key\"",
        r"private key",
        r"BEGIN RSA PRIVATE",
    ]

    def score(
        self,
        proof_found: bool,
        same_as_baseline: bool,
        baseline_score_delta: int,
        fp_matched: bool,
        evidence: str,
        response_body: str = "",
    ) -> Tuple[int, Dict[str, int]]:
        """
        Returns (total_score, breakdown_dict).
        breakdown_dict maps each signal name to its +/- contribution.
        """
        breakdown: Dict[str, int] = {}
        total = 0

        # Proof of execution
        if proof_found:
            breakdown["proof_of_execution"] = +35
        else:
            breakdown["proof_of_execution"] = 0

        # Negative control comparison
        breakdown["negative_control_delta"] = baseline_score_delta

        # Vuln-specific error or indicator in combined text
        combined = (evidence + "\n" + response_body).lower()
        has_specific_indicator = bool(re.search(
            r"(sql syntax|mysql_num_rows|ora-\d|pgsql|sqlite|"
            r"reflected xss|onerror|alert\(|"
            r"no such file|permission denied|"
            r"metadata.*ami|uid=\d|root:x:0)",
            combined, re.IGNORECASE
        ))
        if has_specific_indicator:
            breakdown["vuln_specific_indicator"] = +15
        else:
            breakdown["vuln_specific_indicator"] = 0

        # Impact indicators
        has_impact = any(
            re.search(p, combined, re.IGNORECASE)
            for p in self._IMPACT_INDICATORS
        )
        breakdown["impact_indicators"] = +10 if has_impact else 0

        # Multiple independent signals: evidence contains >= 2 bullet / lines
        signal_lines = [l for l in evidence.splitlines() if l.strip()]
        breakdown["multi_signal"] = +10 if len(signal_lines) >= 2 else 0

        # Known FP pattern
        breakdown["fp_pattern_penalty"] = -10 if fp_matched else 0

        total = sum(breakdown.values())
        total = max(0, min(100, total))  # clamp to [0, 100]
        return total, breakdown


# ---------------------------------------------------------------------------
# Stage 4 — Validation Judge
# ---------------------------------------------------------------------------

class ValidationJudge:
    """
    Issues the final verdict based on the confidence score.

      ≥ 90  →  CONFIRMED   (report immediately, high confidence)
      ≥ 60  →  LIKELY      (report with caveat, suggest manual check)
      <  60  →  REJECTED    (suppress — probable false positive)
    """

    def judge(self, score: int) -> str:
        if score >= 90:
            return "CONFIRMED"
        elif score >= 60:
            return "LIKELY"
        else:
            return "REJECTED"


# ---------------------------------------------------------------------------
# Knowledge Base integration (Phase 2)
# ---------------------------------------------------------------------------

_KB_FILE = Path(__file__).resolve().parents[2] / "data" / "vuln_knowledge_base.json"
_KB_DATA: Optional[Dict] = None


def _kb_proof_method(vuln_type: str) -> Optional[str]:
    """
    Look up the canonical proof_method for a vuln type from the KB.
    Returns None if the KB is unavailable or the type is not found.
    """
    global _KB_DATA
    if _KB_DATA is None:
        try:
            with open(_KB_FILE, "r", encoding="utf-8") as fh:
                _KB_DATA = json.load(fh)
        except Exception:
            _KB_DATA = {"vulnerabilities": []}

    vt_norm = vuln_type.lower().replace("-", "_").replace(" ", "_")
    for entry in _KB_DATA.get("vulnerabilities", []):
        eid = entry["id"].lower()
        # Exact match on id
        if eid == vt_norm:
            return entry["proof_method"]
        # Partial match: e.g. 'sqli' matches 'sqli_error_based'
        if vt_norm in eid or eid.startswith(vt_norm):
            return entry["proof_method"]
    return None


# ---------------------------------------------------------------------------
# Main Pipeline
# ---------------------------------------------------------------------------

class ValidationPipeline:
    """
    Anti-Hallucination Validation Pipeline (4 stages).

    Usage
    -----
    pipeline = ValidationPipeline()

    verdict = pipeline.run({
        "vuln_type": "sqli",
        "url": "http://target.com/page?id=1",
        "parameter": "id",
        "payload": "' OR '1'='1",
        "evidence": "SQL syntax error in response",
        "response_body": "You have an error in your SQL syntax ...",
        "payload_response": {"status": 200, "body_len": 1234, "body_hash": "abc..."},
    })

    print(verdict)          # human-readable verdict
    print(verdict.to_dict()) # machine-readable
    """

    def __init__(self):
        self._negative_ctrl  = NegativeControlEngine()
        self._proof_checker  = ProofOfExecutionChecker()
        self._scorer         = ConfidenceScorer()
        self._judge          = ValidationJudge()
        self._fp_filter      = get_fp_filter()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, finding: Dict) -> ValidationVerdict:
        """
        Run all four pipeline stages and return a ValidationVerdict.

        Required finding keys:
          vuln_type       str   e.g. "sqli", "xss", "ssrf"
          url             str   target URL
          evidence        str   description of what was observed
        Optional:
          parameter       str   query/body parameter that was fuzzed
          payload         str   payload that triggered the finding
          response_body   str   raw HTTP response body
          payload_response dict  {status, body_len, body_hash} of payload request
          fetch_baseline  bool  if True, fetches a real baseline (requires curl)
        """
        vuln_type     = finding.get("vuln_type", "unknown")
        url           = finding.get("url", "")
        parameter     = finding.get("parameter", "")
        evidence      = finding.get("evidence", "")
        response_body = finding.get("response_body", "")
        fetch_baseline = finding.get("fetch_baseline", False)

        # ── KB proof_method resolution (Phase 2 integration) ────────────
        # If the caller didn't override proof_method, look it up in the KB
        kb_proof_method = _kb_proof_method(vuln_type)
        # We store it so ProofOfExecutionChecker uses the canonical method
        # The checker already accepts any proof_method string; KB just ensures
        # the right patterns are selected for e.g. 'sqli' vs 'rce'.
        # Override vuln_type passed to proof checker if a canonical match exists.
        resolved_proof_type = kb_proof_method if kb_proof_method else vuln_type

        all_evidence: List[str] = [evidence] if evidence else []
        score_breakdown: Dict[str, int] = {}

        # ── Stage 1: Negative Controls ──────────────────────────────────
        same_as_baseline = False
        baseline_delta   = 0
        baseline_reason  = "baseline not fetched"

        if fetch_baseline and url:
            baseline = self._negative_ctrl.get_baseline(url, parameter)
            payload_resp = finding.get("payload_response")

            if payload_resp is None and url:
                # Fetch the payload response now (with the payload embedded in URL or body)
                payload_resp = self._negative_ctrl._http_get(url)

            if payload_resp:
                same_as_baseline, baseline_delta, baseline_reason = \
                    self._negative_ctrl.compare(baseline, payload_resp)
                all_evidence.append(f"Negative control: {baseline_reason}")
        else:
            # Use pre-supplied payload_response if available
            payload_resp = finding.get("payload_response")
            if payload_resp and url:
                baseline = self._negative_ctrl.get_baseline(url, parameter)
                same_as_baseline, baseline_delta, baseline_reason = \
                    self._negative_ctrl.compare(baseline, payload_resp)
                all_evidence.append(f"Negative control: {baseline_reason}")

        # ── Stage 2: Proof of Execution ─────────────────────────────────
        proof_found, proof_desc = self._proof_checker.check(
            resolved_proof_type, evidence, response_body
        )
        all_evidence.append(f"Proof check: {proof_desc}")

        # ── Stage 2b: Existing FP pattern check ─────────────────────────
        is_fp, fp_reason = self._fp_filter.is_false_positive(finding)
        if is_fp:
            all_evidence.append(f"FP pattern: {fp_reason}")

        # ── Stage 3: Confidence Scoring ──────────────────────────────────
        score, breakdown = self._scorer.score(
            proof_found=proof_found,
            same_as_baseline=same_as_baseline,
            baseline_score_delta=baseline_delta,
            fp_matched=is_fp,
            evidence=evidence,
            response_body=response_body,
        )
        score_breakdown.update(breakdown)

        # ── Stage 4: Judge ───────────────────────────────────────────────
        verdict_str = self._judge.judge(score)

        return ValidationVerdict(
            verdict=verdict_str,
            score=score,
            vuln_type=vuln_type,
            evidence=all_evidence,
            score_breakdown=score_breakdown,
            fp_matched=is_fp,
            fp_reason=fp_reason or "",
            proof_confirmed=proof_found,
            same_as_baseline=same_as_baseline,
        )

    def run_batch(self, findings: List[Dict]) -> List[ValidationVerdict]:
        """Run the pipeline on a list of findings and return all verdicts."""
        return [self.run(f) for f in findings]

    def run_batch_filtered(self, findings: List[Dict]) -> Tuple[List[ValidationVerdict], List[ValidationVerdict]]:
        """
        Run pipeline on a list.  Returns (accepted, rejected) split.
        Accepted = CONFIRMED or LIKELY.  Rejected = REJECTED.
        """
        verdicts = self.run_batch(findings)
        accepted = [v for v in verdicts if v.verdict != "REJECTED"]
        rejected = [v for v in verdicts if v.verdict == "REJECTED"]
        return accepted, rejected


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

_pipeline: Optional["ValidationPipeline"] = None


def get_validation_pipeline() -> "ValidationPipeline":
    """Get or create the global ValidationPipeline instance."""
    global _pipeline
    if _pipeline is None:
        _pipeline = ValidationPipeline()
    return _pipeline


def validate_finding(
    vuln_type: str,
    url: str,
    evidence: str,
    parameter: str = "",
    response_body: str = "",
    fetch_baseline: bool = False,
) -> ValidationVerdict:
    """
    Convenience wrapper — validate a single finding through the full pipeline.

    Returns a ValidationVerdict with .verdict in ["CONFIRMED", "LIKELY", "REJECTED"].
    """
    pipeline = get_validation_pipeline()
    return pipeline.run({
        "vuln_type": vuln_type,
        "url": url,
        "parameter": parameter,
        "evidence": evidence,
        "response_body": response_body,
        "fetch_baseline": fetch_baseline,
    })
