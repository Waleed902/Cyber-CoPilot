"""
Vulnerability Chainer

Uses an LLM to analyze a list of individual low-to-medium findings and
identify chains of exploits that together produce critical impact.

Example chains:
  SSRF + Internal metadata endpoint → Cloud credential theft
  Open redirect + OAuth → Account takeover
  Reflected XSS + CSRF bypass → Session hijack
  IDOR + PII leakage → Data breach

Usage:
    from src.sdk.vuln_chainer import VulnChainer, ChainedAttack
    chainer = VulnChainer(client, model="stepfun-ai/step-3.5-flash")
    chains = await chainer.chain(findings)
"""

from __future__ import annotations

import json
import textwrap
from dataclasses import dataclass, field
from typing import Any, Optional, TYPE_CHECKING

from loguru import logger
from src.sdk.key_manager import get_key_manager

if TYPE_CHECKING:
    pass


@dataclass
class AttackChain:
    """Represents a multi-step chained exploit path."""
    title: str                          # e.g. "SSRF → Cloud Metadata → RCE"
    combined_severity: str              # CRITICAL / HIGH / MEDIUM
    impact: str                         # Detailed impact description
    steps: list[str]                    # Ordered exploit steps
    prerequisite_findings: list[str]    # IDs / titles of required findings
    cvss_estimate: float                # Rough CVSS 3.1 score
    recommendations: list[str]
    confidence: float = 0.8
    tags: list[str] = field(default_factory=list)


_CHAIN_SYSTEM_PROMPT = textwrap.dedent("""
    You are a senior penetration tester specialized in exploit chaining and attack path analysis.
    You will receive a list of individual vulnerability findings from a pentest engagement.

    Your task is to identify multi-step attack chains where combining 2 or more vulnerabilities
    produces a higher-severity impact than each finding individually.

    Known powerful chains to look for:
    - SSRF → Internal services → Credentials / RCE
    - Open Redirect → OAuth phishing → Account Takeover
    - XSS + CSRF → Session/token theft
    - IDOR + Info Disclosure → Privilege Escalation
    - SQL Injection + File Write → RCE
    - XXE → SSRF → Internal APIs
    - Subdomain Takeover + Cookie scope → Session hijack
    - Race Condition + Business Logic → Double spend / coupon abuse
    - JWT None/Confusion → Auth Bypass → Admin access
    - Deserialization + (any entry point) → RCE

    Respond ONLY with valid JSON matching this schema:
    {
      "chains": [
        {
          "title": "<short chain title>",
          "combined_severity": "CRITICAL|HIGH|MEDIUM",
          "impact": "<detailed impact>",
          "steps": ["<step 1>", "<step 2>", ...],
          "prerequisite_findings": ["<finding title 1>", ...],
          "cvss_estimate": 0.0-10.0,
          "confidence": 0.0-1.0,
          "recommendations": ["<fix 1>", ...],
          "tags": ["<tag>", ...]
        }
      ]
    }

    If no meaningful chains exist, return {"chains": []}.
    Focus on realistic, high-value attack paths. Avoid theoretical chains with too many steps.
""").strip()


def _format_findings(findings: list[Any]) -> str:
    """Convert findings to a compact JSON summary for LLM input."""
    summarized = []
    for i, f in enumerate(findings):
        if hasattr(f, "__dict__"):
            d = {k: v for k, v in vars(f).items() if not k.startswith("_")}
        elif isinstance(f, dict):
            d = f
        else:
            d = {"description": str(f)}
        d["index"] = i
        summarized.append(d)

    try:
        return json.dumps(summarized, indent=2, default=str)
    except Exception:
        return str(summarized)


class VulnChainer:
    """
    AI-powered vulnerability chaining engine.

    Takes a list of individual findings (from any source) and returns
    a list of AttackChain objects representing chained attack paths.
    """

    def __init__(
        self,
        client,
        model: Optional[str] = None,  # type: OpenAI | any
        max_findings: int = 50,
    ):
        self._client = client
        self._model = model or get_key_manager().get_model()
        self._max_findings = max_findings

    def chain(
        self,
        findings: list[Any],
        context: str = "",
    ) -> list[AttackChain]:
        """
        Analyze findings and return chained attack paths.

        Args:
            findings: List of Finding objects or dicts with vuln info
            context: Optional context (e.g., target description, tech stack)

        Returns:
            Ordered list of AttackChain objects (highest severity first)
        """
        if not findings:
            return []

        # Cap at max_findings to stay within context window
        capped = findings[:self._max_findings]
        if len(findings) > self._max_findings:
            logger.info(
                f"VulnChainer: capped findings from {len(findings)} → {self._max_findings}"
            )

        findings_json = _format_findings(capped)

        user_msg_parts = []
        if context:
            user_msg_parts.append(f"Target context: {context}\n")
        user_msg_parts.append(f"Findings ({len(capped)} total):\n{findings_json}")
        user_msg = "\n".join(user_msg_parts)

        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": _CHAIN_SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.0,
                max_tokens=3000,
                response_format={"type": "json_object"},
            )

            raw = response.choices[0].message.content or '{"chains": []}'
            data = json.loads(raw)
            chains_data = data.get("chains", [])

            chains = []
            for c in chains_data:
                try:
                    chains.append(AttackChain(
                        title=c.get("title", "Unnamed Chain"),
                        combined_severity=c.get("combined_severity", "HIGH"),
                        impact=c.get("impact", ""),
                        steps=c.get("steps", []),
                        prerequisite_findings=c.get("prerequisite_findings", []),
                        cvss_estimate=float(c.get("cvss_estimate", 7.0)),
                        confidence=float(c.get("confidence", 0.8)),
                        recommendations=c.get("recommendations", []),
                        tags=c.get("tags", []),
                    ))
                except Exception as ce:
                    logger.debug(f"VulnChainer: failed to parse chain: {ce}")

            # Sort by severity then CVSS
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            chains.sort(
                key=lambda c: (
                    severity_order.get(c.combined_severity.upper(), 5),
                    -c.cvss_estimate
                )
            )

            return chains

        except Exception as e:
            logger.warning(f"VulnChainer.chain failed: {e}")
            return []

    def format_report(self, chains: list[AttackChain]) -> str:
        """Format attack chains as a human-readable report section."""
        if not chains:
            return "No exploitable attack chains identified."

        lines = [
            "══════════════════════════════════════════════════════",
            f"  ATTACK CHAIN ANALYSIS — {len(chains)} chain(s) identified",
            "══════════════════════════════════════════════════════",
            "",
        ]

        for i, chain in enumerate(chains, 1):
            lines += [
                f"Chain #{i}: {chain.title}",
                f"  Severity:     {chain.combined_severity}",
                f"  CVSS (est.):  {chain.cvss_estimate:.1f}",
                f"  Confidence:   {chain.confidence * 100:.0f}%",
                f"  Impact:       {chain.impact}",
                "",
                "  Prerequisites:",
            ]
            for p in chain.prerequisite_findings:
                lines.append(f"    • {p}")
            lines += ["", "  Exploit Steps:"]
            for j, step in enumerate(chain.steps, 1):
                lines.append(f"    {j}. {step}")
            lines += ["", "  Recommendations:"]
            for rec in chain.recommendations:
                lines.append(f"    → {rec}")
            if chain.tags:
                lines.append(f"\n  Tags: {', '.join(chain.tags)}")
            lines.append("")

        return "\n".join(lines)
