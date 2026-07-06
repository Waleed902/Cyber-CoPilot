"""
Finding ↔ Discovery bridge.

The framework has two parallel pipelines:
  - intelligence.engine.IntelligenceBus (typed Finding objects from FindingExtractor)
  - sdk.agent_graph.DiscoveryBus (loosely typed Discovery objects from agents)

Agents read from one or the other, so signals can be missed. This module is the
single integration point: every Finding produces an equivalent Discovery and
vice-versa, so subscribers on either bus see the full picture.

Wire-in points:
  - IntelligenceBus.register_finding() calls publish_finding_to_discovery()
  - DiscoveryBus.publish() calls publish_discovery_to_intelligence()

Both adapters are idempotent — they tag bridged objects with a sentinel attribute
so a re-publish won't loop.
"""

from __future__ import annotations

from loguru import logger


_BRIDGE_TAG = "_bridged"


def _severity_to_intel(severity: str):
    """Map Discovery's string severity → Intelligence Severity enum."""
    from src.intelligence.engine import Severity
    s = (severity or "").lower()
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }.get(s, Severity.INFO)


def _severity_to_discovery(sev) -> str:
    """Map Intelligence Severity enum → Discovery's string severity."""
    from src.intelligence.engine import Severity
    return {
        Severity.CRITICAL: "critical",
        Severity.HIGH: "high",
        Severity.MEDIUM: "medium",
        Severity.LOW: "low",
        Severity.INFO: "info",
    }.get(sev, "info")


def publish_discovery_to_intelligence(discovery, target: str | None = None) -> None:
    """A new Discovery has been published — mirror it as a Finding."""
    if getattr(discovery, _BRIDGE_TAG, False):
        return
    try:
        from src.intelligence.engine import Finding, Confidence

        # Only bridge actionable discovery types.
        from src.sdk.agent_graph import DiscoveryType
        if discovery.type not in (
            DiscoveryType.VULNERABILITY,
            DiscoveryType.CREDENTIAL,
            DiscoveryType.EXPLOIT_SUCCESS,
            DiscoveryType.CONFIGURATION,
        ):
            return

        data = discovery.data or {}
        description = data.get("name") or data.get("description") or discovery.type.value
        evidence = data.get("evidence") or data.get("context") or str(data)[:500]

        finding = Finding(
            tool=f"agent:{discovery.source_agent}",
            description=description,
            severity=_severity_to_intel(discovery.severity),
            confidence=Confidence.FIRM if discovery.validated else Confidence.TENTATIVE,
            evidence=evidence,
            remediation_hints=data.get("remediation"),
        )
        setattr(finding, _BRIDGE_TAG, True)

        from src.repl.session import global_session
        bus = getattr(global_session, "intelligence_bus", None)
        if bus is not None:
            bus.register_finding(finding)
            logger.debug(f"[bridge] Discovery → Finding: {description}")
    except Exception as e:
        logger.debug(f"[bridge] discovery→finding failed: {e}")


def publish_finding_to_discovery(finding, target: str | None = None) -> None:
    """A new Finding has been registered — mirror it as a Discovery for agents."""
    if getattr(finding, _BRIDGE_TAG, False):
        return
    try:
        from src.sdk.agent_graph import Discovery, DiscoveryType
        from src.repl.session import global_session

        bus = getattr(global_session, "discovery_bus", None)
        if bus is None:
            return

        discovery = Discovery(
            type=DiscoveryType.VULNERABILITY,
            source_agent=finding.tool,
            target=target or "",
            data={
                "name": finding.description,
                "evidence": finding.evidence,
                "remediation": finding.remediation_hints or "",
            },
            severity=_severity_to_discovery(finding.severity),
            validated=int(finding.confidence) >= 2,  # FIRM or CERTAIN
        )
        setattr(discovery, _BRIDGE_TAG, True)
        bus.publish(discovery)
        logger.debug(f"[bridge] Finding → Discovery: {finding.description}")
    except Exception as e:
        logger.debug(f"[bridge] finding→discovery failed: {e}")


def install_bridge() -> None:
    """Idempotent installer — patches both buses to call the bridge on publish.

    Call once at startup (e.g. from src/repl/session.py during global_session init).
    Safe to call multiple times.
    """
    try:
        from src.intelligence.engine import IntelligenceBus
        if not getattr(IntelligenceBus, "_bridge_installed", False):
            _orig_register = IntelligenceBus.register_finding

            def register_finding_bridged(self, finding):
                _orig_register(self, finding)
                publish_finding_to_discovery(finding)

            IntelligenceBus.register_finding = register_finding_bridged
            IntelligenceBus._bridge_installed = True
    except Exception as e:
        logger.debug(f"[bridge] IntelligenceBus install skipped: {e}")

    try:
        from src.sdk.agent_graph import DiscoveryBus
        if not getattr(DiscoveryBus, "_bridge_installed", False):
            _orig_publish = DiscoveryBus.publish

            def publish_bridged(self, discovery):
                _orig_publish(self, discovery)
                publish_discovery_to_intelligence(discovery, target=getattr(self, "_target", None))

            DiscoveryBus.publish = publish_bridged
            DiscoveryBus._bridge_installed = True
    except Exception as e:
        logger.debug(f"[bridge] DiscoveryBus install skipped: {e}")
