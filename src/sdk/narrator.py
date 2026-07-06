"""
AI-Powered Attack Narration
Real-time contextual commentary during security operations.
Provides human-readable narration of what's happening at each stage.
"""

import re
import time
from typing import Optional, Dict, List
from dataclasses import dataclass
from datetime import datetime


@dataclass
class NarrationEvent:
    """A single narration event."""
    timestamp: str
    phase: str  # recon, scanning, enumeration, exploitation, post-exploitation, reporting
    event: str  # tool_start, tool_end, finding, escalation, access
    message: str
    icon: str = ""
    severity: str = "info"  # info, success, warning, critical


class AttackNarrator:
    """
    Generates real-time attack narration based on tool execution context.
    Tracks attack phases and provides contextual commentary.
    """
    
    # Phase detection based on tools
    TOOL_PHASES = {
        # Reconnaissance
        "nmap_scan": "recon", "whois_lookup": "recon", "dig_lookup": "recon",
        "subfinder_enum": "recon", "dnsrecon_scan": "recon", "dnsenum_scan": "recon",
        "amass_enum": "recon", "fierce_scan": "recon", "shodan_search": "recon",
        "gau_urls": "recon", "gospider_crawl": "recon",
        
        # Scanning & Enumeration
        "whatweb_scan": "scanning", "httpx_probe": "scanning", "sslscan_check": "scanning",
        "wafw00f_detect": "scanning", "gobuster_scan": "enumeration", "dirsearch_scan": "enumeration",
        "ffuf_fuzz": "enumeration", "wpscan": "enumeration", "arjun_scan": "enumeration",
        "enum4linux_scan": "enumeration", "nuclei_scan": "scanning",
        
        # Exploitation
        "sqlmap_attack": "exploitation", "dalfox_scan": "exploitation",
        "tplmap_scan": "exploitation", "nosqlmap_attack": "exploitation",
        "jwt_tool_attack": "exploitation", "searchsploit": "exploitation",
        "hydra_bruteforce": "exploitation", "commix_inject": "exploitation",
        
        # Post-exploitation
        "crackmapexec": "post_exploitation", "pwncat_shell": "post_exploitation",
        "mimikatz_extract": "post_exploitation", "secretsdump": "post_exploitation",
        "kerbrute_enum": "post_exploitation",
        
        # Forensics
        "volatility3_analyze": "forensics", "tshark_capture": "forensics",
        "binwalk_extract": "forensics", "strings_extract": "forensics",
        
        # Reporting
        "generate_markdown_report": "reporting", "generate_pdf_report": "reporting",
    }
    
    # Start narrations - per tool
    TOOL_START_NARRATIONS = {
        "nmap_scan": ("🔍", "Scanning network ports and services..."),
        "subfinder_enum": ("🌐", "Enumerating subdomains..."),
        "dnsenum_scan": ("📡", "DNS enumeration in progress..."),
        "amass_enum": ("🕸️", "OSINT-powered asset discovery running..."),
        "fierce_scan": ("⚡", "DNS reconnaissance with zone transfer checks..."),
        "whatweb_scan": ("🔎", "Fingerprinting web technologies..."),
        "httpx_probe": ("📊", "Probing HTTP services for live hosts..."),
        "wafw00f_detect": ("🛡️", "Detecting Web Application Firewalls..."),
        "sslscan_check": ("🔐", "Analyzing SSL/TLS configuration..."),
        "gobuster_scan": ("📂", "Brute-forcing directories and files..."),
        "dirsearch_scan": ("📁", "Directory scanning for hidden paths..."),
        "ffuf_fuzz": ("🎯", "Fuzzing web endpoints..."),
        "arjun_scan": ("🔗", "Discovering hidden HTTP parameters..."),
        "nuclei_scan": ("☢️", "Running vulnerability templates..."),
        "wpscan": ("📝", "WordPress vulnerability scanning..."),
        "sqlmap_attack": ("💉", "Testing for SQL injection vulnerabilities..."),
        "dalfox_scan": ("⚡", "Hunting for XSS vulnerabilities..."),
        "tplmap_scan": ("🔥", "Testing for Server-Side Template Injection..."),
        "nosqlmap_attack": ("💾", "Testing for NoSQL injection..."),
        "jwt_tool_attack": ("🔑", "Analyzing JWT token security..."),
        "hydra_bruteforce": ("🔨", "Brute-forcing credentials..."),
        "searchsploit": ("📚", "Searching exploit database..."),
        "crackmapexec": ("🏴", "Executing lateral movement techniques..."),
        "pwncat_shell": ("🐚", "Establishing persistent shell access..."),
        "enum4linux_scan": ("🏢", "Enumerating Windows/Samba shares..."),
        "gau_urls": ("📜", "Fetching historical URLs from archives..."),
        "gospider_crawl": ("🕷️", "Crawling web application..."),
        "shodan_search": ("🌍", "Querying Shodan for exposed services..."),
        "volatility3_analyze": ("🧪", "Analyzing memory dump..."),
        "commix_inject": ("💣", "Testing for OS command injection..."),
    }
    
    # Result-based narrations - pattern -> (icon, message)
    RESULT_NARRATIONS = [
        # Critical findings
        (re.compile(r'injectable|sql injection confirmed|injection point', re.I),
         "critical", "🚨", "SQL INJECTION CONFIRMED! Database is vulnerable."),
        (re.compile(r'remote code execution|rce confirmed|command executed', re.I),
         "critical", "💀", "REMOTE CODE EXECUTION achieved!"),
        (re.compile(r'shell.*obtained|reverse shell|meterpreter session', re.I),
         "critical", "🐚", "SHELL ACCESS OBTAINED! We're in."),
        (re.compile(r'root|administrator|SYSTEM.*privilege|uid=0', re.I),
         "critical", "👑", "PRIVILEGE ESCALATION - Root/Admin access!"),
        
        # High findings
        (re.compile(r'xss.*(?:found|detected|confirmed)', re.I),
         "warning", "⚡", "Cross-Site Scripting (XSS) vulnerability found!"),
        (re.compile(r'ssti.*(?:found|detected)|template injection', re.I),
         "warning", "🔥", "Server-Side Template Injection detected!"),
        (re.compile(r'ssrf.*(?:found|detected)', re.I),
         "warning", "🌐", "Server-Side Request Forgery vulnerability found!"),
        (re.compile(r'password.*(?:found|cracked|leaked)|credentials?\s*(?:found|leaked)', re.I),
         "warning", "🔑", "Credentials discovered!"),
        (re.compile(r'CVE-\d{4}-\d{4,}', re.I),
         "warning", "⚠️", "Known CVE vulnerability identified!"),
        
        # Medium findings
        (re.compile(r'(?:directory|path).*(?:found|listing|accessible)', re.I),
         "info", "📁", "Interesting directories/paths discovered."),
        (re.compile(r'(?:wordpress|wp-|joomla|drupal).*(?:vulnerable|outdated)', re.I),
         "info", "📝", "CMS vulnerabilities detected in web application."),
        (re.compile(r'subdomain.*found|found \d+ subdomain', re.I),
         "info", "🌐", "New subdomains enumerated - expanding attack surface."),
        (re.compile(r'open\s+\d+/tcp|(\d+)\s+open\s+ports?', re.I),
         "info", "🔌", "Open ports discovered - mapping attack surface."),
        
        # WAF/Defense
        (re.compile(r'waf.*detected|is behind.*(?:cloudflare|akamai|incapsula)', re.I),
         "info", "🛡️", "Web Application Firewall detected - adjusting techniques."),
        (re.compile(r'no waf|waf.*not detected', re.I),
         "success", "✅", "No WAF detected - direct testing possible."),
        
        # Access
        (re.compile(r'login.*success|authenticated|session.*valid', re.I),
         "success", "🔓", "Authentication successful!"),
        (re.compile(r'(?:admin|dashboard|panel).*(?:access|found)', re.I),
         "success", "🎯", "Admin panel or dashboard located!"),
    ]
    
    def __init__(self):
        self.events: List[NarrationEvent] = []
        self.current_phase = "recon"
        self.phase_transitions = []
        self._tool_start_times: Dict[str, float] = {}
    
    def narrate_tool_start(self, tool_name: str, args: dict) -> Optional[NarrationEvent]:
        """Generate narration when a tool starts executing."""
        self._tool_start_times[tool_name] = time.time()
        
        # Detect phase transition
        new_phase = self.TOOL_PHASES.get(tool_name, self.current_phase)
        if new_phase != self.current_phase:
            self.current_phase = new_phase
            self.phase_transitions.append((new_phase, datetime.now().isoformat()))
        
        # Get tool-specific narration
        icon, message = self.TOOL_START_NARRATIONS.get(
            tool_name, ("⚙️", f"Executing {tool_name}...")
        )
        
        # Add target context
        target = args.get('target', args.get('url', args.get('domain', '')))
        if target:
            message = f"{message} [dim]→ {target}[/dim]"
        
        event = NarrationEvent(
            timestamp=datetime.now().strftime("%H:%M:%S"),
            phase=self.current_phase,
            event="tool_start",
            message=message,
            icon=icon,
            severity="info"
        )
        self.events.append(event)
        return event
    
    def narrate_tool_end(self, tool_name: str, success: bool, result: str) -> List[NarrationEvent]:
        """Generate narration when a tool finishes, based on results."""
        events = []
        
        if not success:
            event = NarrationEvent(
                timestamp=datetime.now().strftime("%H:%M:%S"),
                phase=self.current_phase,
                event="tool_end",
                message=f"Tool {tool_name} encountered an error.",
                icon="❌",
                severity="info"
            )
            events.append(event)
            self.events.append(event)
            return events
        
        # Check result against narration patterns
        result_text = result[:5000]  # Limit pattern matching
        matched = False
        
        for pattern, severity, icon, message in self.RESULT_NARRATIONS:
            if pattern.search(result_text):
                event = NarrationEvent(
                    timestamp=datetime.now().strftime("%H:%M:%S"),
                    phase=self.current_phase,
                    event="finding",
                    message=message,
                    icon=icon,
                    severity=severity
                )
                events.append(event)
                self.events.append(event)
                matched = True
                break  # Only the most significant narration
        
        # Duration-based narration
        start_time = self._tool_start_times.pop(tool_name, None)
        if start_time:
            duration = time.time() - start_time
            if duration > 60 and not matched:
                event = NarrationEvent(
                    timestamp=datetime.now().strftime("%H:%M:%S"),
                    phase=self.current_phase,
                    event="tool_end",
                    message=f"Completed {tool_name} ({duration:.0f}s) - analyzing results...",
                    icon="✓",
                    severity="info"
                )
                events.append(event)
                self.events.append(event)
        
        return events
    
    def get_phase_icon(self) -> str:
        """Get icon for current attack phase."""
        phase_icons = {
            "recon": "🔍",
            "scanning": "📡",
            "enumeration": "📋",
            "exploitation": "💥",
            "post_exploitation": "🏴",
            "forensics": "🔬",
            "reporting": "📝"
        }
        return phase_icons.get(self.current_phase, "⚙️")
    
    def get_phase_name(self) -> str:
        """Get human-readable phase name."""
        names = {
            "recon": "Reconnaissance",
            "scanning": "Scanning",
            "enumeration": "Enumeration",
            "exploitation": "Exploitation",
            "post_exploitation": "Post-Exploitation",
            "forensics": "Forensics",
            "reporting": "Reporting"
        }
        return names.get(self.current_phase, self.current_phase.title())
    
    def get_narration_summary(self) -> str:
        """Get a formatted summary of all narration events."""
        if not self.events:
            return "No activity recorded yet."
        
        lines = [
            "╔═══════════════════════════════════════════════════════════╗",
            "║                 🎬 ATTACK NARRATION LOG                    ║",
            "╚═══════════════════════════════════════════════════════════╝",
            ""
        ]
        
        current_phase = None
        for event in self.events:
            if event.phase != current_phase:
                current_phase = event.phase
                phase_name = {
                    "recon": "🔍 RECONNAISSANCE", "scanning": "📡 SCANNING",
                    "enumeration": "📋 ENUMERATION", "exploitation": "💥 EXPLOITATION",
                    "post_exploitation": "🏴 POST-EXPLOITATION", "forensics": "🔬 FORENSICS",
                    "reporting": "📝 REPORTING"
                }.get(current_phase, current_phase.upper())
                lines.append(f"\n{'─' * 50}")
                lines.append(f"  {phase_name}")
                lines.append(f"{'─' * 50}")
            
            severity_color = {
                "critical": "🔴", "warning": "🟡", "success": "🟢", "info": "⚪"
            }.get(event.severity, "⚪")
            
            lines.append(f"  {severity_color} [{event.timestamp}] {event.icon} {event.message}")
        
        return "\n".join(lines)


# Global singleton
_narrator: Optional[AttackNarrator] = None


def get_narrator() -> AttackNarrator:
    """Get or create the global narrator."""
    global _narrator
    if _narrator is None:
        _narrator = AttackNarrator()
    return _narrator


def reset_narrator():
    """Reset the narrator."""
    global _narrator
    _narrator = AttackNarrator()
