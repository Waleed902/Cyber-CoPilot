"""
Report Generator - Export sessions to professional markdown/PDF reports
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict
from loguru import logger


class ReportGenerator:
    """Generates professional security reports from session data."""
    
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_markdown_report(self, target: str, session_dir: str,
                                  title: str = None, author: str = "Cyber-CoPilot") -> str:
        """
        Generate a markdown report from a session.
        
        Args:
            target: Target domain/IP
            session_dir: Path to session directory
            title: Report title (optional)
            author: Report author
        
        Returns:
            Path to generated report
        """
        session_path = Path(session_dir)
        
        if not title:
            title = f"Security Assessment Report - {target}"
        
        # Read session files
        inputs = self._read_file(session_path / "user_inputs.txt")
        outputs = self._read_file(session_path / "agent_outputs.txt")
        tools = self._read_file(session_path / "tool_calls.txt")
        
        # Load profile if exists
        profile_data = self._load_profile(target)
        
        # Generate report
        report = self._build_report(
            target=target,
            title=title,
            author=author,
            inputs=inputs,
            outputs=outputs,
            tools=tools,
            profile=profile_data
        )
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("://", "_").replace("/", "_").replace(":", "_")
        report_path = self.output_dir / f"report_{safe_target}_{timestamp}.md"
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        logger.info(f"Report generated: {report_path}")
        return str(report_path)
    
    def _read_file(self, path: Path) -> str:
        """Read file contents."""
        if path.exists():
            return path.read_text(encoding='utf-8')
        return ""
    
    def _load_profile(self, target: str) -> Optional[Dict]:
        """Load target profile if exists."""
        safe_name = target.replace("://", "_").replace("/", "_").replace(":", "_")
        profile_path = Path(f"./targets/{safe_name}/profile.json")
        
        if profile_path.exists():
            try:
                with open(profile_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        return None
    
    def _build_report(self, target: str, title: str, author: str,
                      inputs: str, outputs: str, tools: str,
                      profile: Optional[Dict]) -> str:
        """Build the markdown report."""
        
        now = datetime.now()
        
        report = f"""# {title}

---

| **Field** | **Value** |
|-----------|-----------|
| **Target** | `{target}` |
| **Author** | {author} |
| **Date** | {now.strftime('%B %d, %Y')} |
| **Classification** | CONFIDENTIAL |

---

## Executive Summary

This report documents the security assessment performed on **{target}** using Cyber-CoPilot automated security framework. The assessment included reconnaissance, vulnerability scanning, and analysis of the target's security posture.

---

## Table of Contents

1. [Scope](#scope)
2. [Methodology](#methodology)
3. [Findings Summary](#findings-summary)
4. [Detailed Findings](#detailed-findings)
5. [Recommendations](#recommendations)
6. [Appendix](#appendix)

---

## Scope

**Target:** {target}

**Assessment Type:** Automated Security Assessment

**Tools Used:**
- Nmap (Port Scanning)
- Subfinder (Subdomain Enumeration)
- Nikto (Web Vulnerability Scanner)
- Gobuster (Directory Enumeration)
- Custom AI Analysis

---

## Methodology

The assessment followed the OWASP Testing Guide and PTES (Penetration Testing Execution Standard) methodologies:

1. **Reconnaissance** - Information gathering and enumeration
2. **Scanning** - Port and service discovery
3. **Vulnerability Analysis** - Identification of security weaknesses
4. **Exploitation** (if authorized) - Validation of vulnerabilities
5. **Reporting** - Documentation of findings

---

## Findings Summary

"""
        # --- NEW: Attack Chain Analysis (Phase 7/8 upgrade) ---
        if profile and profile.get('vulnerabilities'):
            try:
                from src.sdk.vuln_chainer import VulnChainer
                from src.sdk.key_manager import get_key_manager
                km = get_key_manager()
                chainer = VulnChainer(client=km.get_client(), model=km.get_model())
                
                # Format findings for chainer
                findings = []
                for v in profile['vulnerabilities']:
                    findings.append({
                        "name": v.get('name', 'Unknown'),
                        "severity": v.get('severity', 'medium'),
                        "description": v.get('description', '')
                    })
                
                chains = chainer.chain(findings, context=target)
                if chains:
                    report += "## Attack Chain Analysis\n\n"
                    report += "> [!IMPORTANT]\n"
                    report += "> The following high-impact attack paths were identified by combining multiple lower-severity findings.\n\n"
                    
                    for i, chain in enumerate(chains, 1):
                        report += f"### Path {i}: {chain.title}\n\n"
                        report += f"- **Combined Severity:** <span class='{chain.combined_severity.lower()}'>{chain.combined_severity}</span> ({chain.cvss_estimate:.1f})\n"
                        report += f"- **Impact:** {chain.impact}\n"
                        report += "- **Exploit Steps:**\n"
                        for j, step in enumerate(chain.steps, 1):
                            report += f"  {j}. {step}\n"
                        report += "\n"
                    report += "---\n\n"
            except Exception as e:
                logger.debug(f"ReportGenerator: vuln chaining failed: {e}")

        
        # Add findings from profile if available
        if profile:
            ports_count = len(profile.get('ports', []))
            vulns_count = len(profile.get('vulnerabilities', []))
            subs_count = len(profile.get('subdomains', []))
            creds_count = len(profile.get('credentials', []))
            
            report += f"""| Metric | Count |
|--------|-------|
| Open Ports | {ports_count} |
| Vulnerabilities | {vulns_count} |
| Subdomains | {subs_count} |
| Credentials Found | {creds_count} |

"""
            
            # Vulnerability summary
            if profile.get('vulnerabilities'):
                report += "### Vulnerability Breakdown\n\n"
                severity_counts = {}
                for v in profile['vulnerabilities']:
                    sev = v.get('severity', 'unknown').upper()
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                
                for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                    if sev in severity_counts:
                        report += f"- **{sev}**: {severity_counts[sev]}\n"
                report += "\n"
        
        report += """---

## Detailed Findings

"""
        
        # Add port information
        if profile and profile.get('ports'):
            report += "### Open Ports\n\n"
            report += "| Port | Protocol | Service | Version |\n"
            report += "|------|----------|---------|----------|\n"
            for p in profile['ports'][:20]:
                report += f"| {p.get('port', '')} | {p.get('protocol', 'tcp')} | {p.get('service', 'unknown')} | {p.get('version', '')} |\n"
            report += "\n"
        
        # Add vulnerability details
        if profile and profile.get('vulnerabilities'):
            report += "### Vulnerabilities\n\n"
            for i, v in enumerate(profile['vulnerabilities'][:10], 1):
                report += f"""#### {i}. {v.get('name', 'Unknown')}

- **Severity:** {v.get('severity', 'Unknown').upper()}
- **CVE:** {v.get('cve', 'N/A')}
- **Description:** {v.get('description', 'No description available')}

"""
        
        # Add subdomains
        if profile and profile.get('subdomains'):
            report += "### Discovered Subdomains\n\n"
            for s in profile['subdomains'][:20]:
                report += f"- `{s}`\n"
            report += "\n"
        
        report += """---

## Recommendations

Based on the findings, the following actions are recommended:

1. **Patch Management** - Update all services to latest versions
2. **Network Segmentation** - Limit exposure of internal services
3. **Credential Security** - Implement strong password policies
4. **Monitoring** - Deploy intrusion detection systems
5. **Regular Assessments** - Conduct periodic security reviews

---

## Appendix

### A. Session Activity Log

The following commands were executed during this assessment:

```
"""
        
        # Add truncated inputs
        if inputs:
            # Extract just the commands
            lines = [l for l in inputs.split('\n') if l.strip() and not l.startswith('=') and not l.startswith('-')]
            report += '\n'.join(lines[:50])
        
        report += """
```

---

### B. Tool Output Summary

Detailed tool outputs are available in the session directory.

---

*Report generated by Cyber-CoPilot - AI-Powered Security Framework*

*This report is confidential and intended only for the authorized recipient.*
"""
        
        return report
    
    def export_to_html(self, markdown_path: str) -> str:
        """Convert markdown report to HTML (requires markdown library)."""
        try:
            import markdown
            
            with open(markdown_path, 'r', encoding='utf-8') as f:
                md_content = f.read()
            
            html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }}
        h2 {{ color: #16213e; border-bottom: 1px solid #ccc; padding-bottom: 5px; }}
        h3 {{ color: #0f3460; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th {{ background: #16213e; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }}
        pre {{ background: #1a1a2e; color: #0f0; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .critical {{ color: #dc3545; font-weight: bold; }}
        .high {{ color: #fd7e14; font-weight: bold; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
    </style>
</head>
<body>
{markdown.markdown(md_content, extensions=['tables', 'fenced_code'])}
</body>
</html>"""
            
            html_path = markdown_path.replace('.md', '.html')
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return html_path
        except ImportError:
            logger.warning("markdown library not installed. Run: pip install markdown")
            return ""


# Global instance
_report_generator: Optional[ReportGenerator] = None


def get_report_generator() -> ReportGenerator:
    """Get or create the global report generator."""
    global _report_generator
    if _report_generator is None:
        _report_generator = ReportGenerator()
    return _report_generator
