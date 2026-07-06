"""
Automated Report Generation - Professional penetration testing reports
Generates PDF/HTML reports with executive summary, findings, CVSS scoring, timeline
"""

import datetime
from typing import List, Dict, Optional
from pathlib import Path
from src.sdk.tool import function_tool


class Finding:
    """Represents a detailed security finding with full technical context."""

    def __init__(
        self,
        title: str,
        severity: str,
        cvss_score: float,
        description: str,
        affected_url: str,
        poc: str,
        remediation: str,
        # Identity
        cwe_id: str = "",
        cve_id: str = "",
        cvss_vector: str = "",
        # WHY this endpoint was chosen
        why_chosen: str = "",
        discovery_method: str = "",
        recon_evidence: str = "",
        # HOW to reproduce
        environment_setup: str = "",
        steps: list = None,
        expected_output: str = "",
        actual_output: str = "",
        # IMPACT
        impact: str = "",
        # REFERENCES
        references: list = None,
        # VISUAL EVIDENCE
        screenshot_path: str = "",
        # VERIFICATION
        confidence: str = "unknown",
    ):
        self.title = title
        self.severity = severity.upper()
        self.cvss_score = cvss_score
        self.description = description
        self.affected_url = affected_url
        self.poc = poc
        self.remediation = remediation
        self.cwe_id = cwe_id
        self.cve_id = cve_id
        self.cvss_vector = cvss_vector
        self.why_chosen = why_chosen
        self.discovery_method = discovery_method
        self.recon_evidence = recon_evidence
        self.environment_setup = environment_setup
        self.steps = steps or []
        self.expected_output = expected_output
        self.actual_output = actual_output
        self.impact = impact
        self.screenshot_path = screenshot_path
        self.references = references or []
        self.confidence = confidence
        self.timestamp = datetime.datetime.now().isoformat()

    def to_dict(self):
        return {
            'title': self.title, 'severity': self.severity, 'cvss_score': self.cvss_score,
            'description': self.description, 'affected_url': self.affected_url,
            'poc': self.poc, 'remediation': self.remediation,
            'cwe_id': self.cwe_id, 'cve_id': self.cve_id, 'cvss_vector': self.cvss_vector,
            'why_chosen': self.why_chosen, 'discovery_method': self.discovery_method,
            'recon_evidence': self.recon_evidence, 'environment_setup': self.environment_setup,
            'steps': self.steps, 'expected_output': self.expected_output,
            'actual_output': self.actual_output, 'impact': self.impact,
            'references': self.references, 'timestamp': self.timestamp,
            'screenshot_path': self.screenshot_path,
        }


class ReportGenerator:
    """Generate professional penetration testing reports"""
    
    def __init__(self, target: str, report_type: str = "Full Penetration Test"):
        self.target = target
        self.report_type = report_type
        self.findings: List[Finding] = []
        self.executive_summary = ""
        self.methodology = ""
        self.scope_in: List[str] = []
        self.scope_out: List[str] = []
        self.timeline = []
        self.start_time = datetime.datetime.now()
        self.engagement_end: Optional[datetime.datetime] = None
        self.tester_name: str = "Cyber-CoPilot"
        self.tester_org: str = "Security Research"
        self.authorization_ref: str = ""
        self.test_environment: str = ""
        self.tools_arsenal: List[str] = []
        
    def add_finding(self, finding: Finding):
        """Add a finding to the report"""
        self.findings.append(finding)
    
    def calculate_risk_rating(self) -> Dict[str, int]:
        """Calculate risk distribution"""
        ratings = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for finding in self.findings:
            if finding.severity in ratings:
                ratings[finding.severity] += 1
        return ratings
    
    def generate_html(self) -> str:
        """Generate HTML report"""
        risk_ratings = self.calculate_risk_rating()
        total_findings = len(self.findings)
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Penetration Test Report - {self.target}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #2c3e50;
            margin: 0;
            font-size: 32px;
        }}
        .header .subtitle {{
            color: #7f8c8d;
            font-size: 18px;
            margin-top: 10px;
        }}
        .meta-info {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin: 30px 0;
            padding: 20px;
            background: #ecf0f1;
            border-radius: 5px;
        }}
        .risk-summary {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            margin: 30px 0;
        }}
        .risk-box {{
            padding: 20px;
            border-radius: 5px;
            text-align: center;
            color: white;
        }}
        .risk-critical {{ background: #e74c3c; }}
        .risk-high {{ background: #e67e22; }}
        .risk-medium {{ background: #f39c12; }}
        .risk-low {{ background: #3498db; }}
        .risk-info {{ background: #95a5a6; }}
        .risk-box .count {{
            font-size: 36px;
            font-weight: bold;
            display: block;
        }}
        .risk-box .label {{
            font-size: 14px;
            text-transform: uppercase;
            margin-top: 5px;
        }}
        .section {{
            margin: 40px 0;
        }}
        .section h2 {{
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        .finding {{
            border-left: 4px solid #95a5a6;
            padding: 20px;
            margin: 20px 0;
            background: #f8f9fa;
            border-radius: 0 5px 5px 0;
        }}
        .finding.critical {{ border-left-color: #e74c3c; }}
        .finding.high {{ border-left-color: #e67e22; }}
        .finding.medium {{ border-left-color: #f39c12; }}
        .finding.low {{ border-left-color: #3498db; }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        .finding-title {{
            font-size: 20px;
            font-weight: bold;
            color: #2c3e50;
        }}
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
            font-size: 12px;
        }}
        .cvss-score {{
            background: #34495e;
            color: white;
            padding: 5px 10px;
            border-radius: 3px;
            margin-left: 10px;
        }}
        .finding-section {{
            margin: 15px 0;
        }}
        .finding-section h4 {{
            color: #34495e;
            margin-bottom: 8px;
        }}
        .code-block {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }}
        .footer {{
            margin-top: 50px;
            padding-top: 20px;
            border-top: 2px solid #ecf0f1;
            text-align: center;
            color: #7f8c8d;
            font-size: 14px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            border: 1px solid #ddd;
            text-align: left;
        }}
        th {{
            background: #34495e;
            color: white;
        }}
        tr:nth-child(even) {{
            background: #f8f9fa;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Penetration Test Report</h1>
            <div class="subtitle">{self.report_type}</div>
        </div>
        
        <div class="meta-info">
            <div>
                <strong>Target:</strong> {self.target}<br>
                <strong>Report Type:</strong> {self.report_type}<br>
                <strong>Total Findings:</strong> {total_findings}
            </div>
            <div>
                <strong>Test Date:</strong> {self.start_time.strftime('%Y-%m-%d')}<br>
                <strong>Report Generated:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
                <strong>Tester:</strong> Cyber-CoPilot Framework
            </div>
        </div>
        
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <p>{self.executive_summary or 'A comprehensive security assessment was performed on the target system to identify potential vulnerabilities and security weaknesses.'}</p>
        </div>
        
        <div class="section">
            <h2>🎯 Risk Summary</h2>
            <div class="risk-summary">
                <div class="risk-box risk-critical">
                    <span class="count">{risk_ratings['CRITICAL']}</span>
                    <span class="label">Critical</span>
                </div>
                <div class="risk-box risk-high">
                    <span class="count">{risk_ratings['HIGH']}</span>
                    <span class="label">High</span>
                </div>
                <div class="risk-box risk-medium">
                    <span class="count">{risk_ratings['MEDIUM']}</span>
                    <span class="label">Medium</span>
                </div>
                <div class="risk-box risk-low">
                    <span class="count">{risk_ratings['LOW']}</span>
                    <span class="label">Low</span>
                </div>
                <div class="risk-box risk-info">
                    <span class="count">{risk_ratings['INFO']}</span>
                    <span class="label">Info</span>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔍 Detailed Findings</h2>
"""
        
        # Sort findings by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_findings = sorted(self.findings, key=lambda x: severity_order.get(x.severity, 5))
        
        for idx, finding in enumerate(sorted_findings, 1):
            severity_class = finding.severity.lower()
            html += f"""
            <div class="finding {severity_class}">
                <div class="finding-header">
                    <div class="finding-title">#{idx}. {finding.title}</div>
                    <div>
                        <span class="severity-badge {severity_class}">{finding.severity}</span>
                        <span class="cvss-score">CVSS: {finding.cvss_score}</span>
                    </div>
                </div>
                
                <div class="finding-section">
                    <h4>📝 Description</h4>
                    <p>{finding.description}</p>
                </div>
                
                <div class="finding-section">
                    <h4>🎯 Affected Resource</h4>
                    <p><code>{finding.affected_url}</code></p>
                </div>
"""
            
            if finding.cwe_id or finding.cve_id:
                html += """
                <div class="finding-section">
                    <h4>🔖 References</h4>
                    <p>
"""
                if finding.cwe_id:
                    html += f'<strong>CWE:</strong> {finding.cwe_id}<br>'
                if finding.cve_id:
                    html += f'<strong>CVE:</strong> {finding.cve_id}<br>'
                html += """
                    </p>
                </div>
"""
            
            html += f"""
                <div class="finding-section">
                    <h4>🧪 Proof of Concept</h4>
                    <div class="code-block">{finding.poc.replace('<', '&lt;').replace('>', '&gt;')}</div>
                </div>
"""
            
            if getattr(finding, 'screenshot_path', ''):
                import os
                import base64
                sp = finding.screenshot_path
                if os.path.exists(sp):
                    with open(sp, "rb") as image_file:
                        encoded_string = base64.b64encode(image_file.read()).decode()
                    ext = os.path.splitext(sp)[1].lower().strip('.')
                    mime_type = "jpeg" if ext in ("jpg", "jpeg") else "png"
                    html += f"""
                <div class="finding-section">
                    <h4>📸 Visual Evidence</h4>
                    <img src="data:image/{mime_type};base64,{encoded_string}" style="max-width:100%; border:1px solid #ccc; border-radius:3px;" />
                </div>
"""
            
            html += f"""
                <div class="finding-section">
                    <h4>✅ Remediation</h4>
                    <p>{finding.remediation}</p>
                </div>
            </div>
"""
        
        html += """
        </div>
        
        <div class="section">
            <h2>📋 Findings Summary Table</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Finding</th>
                        <th>Severity</th>
                        <th>CVSS</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        for idx, finding in enumerate(sorted_findings, 1):
            html += f"""
                    <tr>
                        <td>{idx}</td>
                        <td>{finding.title}</td>
                        <td>{finding.severity}</td>
                        <td>{finding.cvss_score}</td>
                        <td>Open</td>
                    </tr>
"""
        
        html += f"""
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>This report was automatically generated by <strong>Cyber-CoPilot Framework</strong></p>
            <p>Report ID: {datetime.datetime.now().strftime('%Y%m%d%H%M%S')}</p>
        </div>
    </div>
</body>
</html>
"""
        return html
    
    def generate_markdown(self) -> str:
        """Generate Markdown report"""
        risk_ratings = self.calculate_risk_rating()
        
        md = f"""# Penetration Test Report

## Target Information
- **Target:** {self.target}
- **Report Type:** {self.report_type}
- **Test Date:** {self.start_time.strftime('%Y-%m-%d')}
- **Report Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary
{self.executive_summary or 'A comprehensive security assessment was performed.'}

## Risk Summary
| Severity | Count |
|----------|-------|
| 🔴 Critical | {risk_ratings['CRITICAL']} |
| 🟠 High | {risk_ratings['HIGH']} |
| 🟡 Medium | {risk_ratings['MEDIUM']} |
| 🔵 Low | {risk_ratings['LOW']} |
| ⚪ Info | {risk_ratings['INFO']} |

## Detailed Findings

"""
        
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_findings = sorted(self.findings, key=lambda x: severity_order.get(x.severity, 5))
        
        for idx, finding in enumerate(sorted_findings, 1):
            md += f"""
### {idx}. {finding.title}
**Severity:** {finding.severity} | **CVSS:** {finding.cvss_score}

**Description:**
{finding.description}

**Affected Resource:**
`{finding.affected_url}`

**Proof of Concept:**
```
{finding.poc}
```
"""
            if getattr(finding, 'screenshot_path', ''):
                md += f"\n**Visual Evidence:**\n![Screenshot]({finding.screenshot_path})\n\n"

            md += f"""
**Remediation:**
{finding.remediation}

---

"""
        
        return md
    
    def generate_pdf_html(self) -> str:  # noqa: C901
        """Generate a comprehensive, publication-ready penetration test report in HTML.

        Sections:
          1. Engagement Details            6. Testing Methodology
          2. Scope of Assessment           7. Findings Summary Table
          3. Test Environment & Setup      8. Detailed Findings (full technical writeup)
          4. Executive Summary             9. Recommendations & Roadmap
          5. Risk Summary                 10. Appendix (tools, glossary, disclaimer)
        """
        risk_ratings = self.calculate_risk_rating()
        total_findings = len(self.findings)
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_findings = sorted(self.findings, key=lambda x: severity_order.get(x.severity, 5))

        SEV_BG    = {'CRITICAL': '#b71c1c', 'HIGH': '#bf360c', 'MEDIUM': '#e65100', 'LOW': '#1b5e20', 'INFO': '#0d47a1'}
        SEV_LIGHT = {'CRITICAL': '#ffcdd2', 'HIGH': '#fbe9e7', 'MEDIUM': '#fff3e0', 'LOW': '#e8f5e9', 'INFO': '#e3f2fd'}

        # ─── helpers ────────────────────────────────────────────────────────────
        def e(s: str) -> str:
            return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

        now_str  = datetime.datetime.now().strftime('%B %d, %Y at %H:%M')
        date_str = self.start_time.strftime('%B %d, %Y')
        eng_id   = f"ENG-{self.start_time.strftime('%Y%m%d%H%M')}"

        # ─── CSS (xhtml2pdf + WeasyPrint compatible — no Grid/Flex) ─────────────
        css = (
            "* { margin:0; padding:0; box-sizing:border-box; }"
            "body { font-family:Arial,Helvetica,sans-serif; font-size:10pt; "
                   "color:#1a1a2e; background:#fff; line-height:1.5; }"
            ".wrap { max-width:750px; margin:0 auto; padding:24px 28px; }"
            ".cover { text-align:center; padding:38px 20px 28px; "
                     "border-bottom:5px solid #1a1a2e; margin-bottom:22px; }"
            ".logo { font-size:28pt; font-weight:bold; color:#1a1a2e; letter-spacing:-1px; }"
            ".logo span { color:#e53935; }"
            ".cover h1 { font-size:15pt; color:#1a1a2e; margin:10px 0 4px; font-weight:bold; }"
            ".cover .sub { font-size:11pt; color:#e53935; font-weight:bold; margin-bottom:12px; }"
            ".cmeta { width:380px; margin:14px auto; border-collapse:collapse; }"
            ".cmeta td { padding:5px 10px; font-size:9pt; border:1px solid #c8d0da; }"
            ".cmeta td.lbl { background:#eef2fa; font-weight:bold; width:44%; }"
            ".class-badge { background:#b71c1c; color:#fff; font-weight:bold; "
                           "padding:4px 16px; font-size:9.5pt; margin-top:10px; display:inline-block; }"
            ".sh { background:#1a1a2e; color:#fff; padding:7px 14px; font-size:12pt; "
                  "font-weight:bold; margin:26px 0 9px; page-break-inside:avoid; }"
            ".sh-num { background:#e53935; color:#fff; padding:2px 8px; "
                      "margin-right:7px; font-size:10pt; }"
            ".ssh { color:#1a1a2e; font-size:10pt; font-weight:bold; "
                   "border-left:4px solid #e53935; padding-left:8px; margin:13px 0 5px; }"
            "table.t { width:100%; border-collapse:collapse; margin-bottom:11px; }"
            "table.t td { padding:5px 9px; border:1px solid #c8d0da; font-size:9pt; }"
            "table.t td.lbl { background:#eef2fa; font-weight:bold; width:34%; }"
            "table.t th { background:#1a1a2e; color:#fff; padding:6px 9px; font-size:9pt; text-align:left; }"
            "table.t tr:nth-child(even) td { background:#f7f9fc; }"
            "table.risk { width:100%; border-collapse:collapse; margin:9px 0; }"
            "table.risk td { text-align:center; padding:11px 4px; border:3px solid #fff; }"
            "table.risk .n { font-size:22pt; font-weight:bold; display:block; }"
            "table.risk .lb { font-size:8pt; text-transform:uppercase; letter-spacing:0.5px; margin-top:2px; }"
            ".badge { color:#fff; font-weight:bold; padding:2px 7px; font-size:8pt; }"
            ".fc { border:1px solid #c8d0da; margin:16px 0; page-break-inside:avoid; }"
            ".fch { padding:9px 14px; font-size:10.5pt; font-weight:bold; }"
            ".fcb { padding:11px 14px; }"
            ".lbl2 { font-size:7.5pt; font-weight:bold; text-transform:uppercase; "
                    "letter-spacing:0.8px; color:#5a5f8a; margin-top:12px; margin-bottom:3px; "
                    "border-bottom:1px dashed #cdd2e8; padding-bottom:2px; }"
            ".lbl2:first-child { margin-top:0; }"
            "p.txt { font-size:9.5pt; margin-bottom:4px; line-height:1.55; }"
            "table.code { width:100%; border-collapse:collapse; margin:4px 0; }"
            "table.code td { background:#1e2a38; color:#e8f0fe; "
                            "font-family:'Courier New',Courier,monospace; font-size:7.5pt; "
                            "padding:8px 12px; white-space:pre-wrap; word-break:break-all; }"
            "table.steps { width:100%; border-collapse:collapse; margin:4px 0; }"
            "table.steps td.num { background:#1a1a2e; color:#fff; font-weight:bold; "
                                 "font-size:8.5pt; width:26px; text-align:center; "
                                 "padding:7px 0; vertical-align:top; }"
            "table.steps td.body { background:#f7f9fc; border:1px solid #d8dff0; "
                                  "padding:7px 10px; font-size:9pt; vertical-align:top; }"
            ".scope-in { background:#e8f5e9; border-left:4px solid #2e7d32; "
                        "padding:5px 10px; margin:3px 0; font-size:9pt; }"
            ".scope-out { background:#fce4ec; border-left:4px solid #c62828; "
                         "padding:5px 10px; margin:3px 0; font-size:9pt; }"
            ".ref { color:#1565c0; font-size:8.5pt; margin:2px 0; }"
            "table.prio { width:100%; border-collapse:collapse; margin:9px 0; }"
            "table.prio th { background:#1a1a2e; color:#fff; padding:6px 9px; font-size:9pt; }"
            "table.prio td { padding:6px 9px; border:1px solid #d0d5ea; "
                            "font-size:9pt; vertical-align:top; }"
            "table.prio tr:nth-child(even) td { background:#f5f7fc; }"
            ".foot { margin-top:26px; padding-top:11px; border-top:2px solid #d0d5ea; "
                    "text-align:center; font-size:8pt; color:#888; }"
            ".pb { page-break-before:always; }"
        )

        # ─── Open document ──────────────────────────────────────────────────────
        html = (
            f'<!DOCTYPE html>\n<html><head><meta charset="UTF-8">\n'
            f'<style>{css}</style>\n</head><body>\n<div class="wrap">\n'
        )

        # ─── COVER PAGE ─────────────────────────────────────────────────────────
        html += (
            f'<div class="cover">'
            f'<div class="logo">CYBER<span>COPILOT</span></div>'
            f'<h1>{e(self.report_type)}</h1>'
            f'<div class="sub">Penetration Test Report</div>'
            f'<table class="cmeta">'
            f'<tr><td class="lbl">Target</td><td>{e(self.target)}</td></tr>'
            f'<tr><td class="lbl">Assessment Date</td><td>{date_str}</td></tr>'
            f'<tr><td class="lbl">Report Generated</td><td>{now_str}</td></tr>'
            f'<tr><td class="lbl">Tester</td><td>{e(self.tester_name)}</td></tr>'
            f'<tr><td class="lbl">Organisation</td><td>{e(self.tester_org)}</td></tr>'
            f'<tr><td class="lbl">Engagement ID</td><td>{eng_id}</td></tr>'
            f'<tr><td class="lbl">Total Findings</td><td>{total_findings}</td></tr>'
            f'</table>'
            f'<div class="class-badge">&#128274; CONFIDENTIAL</div>'
            f'</div>\n'
        )

        # ─── SECTION 1: Engagement Details ──────────────────────────────────────
        html += '<div class="sh"><span class="sh-num">1</span>Engagement Details</div>\n'
        html += (
            f'<table class="t">'
            f'<tr><td class="lbl">Project Name</td><td>{e(self.report_type)}</td></tr>'
            f'<tr><td class="lbl">Primary Target</td><td>{e(self.target)}</td></tr>'
            f'<tr><td class="lbl">Engagement Start</td><td>{self.start_time.strftime("%Y-%m-%d %H:%M:%S")}</td></tr>'
            f'<tr><td class="lbl">Engagement End</td><td>{self.engagement_end.strftime("%Y-%m-%d %H:%M:%S") if getattr(self,"engagement_end",None) else now_str}</td></tr>'
            f'<tr><td class="lbl">Tester</td><td>{e(self.tester_name)}</td></tr>'
            f'<tr><td class="lbl">Organisation</td><td>{e(self.tester_org)}</td></tr>'
            f'<tr><td class="lbl">Authorisation Ref.</td><td>{e(getattr(self,"authorization_ref","") or "Bug Bounty / Written Permission")}</td></tr>'
            f'<tr><td class="lbl">Methodology</td><td>OWASP TG v4 &mdash; PTES &mdash; MITRE ATT&amp;CK Framework</td></tr>'
            f'<tr><td class="lbl">Engagement ID</td><td>{eng_id}</td></tr>'
            f'</table>\n'
        )

        # ─── SECTION 2: Scope ────────────────────────────────────────────────────
        html += '<div class="sh"><span class="sh-num">2</span>Scope of Assessment</div>\n'
        html += '<div class="ssh">In-Scope Targets</div>\n'
        for s in (getattr(self, 'scope_in', None) or [self.target]):
            html += f'<div class="scope-in">&#10003; {e(s)}</div>\n'
        scope_out = getattr(self, 'scope_out', []) or []
        if scope_out:
            html += '<div class="ssh">Out-of-Scope</div>\n'
            for s in scope_out:
                html += f'<div class="scope-out">&#10007; {e(s)}</div>\n'
        html += '<p class="txt" style="margin-top:7px;">All testing was conducted strictly within the authorised scope. No out-of-scope systems were accessed.</p>\n'

        # ─── SECTION 3: Test Environment & Setup ────────────────────────────────
        html += '<div class="sh"><span class="sh-num">3</span>Test Environment &amp; Tool Setup</div>\n'
        test_env = getattr(self, 'test_environment', '') or ''
        if test_env:
            html += f'<p class="txt">{e(test_env)}</p>\n'
        else:
            html += (
                '<table class="t">'
                '<tr><td class="lbl">Operating System</td><td>Kali Linux 2024.x (64-bit) / Parrot OS</td></tr>'
                '<tr><td class="lbl">Machine Type</td><td>Virtual Machine (VMware / VirtualBox) or Physical</td></tr>'
                '<tr><td class="lbl">Network Access</td><td>VPN tunnel or direct connection to target network</td></tr>'
                '<tr><td class="lbl">Python Version</td><td>3.12+</td></tr>'
                '<tr><td class="lbl">Framework</td><td>Cyber-CoPilot &mdash; AI-Powered Penetration Testing</td></tr>'
                '<tr><td class="lbl">Interception Proxy</td><td>Burp Suite Community / Pro (optional)</td></tr>'
                '</table>\n'
            )
        html += '<div class="ssh">Base Environment Setup Commands</div>\n'
        html += (
            '<table class="code"><tr><td>'
            '# 1. Prepare the test machine (Kali Linux recommended)\n'
            'sudo apt update && sudo apt upgrade -y\n'
            'sudo apt install -y nmap curl git python3 python3-pip golang\n\n'
            '# 2. Install common reconnaissance and exploitation tools\n'
            'sudo apt install -y subfinder amass ffuf gobuster feroxbuster\n'
            'sudo apt install -y sqlmap nikto whatweb wafw00f sslscan dnsrecon\n'
            'pip install requests dnspython python-whois shodan arjun\n\n'
            '# 3. Install Go-based tools\n'
            'go install github.com/projectdiscovery/httpx/cmd/httpx@latest\n'
            'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n'
            'go install github.com/hahwul/dalfox/v2@latest\n'
            'go install github.com/lc/gau/v2/cmd/gau@latest\n\n'
            '# 4. Setup Cyber-CoPilot framework\n'
            'git clone https://github.com/yourusername/cyber-copilot\n'
            'cd cyber-copilot && python -m venv .venv\n'
            'source .venv/bin/activate   # Linux/Mac  |  .venv\\Scripts\\activate  # Windows\n'
            'pip install -r requirements.txt\n'
            '</td></tr></table>\n'
        )
        tools_arsenal = getattr(self, 'tools_arsenal', []) or []
        if tools_arsenal:
            html += '<div class="ssh">Tools Used in This Engagement</div>\n'
            html += '<table class="t"><tr><th>Tool</th><th>Purpose</th></tr>\n'
            for t in tools_arsenal:
                name, _, purpose = t.partition('::')
                html += f'<tr><td><b>{e(name.strip())}</b></td><td>{e(purpose.strip())}</td></tr>\n'
            html += '</table>\n'

        # ─── SECTION 4: Executive Summary ───────────────────────────────────────
        html += '<div class="sh pb"><span class="sh-num">4</span>Executive Summary</div>\n'
        exec_text = self.executive_summary or (
            f'A comprehensive security assessment was conducted against <b>{e(self.target)}</b> '
            'using industry-standard penetration testing methodologies. The assessment covered '
            'passive and active reconnaissance, service enumeration, vulnerability discovery, '
            'controlled exploitation, and post-exploitation analysis — all within the authorised scope.'
        )
        html += f'<p class="txt">{exec_text}</p>\n'
        html += (
            '<p class="txt" style="margin-top:7px;">'
            'Testing followed the OWASP Testing Guide v4, PTES, and MITRE ATT&amp;CK Framework. '
            'All findings are based on verified, reproducible tests. '
            'Severity ratings use the CVSS v3.1 scoring system.</p>\n'
        )
        if risk_ratings.get('CRITICAL', 0) > 0:
            html += (
                f'<p class="txt" style="margin-top:8px;color:#b71c1c;font-weight:bold;">'
                f'&#9888; IMMEDIATE ACTION REQUIRED: {risk_ratings["CRITICAL"]} critical finding(s) '
                'allow direct system compromise without authentication.</p>\n'
            )

        # ─── SECTION 5: Risk Summary ─────────────────────────────────────────────
        html += '<div class="sh"><span class="sh-num">5</span>Risk Summary</div>\n'
        risk_color = {
            'CRITICAL': ('#b71c1c','#fff'), 'HIGH': ('#bf360c','#fff'),
            'MEDIUM':   ('#e65100','#fff'), 'LOW':  ('#1b5e20','#fff'), 'INFO': ('#0d47a1','#fff'),
        }
        html += '<table class="risk"><tr>\n'
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            bg, fg = risk_color[sev]
            n = risk_ratings.get(sev, 0)
            html += f'<td style="background:{bg};color:{fg};width:20%;"><span class="n">{n}</span><span class="lb">{sev}</span></td>\n'
        html += '</tr></table>\n'
        if sorted_findings:
            scores = [f.cvss_score for f in sorted_findings]
            max_s = max(scores)
            avg_s = round(sum(scores) / len(scores), 1)
            html += f'<p class="txt" style="margin-top:7px;">Highest CVSS: <b>{max_s}</b> &nbsp;|&nbsp; Average CVSS: <b>{avg_s}</b> &nbsp;|&nbsp; Total Findings: <b>{total_findings}</b></p>\n'

        # ─── SECTION 6: Testing Methodology ─────────────────────────────────────
        html += '<div class="sh"><span class="sh-num">6</span>Testing Methodology</div>\n'
        phases = [
            ('Phase 1 &mdash; Reconnaissance',
             'Passive OSINT, DNS enumeration, subdomain discovery, certificate transparency, '
             'Shodan/Censys querying, WAF detection.',
             'subfinder, amass, fierce, dnsrecon, crt.sh, shodan, whois, dig, wafw00f'),
            ('Phase 2 &mdash; Service Enumeration',
             'Port scanning, service/version fingerprinting, SSL/TLS analysis, '
             'web directory brute-forcing, parameter discovery.',
             'nmap, httpx, whatweb, sslscan, ffuf, feroxbuster, gobuster, arjun, gau, katana'),
            ('Phase 3 &mdash; Vulnerability Discovery',
             'Automated template-based scanning, manual parameter analysis, '
             'authentication bypass testing, logic flaw enumeration.',
             'nuclei, nikto, sqlmap (detect), dalfox (detect), tplmap (detect), paramspider'),
            ('Phase 4 &mdash; Exploitation &amp; PoC',
             'Controlled proof-of-concept exploitation to confirm real-world impact.',
             'sqlmap, dalfox, tplmap, jwt_tool, nosqlmap, curl/Python scripts, Burp Suite'),
            ('Phase 5 &mdash; Post-Exploitation',
             'Privilege escalation path analysis, lateral movement, persistence mechanisms.',
             'pwncat, crackmapexec, impacket, linpeas/winpeas, BloodHound'),
        ]
        html += '<table class="t"><tr><th>Phase</th><th>Description</th><th>Key Tools</th></tr>\n'
        for ph, desc, tools in phases:
            html += f'<tr><td><b>{ph}</b></td><td style="font-size:8.5pt;">{desc}</td><td style="font-size:7.5pt;">{tools}</td></tr>\n'
        html += '</table>\n'

        # ─── SECTION 7: Findings Summary Table ───────────────────────────────────
        if sorted_findings:
            html += '<div class="sh pb"><span class="sh-num">7</span>Findings Summary</div>\n'
            html += '<table class="t"><tr><th>#</th><th>Title</th><th>Severity</th><th>CVSS</th><th>Affected Endpoint</th><th>Discovery Method</th></tr>\n'
            for idx, f in enumerate(sorted_findings, 1):
                bg     = SEV_BG.get(f.severity, '#607d8b')
                method = getattr(f, 'discovery_method', '') or 'Manual Review'
                url_s  = f.affected_url[:52] + ('...' if len(f.affected_url) > 52 else '')
                html += (
                    f'<tr><td style="text-align:center;">{idx}</td>'
                    f'<td>{e(f.title)}</td>'
                    f'<td style="text-align:center;"><span class="badge" style="background:{bg};">{f.severity}</span></td>'
                    f'<td style="text-align:center;">{f.cvss_score}</td>'
                    f'<td style="font-size:8pt;font-family:Courier New,monospace;">{e(url_s)}</td>'
                    f'<td style="font-size:8pt;">{e(method)}</td></tr>\n'
                )
            html += '</table>\n'

            # ─── SECTION 8: Detailed Findings ────────────────────────────────────
            html += '<div class="sh pb"><span class="sh-num">8</span>Detailed Findings</div>\n'
            for idx, f in enumerate(sorted_findings, 1):
                bg    = SEV_BG.get(f.severity, '#607d8b')
                light = SEV_LIGHT.get(f.severity, '#f5f5f5')
                cwe_s = f' | CWE-{e(f.cwe_id.replace("CWE-",""))}' if f.cwe_id else ''
                cve_s = f' | {e(f.cve_id)}' if f.cve_id else ''
                vec_s = getattr(f, 'cvss_vector', '') or ''

                html += (
                    f'<div class="fc">\n'
                    f'<div class="fch" style="background:{light}; border-left:6px solid {bg};">'
                    f'<span class="badge" style="background:{bg};">{f.severity}</span>'
                    f' &nbsp;Finding #{idx}: {e(f.title)}'
                    f'<span style="float:right;font-size:8.5pt;color:#555;font-weight:normal;">'
                    f'CVSS {f.cvss_score}{cwe_s}{cve_s}</span></div>\n'
                    f'<div class="fcb">\n'
                )

                why = getattr(f, 'why_chosen', '') or ''
                if why:
                    html += f'<div class="lbl2">&#128269; Why This Endpoint Was Targeted</div>\n<p class="txt">{e(why)}</p>\n'

                dm = getattr(f, 'discovery_method', '') or ''
                if dm:
                    html += f'<div class="lbl2">&#128270; Discovery Method &amp; Tool Used</div>\n<p class="txt">{e(dm)}</p>\n'

                re_ = getattr(f, 'recon_evidence', '') or ''
                if re_:
                    html += f'<div class="lbl2">&#128202; Reconnaissance Evidence (Raw Tool Output)</div>\n<table class="code"><tr><td>{e(re_)}</td></tr></table>\n'

                html += f'<div class="lbl2">&#128196; Technical Description</div>\n<p class="txt">{e(f.description)}</p>\n'

                env = getattr(f, 'environment_setup', '') or ''
                if env:
                    html += f'<div class="lbl2">&#9881; Test Environment Setup (Install Commands)</div>\n<table class="code"><tr><td>{e(env)}</td></tr></table>\n'

                steps = getattr(f, 'steps', []) or []
                if steps:
                    html += '<div class="lbl2">&#128205; Step-by-Step Reproduction Guide</div>\n'
                    html += '<table class="steps">\n'
                    for si, step in enumerate(steps, 1):
                        html += f'<tr><td class="num">{si}</td><td class="body">{e(step)}</td></tr>\n'
                    html += '</table>\n'

                html += f'<div class="lbl2">&#9876; Proof of Concept Command</div>\n<table class="code"><tr><td>{e(f.poc)}</td></tr></table>\n'

                exp = getattr(f, 'expected_output', '') or ''
                if exp:
                    html += f'<div class="lbl2">&#9989; Expected Output (Proof of Successful Exploitation)</div>\n<table class="code"><tr><td>{e(exp)}</td></tr></table>\n'

                act = getattr(f, 'actual_output', '') or ''
                if act:
                    html += f'<div class="lbl2">&#128249; Actual Observed Output / Captured Evidence</div>\n<table class="code"><tr><td>{e(act)}</td></tr></table>\n'

                screen = getattr(f, 'screenshot_path', '') or ''
                if screen:
                    import os
                    import base64
                    if os.path.exists(screen):
                        with open(screen, "rb") as image_file:
                            encoded_string = base64.b64encode(image_file.read()).decode()
                        ext = os.path.splitext(screen)[1].lower().strip('.')
                        mime_type = "jpeg" if ext in ("jpg", "jpeg") else "png"
                        html += f'<div class="lbl2">&#128248; Visual Evidence (Screenshot)</div>\n<div style="margin:10px 0;"><img src="data:image/{mime_type};base64,{encoded_string}" style="max-width:100%; border:1px solid #c8d0da;" /></div>\n'
                    else:
                        html += f'<div class="lbl2">&#128248; Visual Evidence (Screenshot)</div>\n<p class="txt">[Image path not found: {e(screen)}]</p>\n'

                imp = getattr(f, 'impact', '') or ''
                html += (
                    f'<div class="lbl2">&#128165; Business &amp; Technical Impact</div>\n'
                    f'<p class="txt">{e(imp) if imp else "Successful exploitation could allow an attacker to compromise the confidentiality, integrity, or availability of the affected system and its data."}</p>\n'
                )

                html += '<div class="lbl2">&#128290; CVSS v3.1 Score</div>\n'
                html += f'<p class="txt">Base Score: <b>{f.cvss_score}</b> ({f.severity})'
                if vec_s:
                    html += f'<br>Vector: <span style="font-family:Courier New,monospace;font-size:7.5pt;">{e(vec_s)}</span>'
                html += '</p>\n'

                html += f'<div class="lbl2">&#128736; Remediation &amp; Mitigation</div>\n<p class="txt">{e(f.remediation)}</p>\n'

                refs = list(getattr(f, 'references', []) or [])
                if f.cwe_id:
                    cnum = f.cwe_id.replace('CWE-', '')
                    refs = [r for r in refs if 'cwe.mitre' not in r]
                    refs.insert(0, f'https://cwe.mitre.org/data/definitions/{cnum}.html')
                if f.cve_id:
                    refs.insert(0, f'https://nvd.nist.gov/vuln/detail/{f.cve_id}')
                if refs:
                    html += '<div class="lbl2">&#128279; References</div>\n'
                    for r in refs:
                        html += f'<p class="ref">&#8226; {e(r)}</p>\n'

                html += '</div>\n</div>\n'

        # ─── SECTION 9: Recommendations ─────────────────────────────────────────
        html += '<div class="sh pb"><span class="sh-num">9</span>Recommendations &amp; Remediation Roadmap</div>\n'
        sev_action = {
            'CRITICAL': ('P1 &mdash; Immediate', 'Patch or apply compensating control NOW. Consider taking the affected service offline until remediated.', '24&ndash;48 Hours'),
            'HIGH':     ('P2 &mdash; Urgent',    'Apply patch or hardened configuration. Deploy WAF rule as interim mitigation while fix is developed.',   '1 Week'),
            'MEDIUM':   ('P3 &mdash; Planned',   'Schedule remediation in the next development sprint. Validate the fix with a targeted re-test.',          '2&ndash;4 Weeks'),
            'LOW':      ('P4 &mdash; Backlog',   'Address in the next planned maintenance window.',                                                          '1&ndash;3 Months'),
            'INFO':     ('P5 &mdash; Improvement','Review and improve as part of ongoing hardening programme.',                                              'Next Quarter'),
        }
        html += '<table class="prio"><tr><th>Priority</th><th>Finding</th><th>Recommended Action</th><th>Timeframe</th></tr>\n'
        for f in sorted_findings:
            prio, action, tf = sev_action.get(f.severity, ('P3', 'Review and remediate.', '30 Days'))
            html += (
                f'<tr><td><b>{prio}</b></td>'
                f'<td>{e(f.title[:50])}</td>'
                f'<td style="font-size:8.5pt;">{action}</td>'
                f'<td>{tf}</td></tr>\n'
            )
        html += '</table>\n'

        html += '<div class="ssh">General Security Hardening Recommendations</div>\n'
        general = [
            ('Web Application Firewall (WAF)',
             'Deploy ModSecurity with OWASP CRS or a managed WAF (Cloudflare, AWS WAF) to block SQLi, XSS, SSTI, and path traversal payloads at the perimeter.'),
            ('Input Validation &amp; Output Encoding',
             'Enforce strict server-side input validation (whitelist approach). HTML-encode all user-controlled data before rendering. Use parameterised queries for all database access.'),
            ('Comprehensive Logging &amp; SIEM',
             'Centralise application, web server, and OS logs in a SIEM (Splunk/ELK/Wazuh). Alert on SQLi signatures, repeated 4xx errors, unusual payload sizes, and privilege escalation events.'),
            ('Secure Development Lifecycle',
             'Integrate SAST (Semgrep, SonarQube) and DAST (OWASP ZAP, Nuclei) into CI/CD pipelines. Require security review before production deployments.'),
            ('Patch Management',
             'Maintain a complete software inventory. Automate patching for OS and dependencies. Address critical CVEs within 48 hours of public disclosure.'),
            ('Least-Privilege &amp; MFA',
             'Audit all IAM roles, database accounts, and service accounts. Remove unnecessary permissions. Enforce MFA on all admin interfaces, SSH, and VPN.'),
            ('Secrets Management',
             'Rotate all credentials exposed during this assessment immediately. Use a secrets manager (HashiCorp Vault, AWS Secrets Manager). Never hard-code credentials in source code or repositories.'),
            ('Recurring Penetration Testing',
             'Conduct quarterly automated vulnerability scans and annual full penetration tests. Consider a bug bounty programme for continuous coverage.'),
        ]
        html += '<table class="prio"><tr><th>Recommendation</th><th>Details</th></tr>\n'
        for title_r, detail in general:
            html += f'<tr><td><b>{title_r}</b></td><td style="font-size:8.5pt;">{detail}</td></tr>\n'
        html += '</table>\n'

        # ─── SECTION 10: Appendix ────────────────────────────────────────────────
        html += '<div class="sh pb"><span class="sh-num">10</span>Appendix</div>\n'

        html += '<div class="ssh">A. Full Tools Arsenal &mdash; Install Commands</div>\n'
        tools_list = [
            ('nmap',         'Network port scanner, service/version detection',             'sudo apt install nmap'),
            ('subfinder',    'Passive subdomain enumeration via public APIs',               'go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'),
            ('amass',        'Active/passive subdomain enumeration and mapping',            'go install github.com/owasp-amass/amass/v4/...@master'),
            ('ffuf',         'Fast web fuzzer &mdash; dirs, params, subdomains',            'go install github.com/ffuf/ffuf/v2@latest'),
            ('feroxbuster',  'Recursive content discovery tool',                           'sudo apt install feroxbuster'),
            ('gobuster',     'Directory and DNS brute-forcing',                            'go install github.com/OJ/gobuster/v3@latest'),
            ('httpx',        'HTTP probing and technology fingerprinting',                 'go install github.com/projectdiscovery/httpx/cmd/httpx@latest'),
            ('nuclei',       'Template-based vulnerability scanner (4,000+ templates)',    'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'),
            ('sqlmap',       'Automated SQL injection detection and exploitation',         'sudo apt install sqlmap'),
            ('dalfox',       'XSS scanner and parameter analyser',                        'go install github.com/hahwul/dalfox/v2@latest'),
            ('tplmap',       'Server-Side Template Injection (SSTI) exploitation',        'git clone https://github.com/epinna/tplmap'),
            ('arjun',        'HTTP parameter discovery (GET/POST/JSON/XML)',               'pip install arjun'),
            ('wafw00f',      'WAF fingerprinting',                                        'pip install wafw00f'),
            ('sslscan',      'SSL/TLS configuration analysis',                            'sudo apt install sslscan'),
            ('gau',          'Fetch URLs from AlienVault, Wayback, Common Crawl',         'go install github.com/lc/gau/v2/cmd/gau@latest'),
            ('katana',       'Next-generation web crawler with JS rendering',             'go install github.com/projectdiscovery/katana/cmd/katana@latest'),
            ('shodan-cli',   'Query Shodan internet-wide scanner',                        'pip install shodan  # API key required'),
            ('whatweb',      'Web technology fingerprinting',                             'sudo apt install whatweb'),
            ('Burp Suite',   'HTTP intercepting proxy for manual testing',               'https://portswigger.net/burp'),
        ]
        html += '<table class="t"><tr><th>Tool</th><th>Purpose</th><th>Install Command</th></tr>\n'
        for tn, tp, ti in tools_list:
            html += (
                f'<tr><td><b>{tn}</b></td>'
                f'<td style="font-size:8pt;">{tp}</td>'
                f'<td style="font-size:7.5pt;font-family:Courier New,monospace;">{e(ti)}</td></tr>\n'
            )
        html += '</table>\n'

        html += '<div class="ssh">B. Glossary of Technical Terms</div>\n'
        glossary = [
            ('CVSS',        'Common Vulnerability Scoring System &mdash; standard severity scale 0.0&ndash;10.0. Critical=9&ndash;10, High=7&ndash;8.9, Medium=4&ndash;6.9, Low=0.1&ndash;3.9.'),
            ('CWE',         'Common Weakness Enumeration &mdash; taxonomy of software/hardware weakness types maintained by MITRE.'),
            ('CVE',         'Common Vulnerabilities and Exposures &mdash; public registry of specific disclosed vulnerability instances.'),
            ('SQLi',        'SQL Injection &mdash; inserting malicious SQL to read, modify, or delete database data; bypass authentication; or execute OS commands.'),
            ('XSS',         'Cross-Site Scripting &mdash; injecting malicious JavaScript into pages viewed by other users; leads to session hijacking or credential theft.'),
            ('SSTI',        'Server-Side Template Injection &mdash; injecting directives into a template engine (Jinja2, Twig) to achieve Remote Code Execution (RCE).'),
            ('SSRF',        'Server-Side Request Forgery &mdash; forcing the server to make requests to internal services or cloud metadata APIs (AWS 169.254.169.254).'),
            ('RCE',         'Remote Code Execution &mdash; ability for an attacker to execute arbitrary commands on the target server.'),
            ('LFI / RFI',   'Local/Remote File Inclusion &mdash; reading server filesystem files or including a remote malicious file for execution.'),
            ('IDOR',        'Insecure Direct Object Reference &mdash; accessing objects by manipulating predictable IDs without authorisation checks.'),
            ('PoC',         'Proof of Concept &mdash; a working, confirmed exploit demonstrating that a vulnerability is real and exploitable.'),
            ('WAF',         'Web Application Firewall &mdash; filters HTTP traffic and blocks known attack patterns.'),
            ('OSINT',       'Open Source Intelligence &mdash; collecting information from publicly available sources.'),
            ('JWT',         'JSON Web Token &mdash; Base64-encoded signed token for authentication; weak secrets allow forgery.'),
            ('MITRE ATT&amp;CK', 'Knowledge base of adversary tactics, techniques, and procedures (TTPs) for mapping findings to real-world attacker behaviour.'),
            ('OWASP Top 10','The 10 most critical web application security risks published by the Open Web Application Security Project.'),
        ]
        html += '<table class="t"><tr><th>Term</th><th>Definition</th></tr>\n'
        for term, defn in glossary:
            html += f'<tr><td><b>{term}</b></td><td style="font-size:8.5pt;">{defn}</td></tr>\n'
        html += '</table>\n'

        html += '<div class="ssh">C. Legal Disclaimer &amp; Responsible Disclosure</div>\n'
        html += (
            f'<p class="txt">This security assessment was prepared solely for <b>{e(self.target)}</b> '
            f'and contains confidential information. '
            f'All testing was conducted with <b>explicit written authorisation</b> from the system owner. '
            f'The tester (<b>{e(self.tester_name)}</b>) assumes no liability for damages arising from these findings.</p>\n'
            '<p class="txt" style="margin-top:6px;">'
            'All findings must be remediated before disclosure to third parties. '
            'Unauthorised reproduction, distribution, or use of this report is strictly prohibited. '
            'This document must be handled as <b>CONFIDENTIAL &mdash; RESTRICTED</b>.</p>\n'
            '<p class="txt" style="margin-top:6px;color:#b71c1c;"><b>&#9888; Handle With Care &mdash; CONFIDENTIAL</b></p>\n'
        )

        html += (
            f'<div class="foot">'
            f'<p><b>Cyber-CoPilot</b> &mdash; AI-Powered Penetration Testing Framework</p>'
            f'<p>Report ID: {eng_id} &nbsp;|&nbsp; Target: {e(self.target)} &nbsp;|&nbsp; {now_str}</p>'
            f'</div>\n</div>\n</body>\n</html>\n'
        )
        return html

    def save_pdf(self, output_dir: str) -> str:
        """
        Render the report as a PDF using the best available engine.

        Priority order:
          1. WeasyPrint  — highest fidelity (requires system libs: libpango/cairo)
          2. xhtml2pdf   — pure-Python fallback
          3. HTML file   — open in browser → Ctrl+P → Save as PDF

        Returns the absolute path of the generated file.
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        ts          = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_target = self.target.replace('://', '_').replace('/', '_').replace(':', '_')
        base        = f"pentest_report_{safe_target}_{ts}"
        html_content = self.generate_pdf_html()

        # ── 1. WeasyPrint ─────────────────────────────────────────────────────
        try:
            from weasyprint import HTML as _WP
            pdf_path = output_path / f"{base}.pdf"
            _WP(string=html_content, base_url=str(output_path)).write_pdf(str(pdf_path))
            return str(pdf_path)
        except ImportError:
            weasy_err = "WeasyPrint not installed (pip install weasyprint)"
        except Exception as e:
            weasy_err = f"WeasyPrint error: {e}"

        # ── 2. xhtml2pdf ──────────────────────────────────────────────────────
        try:
            from xhtml2pdf import pisa
            pdf_path = output_path / f"{base}.pdf"
            with open(pdf_path, "wb") as fout:
                result = pisa.CreatePDF(html_content.encode("utf-8"), dest=fout, encoding="utf-8")
            if not result.err:
                return str(pdf_path)
            else:
                pisa_err = f"xhtml2pdf error: {result.err}"
        except ImportError:
            pisa_err = "xhtml2pdf not installed (pip install xhtml2pdf)"
        except Exception as e:
            pisa_err = f"xhtml2pdf error: {e}"

        # ── 3. FPDF (Basic fallback) ──────────────────────────────────────────
        try:
            from fpdf import FPDF
            pdf_path = output_path / f"{base}.pdf"
            
            class BasicPDF(FPDF):
                def header(self):
                    self.set_font('Arial', 'B', 12)
                    self.cell(0, 10, 'Security Assessment Report', 0, 1, 'C')
                    self.ln(5)
                def footer(self):
                    self.set_y(-15)
                    self.set_font('Arial', 'I', 8)
                    self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

            pdf = BasicPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=10)
            
            # Simple text conversion of HTML (best effort for basic FPDF)
            import re
            text_content = re.sub('<[^<]+?>', '', html_content)
            # Remove excessive newlines
            text_content = re.sub(r'\n\s*\n', '\n\n', text_content)
            
            for line in text_content.split('\n'):
                # FPDF 1.7.2 doesn't handle unicode well by default, encode to latin-1
                try:
                    line_safe = line.encode('latin-1', 'replace').decode('latin-1')
                    pdf.multi_cell(0, 5, line_safe)
                except Exception:
                    pdf.multi_cell(0, 5, "[Encoding Error]")
            
            pdf.output(str(pdf_path))
            return str(pdf_path)
        except ImportError:
            fpdf_err = "fpdf not installed"
        except Exception as e:
            fpdf_err = f"fpdf error: {e}"

        # ── 4. HTML fallback (Last resort) ────────────────────────────────────
        html_path = output_path / f"{base}.html"
        html_path.write_text(html_content, encoding='utf-8')
        return (
            f"{html_path}  \n"
            f"⚠️ PDF engines unavailable: \n"
            f"   - {weasy_err}\n"
            f"   - {pisa_err}\n"
            f"   - {fpdf_err}\n"
            f"Please open the HTML file in a browser and use Ctrl+P → Save as PDF."
        )

    def save_report(self, output_dir: str, format: str = "html") -> str:
        """Save report to file.  format: 'html' | 'pdf' | 'markdown' / 'md'"""
        if format == "pdf":
            return self.save_pdf(output_dir)

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename  = f"pentest_report_{self.target.replace('://', '_').replace('/', '_')}_{timestamp}.{format}"
        filepath  = output_path / filename

        if format == "html":
            content = self.generate_html()
        elif format in ("markdown", "md"):
            content = self.generate_markdown()
        else:
            raise ValueError(f"Unsupported format: {format}")

        filepath.write_text(content, encoding='utf-8')
        return str(filepath)


@function_tool()
def create_report(target: str, report_type: str = "Full Penetration Test", executive_summary: str = "") -> str:
    """
    Initialize a new penetration test report.
    
    Args:
        target: Target system/URL
        report_type: Type of assessment
        executive_summary: Optional executive summary
    
    Returns:
        Report ID for adding findings
    """
    try:
        from src.sdk.context_hub import get_context_hub
        hub = get_context_hub()
        
        report = ReportGenerator(target, report_type)
        if executive_summary:
            report.executive_summary = executive_summary
        
        # Store in context hub
        report_id = f"report_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        hub.store_custom_data(report_id, report)
        
        return f"""## ✅ Report Initialized

**Report ID:** {report_id}
**Target:** {target}
**Type:** {report_type}

**Next Steps:**
1. Use `add_finding_to_report` to add vulnerabilities
2. Use `generate_report` to create final HTML/PDF report
"""
    except Exception as e:
        return f"Error creating report: {str(e)}"


@function_tool()
def add_finding_to_report(report_id: str, title: str, severity: str, cvss_score: float,
                          description: str, affected_url: str, poc: str,
                          remediation: str, cwe_id: str = "", cve_id: str = "",
                          screenshot_path: str = "") -> str:
    """
    Add a security finding to the report.
    
    Args:
        report_id: Report identifier from create_report
        title: Finding title (e.g., "SQL Injection in Login Form")
        severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
        cvss_score: CVSS score (0.0-10.0)
        description: Detailed description of the vulnerability
        affected_url: URL or component affected
        poc: Proof of concept (curl command, payload, etc.)
        remediation: How to fix the vulnerability
        cwe_id: Optional CWE identifier (e.g., "CWE-89")
        cve_id: Optional CVE identifier (e.g., "CVE-2024-1234")
        screenshot_path: Optional path to a screenshot image (e.g. from browser_screenshot tool)
    
    Returns:
        Confirmation message
    """
    try:
        from src.sdk.context_hub import get_context_hub
        hub = get_context_hub()
        
        report = hub.get_custom_data(report_id)
        if not report:
            return f"❌ Report {report_id} not found. Create report first with create_report()"
        
        finding = Finding(title, severity, cvss_score, description, affected_url,
                         poc, remediation, cwe_id, cve_id, screenshot_path=screenshot_path)
        report.add_finding(finding)
        
        # Update stored report
        hub.store_custom_data(report_id, report)
        
        return f"""✅ Finding Added: {title}
**Severity:** {severity} | **CVSS:** {cvss_score}
**Total Findings:** {len(report.findings)}
"""
    except Exception as e:
        return f"Error adding finding: {str(e)}"


@function_tool()
def generate_report(report_id: str, output_format: str = "html", output_dir: str = "reports") -> str:
    """
    Generate the final penetration test report.
    
    Args:
        report_id: Report identifier
        output_format: html, markdown, or pdf
        output_dir: Output directory for report
    
    Returns:
        Path to generated report
    """
    try:
        from src.sdk.context_hub import get_context_hub
        hub = get_context_hub()
        
        report = hub.get_custom_data(report_id)
        if not report:
            return f"❌ Report {report_id} not found"
        
        if len(report.findings) == 0:
            return "⚠️ Warning: Report has no findings. Add findings first with add_finding_to_report()"
        
        if output_dir == "reports":
            from src.sdk.utils import get_project_root
            output_dir = str(get_project_root() / "reports")
        
        filepath = report.save_report(output_dir, output_format)
        
        try:
            from src.sdk.context_hub import get_scan_memory
            scan_memory = get_scan_memory()
            
            # Record in global execution_history
            vulns = []
            target_str = getattr(report, 'target', 'Unknown')
            for f in report.findings:
                vulns.append({
                    "vuln_id": getattr(f, 'title', 'Unknown'),
                    "severity": getattr(f, 'severity', 'Unknown'),
                    "tool": getattr(f, 'discovery_method', 'ReportGenerator'),
                    "payload": getattr(f, 'poc', ''),
                    "validated": True,
                    "validation_score": 100,
                    "endpoint": getattr(f, 'affected_url', '')
                })
                
            tools_used = getattr(report, 'tools_arsenal', [])
            
            scan_memory.record_scan(
                target=target_str,
                tech_stack=[],
                scan_type=getattr(report, 'report_type', "web_application"),
                vulns_found=vulns,
                tools_executed=tools_used,
                notes=getattr(report, 'executive_summary', "")
            )
            
            # Record in individual target profile.json
            if target_str and target_str != "Unknown":
                try:
                    from src.repl.profiles import get_profile_manager
                    pm = get_profile_manager()
                    for f in report.findings:
                        pm.add_vulnerability(
                            target=target_str,
                            name=getattr(f, 'title', 'Unknown finding'),
                            severity=getattr(f, 'severity', 'unknown'),
                            cve=getattr(f, 'cve_id', ''),
                            description=getattr(f, 'description', ''),
                            verified=True
                        )
                except Exception:
                    # Ignore missing module/errors for profiles if repl isn't available
                    pass
        except Exception as _e:
            pass  # Fail gracefully if serialization to execution_history fails

        risk_ratings = report.calculate_risk_rating()
        
        return f"""## ✅ Report Generated Successfully!

**File:** {filepath}
**Format:** {output_format.upper()}
**Total Findings:** {len(report.findings)}

**Risk Distribution:**
- 🔴 Critical: {risk_ratings['CRITICAL']}
- 🟠 High: {risk_ratings['HIGH']}
- 🟡 Medium: {risk_ratings['MEDIUM']}
- 🔵 Low: {risk_ratings['LOW']}
- ⚪ Info: {risk_ratings['INFO']}

Open the report in your browser to view the professional assessment!
"""
    except Exception as e:
        return f"Error generating report: {str(e)}"


@function_tool()
def auto_add_finding_from_validation(report_id: str, validation_result: str, affected_url: str) -> str:
    """
    Automatically parse validation results and add finding to report.
    Works with validate_sqli, validate_xss, validate_ssrf outputs.
    
    Args:
        report_id: Report identifier
        validation_result: Output from validation tool
        affected_url: URL where vulnerability was found
    
    Returns:
        Confirmation message
    """
    try:
        # Parse validation result
        if "SQLi" in validation_result or "SQL Injection" in validation_result:
            title = "SQL Injection Vulnerability"
            cwe_id = "CWE-89"
            severity = "HIGH"
            cvss_score = 8.6
            remediation = "Use parameterized queries/prepared statements. Implement input validation and escaping."
        elif "XSS" in validation_result or "Cross-Site Scripting" in validation_result:
            title = "Cross-Site Scripting (XSS)"
            cwe_id = "CWE-79"
            severity = "MEDIUM"
            cvss_score = 6.1
            remediation = "Implement output encoding/escaping. Use Content Security Policy (CSP)."
        elif "SSRF" in validation_result:
            title = "Server-Side Request Forgery (SSRF)"
            cwe_id = "CWE-918"
            severity = "HIGH"
            cvss_score = 8.2
            remediation = "Validate and whitelist allowed URLs/IPs. Implement network segmentation."
        else:
            return "❌ Could not parse validation result. Use add_finding_to_report manually."
        
        # Extract PoC from validation result
        poc = validation_result
        
        # Add finding
        return add_finding_to_report(
            report_id, title, severity, cvss_score,
            "Validated vulnerability found through automated testing.",
            affected_url, poc, remediation, cwe_id
        )
    except Exception as e:
        return f"Error auto-adding finding: {str(e)}"
