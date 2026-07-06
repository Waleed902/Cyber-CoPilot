"""
Centralized Vulnerability Database (State Management)

This module provides a SQLite-backed registry for all vulnerabilities discovered
by the autonomous agents. It prevents findings from being lost if an agent's
context window clears, and allows the Orchestrator to generate comprehensive reports.
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime
from loguru import logger
from typing import List, Dict, Any
from urllib.parse import urlparse

from src.sdk.tool import function_tool

# Use the current active session directory if possible, otherwise fallback to a generic db
def _get_db_path() -> Path:
    try:
        from src.repl.target_manager import get_target_manager
        tm = get_target_manager()
        db_dir = tm.get_session_files_dir("database")
        if db_dir:
            return db_dir / "findings.db"
    except Exception:
        pass
    
    # Fallback to local directory
    fallback_dir = Path("data")
    fallback_dir.mkdir(exist_ok=True)
    return fallback_dir / "findings.db"

def _init_db():
    db_path = _get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            target_url TEXT NOT NULL,
            vuln_type TEXT NOT NULL,
            parameter TEXT,
            severity TEXT NOT NULL,
            payload TEXT,
            evidence TEXT,
            reproduced BOOLEAN DEFAULT 0,
            metadata TEXT,
            status TEXT DEFAULT 'OPEN'
        )
    ''')
    
    # Create unique index to prevent duplicate logging of the same vuln on the same parameter
    cursor.execute('''
        CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_unique 
        ON vulnerabilities(target_url, vuln_type, parameter)
    ''')
    
    # Auto-migrate: add status column if it doesn't exist (for older databases)
    try:
        cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN status TEXT DEFAULT 'OPEN'")
    except sqlite3.OperationalError:
        pass # Column already exists
    
    conn.commit()
    conn.close()
    return db_path


def _mirror_to_target_profile(
    target_url: str,
    vuln_type: str,
    severity: str,
    parameter: str = "",
    payload: str = "",
    evidence: str = "",
    metadata: str = "{}",
    status: str = "OPEN",
) -> None:
    """Mirror DB findings into target profile context used by future agents."""
    try:
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        host = parsed.hostname or target_url

        try:
            from src.repl.target_manager import get_target_manager
            active_target = getattr(get_target_manager(), "current_target", "") or ""
            if active_target:
                host = active_target
        except Exception:
            pass

        path = parsed.path or "/"
        name = f"{vuln_type} in {path}"
        if parameter:
            name += f" [{parameter}]"

        description_parts = [
            f"URL: {target_url}",
            f"Parameter: {parameter or 'N/A'}",
            f"Status: {status.upper()}",
        ]
        if payload:
            description_parts.append(f"Payload: {payload}")
        if evidence:
            description_parts.append(f"Evidence: {evidence}")
        if metadata and metadata != "{}":
            description_parts.append(f"Metadata: {metadata}")

        from src.repl.profiles import get_profile_manager
        get_profile_manager().add_vulnerability(
            host,
            name=name,
            severity=severity.lower(),
            cve="",
            description="\n".join(description_parts),
            verified=status.upper() in {"VERIFIED", "CONFIRMED", "VALIDATED"},
        )
    except Exception as e:
        logger.debug(f"Could not mirror vulnerability to target profile: {e}")

@function_tool()
def register_vulnerability(
    target_url: str,
    vuln_type: str,
    severity: str,
    parameter: str = "",
    payload: str = "",
    evidence: str = "",
    metadata: str = "{}",
    status: str = "OPEN"
) -> str:
    """
    Register a confirmed vulnerability into the centralized database.
    Scanners MUST call this automatically when a vulnerability is confirmed.
    
    Args:
        target_url: The URL where the vulnerability exists.
        vuln_type: Type of vulnerability (e.g. 'SQL Injection', 'Cross-Site Scripting').
        severity: Severity level ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO').
        parameter: The vulnerable parameter (if applicable).
        payload: The exact payload used to trigger the vulnerability.
        evidence: Text or description of why this is considered vulnerable.
        metadata: JSON string with any extra context.
        status: The current status ('OPEN', 'FALSE_POSITIVE', 'FIXED', 'VERIFIED').
        
    Returns:
        Status message of the registration.
    """
    db_path = _init_db()
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        timestamp = datetime.now().isoformat()
        
        # Check if already exists (Update if it does, insert if new)
        try:
            cursor.execute('''
                INSERT INTO vulnerabilities 
                (timestamp, target_url, vuln_type, parameter, severity, payload, evidence, metadata, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, target_url, vuln_type, parameter, severity.upper(), payload, evidence, metadata, status.upper()))
            conn.commit()
            action = "Registered new"
        except sqlite3.IntegrityError:
            # It already exists (Unique constraint failed), update it instead
            cursor.execute('''
                UPDATE vulnerabilities 
                SET timestamp = ?, severity = ?, payload = ?, evidence = ?, metadata = ?, status = ?
                WHERE target_url = ? AND vuln_type = ? AND parameter = ?
            ''', (timestamp, severity.upper(), payload, evidence, metadata, status.upper(), target_url, vuln_type, parameter))
            conn.commit()
            action = "Updated existing"
            
        conn.close()
        _mirror_to_target_profile(
            target_url=target_url,
            vuln_type=vuln_type,
            severity=severity,
            parameter=parameter,
            payload=payload,
            evidence=evidence,
            metadata=metadata,
            status=status,
        )
        logger.success(f"{action} vulnerability: {severity} {vuln_type} on {target_url} ({parameter}) [Status: {status}]")
        return f"✅ {action} vulnerability: [{severity}] {vuln_type} on {target_url} (Status: {status})"
        
    except Exception as e:
        logger.error(f"Failed to register vulnerability: {e}")
        return f"❌ Failed to register vulnerability: {str(e)}"

@function_tool()
def update_vulnerability_status(target_url: str, vuln_type: str, status: str, parameter: str = "") -> str:
    """
    Update the status of an existing vulnerability.
    Use this to mark findings as 'FALSE_POSITIVE', 'RESOLVED', 'FIXED', or 'VERIFIED'.
    
    Args:
        target_url: The exact URL of the previously registered vulnerability.
        vuln_type: The type of vulnerability.
        status: The new status to apply (e.g., 'FALSE_POSITIVE', 'RESOLVED').
        parameter: The vulnerable parameter (if applicable).
        
    Returns:
        Status message of the update.
    """
    db_path = _init_db()
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE vulnerabilities 
            SET status = ?
            WHERE target_url = ? AND vuln_type = ? AND parameter = ?
        ''', (status.upper(), target_url, vuln_type, parameter))
        
        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        if updated:
            logger.success(f"Updated status of {vuln_type} on {target_url} ({parameter}) to {status.upper()}")
            return f"✅ Status updated to {status.upper()} for {vuln_type} on {target_url}"
        else:
            return f"⚠️ No matching vulnerability found to update. (Target: {target_url}, Type: {vuln_type}, Parameter: {parameter})"
            
    except Exception as e:
        logger.error(f"Failed to update vulnerability status: {e}")
        return f"❌ Failed to update vulnerability status: {str(e)}"

@function_tool()
def get_all_vulnerabilities() -> str:
    """
    Retrieve all confirmed vulnerabilities from the centralized database.
    The Orchestrator agent should use this before generating the final report.
    
    Returns:
        A Markdown formatted table of all vulnerabilities.
    """
    db_path = _init_db()
    
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM vulnerabilities ORDER BY severity ASC")  # We'll sort properly in python
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            return "No vulnerabilities registered in the database yet."
            
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_rows = sorted(rows, key=lambda x: severity_order.get(x["severity"], 99))
        
        out = ["## 🛡️ Centralized Vulnerability Database\n"]
        out.append(f"Total Confirmed Findings: **{len(sorted_rows)}**\n")
        
        out.append("| Severity | Type | Target | Parameter | Payload | Status | Evidence |")
        out.append("|----------|------|--------|-----------|---------|--------|----------|")
        
        for r in sorted_rows:
            sev = r["severity"]
            vtype = r["vuln_type"]
            target = r["target_url"].split("?")[0]  # truncate query string for display
            param = r["parameter"] or "N/A"
            payload = (r["payload"] or "N/A").replace("\n", " ").replace("|", "\\|")
            if len(payload) > 48:
                payload = payload[:45] + "..."
            status = r["status"] if "status" in r.keys() else "OPEN"
            evid = (r["evidence"][:40] + "...") if len(r["evidence"]) > 40 else r["evidence"]
            evid = evid.replace("\n", " ").replace("|", " ")
            
            out.append(f"| {sev} | {vtype} | {target} | {param} | {payload} | {status} | {evid} |")
            
        out.append("\nTo view full payload details, query the database directly.")
        return "\n".join(out)
        
    except Exception as e:
        return f"Failed to retrieve vulnerabilities: {str(e)}"
