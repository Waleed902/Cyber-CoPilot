#!/usr/bin/env python3
"""
Cyber-CoPilot - AI-Powered Cybersecurity Operations
Professional Terminal Interface Base Entrypoint

"""

import os
import sys
import asyncio
import subprocess
import threading
import time

# Ensure the src directory is in the python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv

# Configure logging at a basic level before the REPL starts
from loguru import logger
import sys

def setup_base_logging():
    logger.remove()
    logger.add(sys.stderr, level="WARNING")
    logger.add("logs/cyber_copilot.log", rotation="10 MB", level="DEBUG")

def keep_sudo_alive():
    """Background thread to keep sudo credentials cached without prompting."""
    while True:
        try:
            # Refresh sudo timestamp silently
            subprocess.run(["sudo", "-n", "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        time.sleep(60)

def init_sudo():
    """Prompt for sudo password once at startup if not running as root."""
    if os.geteuid() != 0:
        print("\033[94m[*] Cyber-CoPilot requires sudo privileges for certain tools (e.g. nmap, tcpdump).\033[0m")
        print("\033[94m[*] Please enter your password to cache sudo credentials:\033[0m")
        try:
            subprocess.run(["sudo", "-v"], check=True)
            # Erase: sudo's password prompt line + our 2 info lines (3 lines total)
            sys.stdout.write("\033[A\033[2K" * 3 + "\r")
            sys.stdout.flush()
            # Start background thread to keep it alive
            t = threading.Thread(target=keep_sudo_alive, daemon=True)
            t.start()
        except subprocess.CalledProcessError:
            # Erase only our 2 info lines; leave sudo's error message visible
            sys.stdout.write("\033[A\033[2K" * 2 + "\r")
            sys.stdout.flush()
            print("\033[93m[!] Sudo authentication failed or cancelled. Some tools may fail or hang.\033[0m")

def main():
    """Application entrypoint."""
    load_dotenv()
    setup_base_logging()
    
    # Prompt for sudo before starting the REPL
    init_sudo()
    
    # Import and start the large interactive terminal loop
    try:
        from src.repl.loop import main as start_repl
        asyncio.run(start_repl())
    except KeyboardInterrupt:
        print("\n\033[93m[!] Shutdown requested. Exiting...\033[0m")
        sys.exit(0)

if __name__ == "__main__":
    main()
