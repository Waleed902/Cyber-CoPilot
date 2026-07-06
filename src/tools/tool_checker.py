"""
Comprehensive tool checker - Checks ALL tools across all categories in the framework.
"""

import shutil
import os
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def check_tool_installed(tool_name: str) -> bool:
    """Check if a tool is installed and available in PATH or Go bin."""
    import platform
    import subprocess
    
    # Check standard PATH
    if shutil.which(tool_name) is not None:
        return True
    
    # Linux-specific checks
    if platform.system().lower() == "linux":
        # Check for impacket tools with impacket- prefix
        if tool_name.endswith(".py"):
            base_name = tool_name.replace(".py", "")
            impacket_name = f"impacket-{base_name}"
            if shutil.which(impacket_name) is not None:
                return True
            # Also check if importable as Python module
            try:
                subprocess.run(
                    ["python3", "-c", f"import impacket.examples.{base_name}"],
                    capture_output=True, timeout=2, check=True
                )
                return True
            except:
                pass
        
        # Check for enum4linux-ng (not just enum4linux)
        if tool_name == "enum4linux-ng":
            return shutil.which("enum4linux-ng") is not None
        
        # Check for netcat variations (nc, ncat, netcat)
        if tool_name in ["nc", "netcat", "ncat"]:
            return any(shutil.which(cmd) for cmd in ["nc", "ncat", "netcat"])
        
        # Check for crackmapexec variations (cme, crackmapexec, netexec)
        if tool_name == "crackmapexec":
            return any(shutil.which(cmd) for cmd in ["crackmapexec", "cme", "netexec"])
        
        # Check for john variations (john, john-jumbo)
        if tool_name == "john":
            return any(shutil.which(cmd) for cmd in ["john", "john-the-ripper"])
        
        # Check for volatility variations (volatility, vol.py, volatility3, vol)
        if tool_name == "volatility":
            return any(shutil.which(cmd) for cmd in ["volatility", "volatility3", "vol", "vol.py", "vol3"])
        
        # Check for metasploit (msfconsole command)
        if tool_name == "metasploit":
            return shutil.which("msfconsole") is not None
        
        # Check for mitm6 (Python tool)
        if tool_name == "mitm6":
            if shutil.which("mitm6") is not None:
                return True
            # Check as Python module
            try:
                subprocess.run(
                    ["python3", "-c", "import mitm6"],
                    capture_output=True, timeout=2, check=True
                )
                return True
            except:
                pass
        
        # Check for ligolo (ligolo-ng, ligolo-proxy)
        if tool_name == "ligolo":
            return any(shutil.which(cmd) for cmd in ["ligolo", "ligolo-ng", "ligolo-proxy", "agent"])
        
        # Check for sliver
        if tool_name == "sliver":
            return any(shutil.which(cmd) for cmd in ["sliver", "sliver-server", "sliver-client"])
        
        # Check for empire variations
        if tool_name in ["empire", "powershell-empire"]:
            return any(shutil.which(cmd) for cmd in ["empire", "powershell-empire", "ps-empire"])
        
        # Skip Windows-only tools on Linux (return True to avoid false negatives)
        windows_only = ["Rubeus.exe", "mimikatz.exe", "covenant", "cobalt-strike"]
        if tool_name in windows_only:
            return True  # Mark as "installed" to skip on Linux
        
        # Check for bloodhound-python variations
        if tool_name == "bloodhound-python":
            return any(shutil.which(cmd) for cmd in ["bloodhound-python", "bloodhound.py", "bloodhound"])

        # pwntools installs a 'pwn' binary, not 'pwntools'
        if tool_name == "pwntools":
            if shutil.which("pwn") is not None:
                return True
            try:
                subprocess.run(["python3", "-c", "import pwn"], capture_output=True, timeout=3, check=True)
                return True
            except Exception:
                return False

        # ROPgadget binary is 'ROPgadget' (capital)
        if tool_name == "ropgadget":
            return any(shutil.which(cmd) for cmd in ["ROPgadget", "ropgadget"])

        # roadtools is installed as 'roadrecon', 'roadtx', etc.
        if tool_name == "roadtools":
            return any(shutil.which(cmd) for cmd in ["roadrecon", "roadtx", "roadtools"])

        # msolspray - pip package, check as module if binary missing
        if tool_name == "msolspray":
            if shutil.which("msolspray") is not None:
                return True
            import sys
            try:
                subprocess.run([sys.executable, "-c", "import msolspray"], capture_output=True, timeout=3, check=True)
                return True
            except Exception:
                pass
            # Also try python3 as fallback
            try:
                subprocess.run(["python3", "-c", "import msolspray"], capture_output=True, timeout=3, check=True)
                return True
            except Exception:
                return False

        # ysoserial - Java JAR file, not a PATH binary
        if tool_name == "ysoserial":
            if shutil.which("ysoserial") is not None:
                return True
            # Look for the JAR in common tool locations
            jar_search_dirs = [
                Path.home() / "tools",
                Path.home() / ".local" / "share",
                Path("/opt"),
                Path("/usr/share"),
                Path("/usr/local"),
            ]
            for search_dir in jar_search_dirs:
                if search_dir.exists():
                    jars = list(search_dir.rglob("ysoserial*.jar"))
                    if jars:
                        return True
            return False

        # volatility - check v2 and v3 variants (redundant guard; first check at top already handles this)
        if tool_name == "volatility":
            return any(shutil.which(cmd) for cmd in ["volatility", "volatility3", "vol", "vol.py", "vol3"])

        # whisker - .NET tool; only meaningful on Windows. Mark as installed on Linux.
        if tool_name == "whisker":
            return True  # Skip on Linux (Windows-only .NET binary)

        # aadinternals - PowerShell module, Windows-only
        if tool_name == "aadinternals":
            return True  # Windows PowerShell only; skip on Linux

        # sharpcollection - collection of .NET binaries, Windows-only
        if tool_name == "sharpcollection":
            return True  # Windows-only

        # pupy - check for pupy command or cloned directory
        if tool_name == "pupy":
            if shutil.which("pupy") is not None:
                return True
            return Path.home().joinpath("tools", "pupy").exists()

        # havoc - check binary or cloned directory
        if tool_name == "havoc":
            if shutil.which("havoc") is not None:
                return True
            # Check workspace-local copy
            local_havoc = Path(__file__).parent.parent.parent / "cloudflair" / "Havoc"
            return local_havoc.exists()

    # Check Go bin directory (common location for Go tools)
    go_bin_paths = [
        Path.home() / "go" / "bin" / tool_name,
        Path.home() / "go" / "bin" / f"{tool_name}.exe",  # Windows
        Path("/usr/local/go/bin") / tool_name,
    ]
    
    for go_bin in go_bin_paths:
        if go_bin.exists() and os.access(go_bin, os.X_OK):
            return True
    
    return False


def check_all_tools() -> str:
    """
    Check installation status of ALL tools used in the framework.
    Covers reconnaissance, web, exploitation, AD, forensics, and more.
    
    Returns:
        Rich formatted table showing all tool categories and their status
    """
    
    # Define all tool categories
    tool_categories = {
        "🔍 Reconnaissance": [
            "subfinder", "httpx", "nuclei", "nmap", "masscan", "rustscan",
            "whois", "dig", "dnsrecon", "dnsenum", "theharvester",
            "assetfinder", "gospider", "gau", "waybackurls", "katana",
            "dnsx", "naabu", "chaos", "subjack", "webanalyze", "whatweb",
            "amass", "alterx", "sublist3r", "cloudflair", "gowitness", "aquatone"
        ],
        "🌐 Web Security": [
            "gobuster", "dirsearch", "wfuzz", "ffuf", "nikto",
            "sqlmap", "commix", "wpscan", "curl", "wget",
            "burpsuite", "zaproxy", "wapiti", "dirb", "feroxbuster",
            "arjun", "dalfox", "kiterunner", "jwt_tool", "gopherus",
            "corsy", "graphql-cop", "inql"
        ],
        "💥 Exploitation": [
            "searchsploit", "msfconsole", "msfvenom", "exploitdb",
            "ysoserial", "phpggc", "pwncat", "socat", "nc", "ncat",
            "pwntools", "ropgadget", "angr", "radare2", "r2", "gdb", "tplmap"
        ],
        "🏢 Active Directory": [
            "enum4linux-ng", "ldapsearch", "kerbrute", "bloodhound-python",
            "Rubeus.exe", "ntlmrelayx.py", "GetUserSPNs.py", "GetNPUsers.py",
            "secretsdump.py", "mimikatz.exe", "smbclient", "rpcclient",
            "crackmapexec", "netexec", "mitm6", "responder", "psexec.py", "smbexec.py",
            "certipy", "lsassy", "evil-winrm", "coercer", "sprayhound",
            "donpapi", "whisker", "plumhound", "sharphound", "roadtools", "petitpotam", "certify"
        ],
        "☁️ Cloud Security": [
            "pacu", "scoutsuite", "prowler", "cloud_enum", 
            "aws", "az", "gcloud"
        ],
        "🚀 Privilege Escalation": [
            "linpeas", "winpeas", "pspy", "traitor", "seatbelt"
        ],
        "🔐 Credential Attacks": [
            "hashcat", "john", "hydra", "medusa", "patator",
            "cewl", "crunch", "wordlists", "hashid", "msolspray"
        ],
        "🔬 Forensics & Analysis": [
            "volatility", "autopsy", "foremost", "binwalk", "exiftool",
            "strings", "file", "xxd", "hexdump", "wireshark", "tcpdump",
            "jadx", "upx", "wasm-decompile", "wasm2wat", "wasm-objdump", 
            "javap", "unzip", "zipgrep"
        ],
        "🛡️ Network Tools": [
            "wireshark", "tcpdump", "tshark", "arpspoof", "ettercap",
            "bettercap", "mitmproxy", "proxychains", "chisel", "ligolo",
            "tor", "tornet", "anonsurf", "sshuttle"
        ],
        "📦 Development & Core": [
            "python", "python3", "pip", "pip3", "go", "git",
            "gcc", "make", "docker", "node", "npm", "jq",
            "pip-audit", "trufflehog", "gitleaks"
        ],
        "🎯 C2 & Post-Exploitation": [
            "metasploit", "cobalt-strike", "sliver", "empire",
            "covenant", "pupy", "powershell-empire", "havoc", "villain",
            "sharpcollection", "powersploit", "aadinternals"
        ]
    }
    
    # Note: Impacket scripts are already in AD category above
    # They're installed via: pip install impacket
    
    # Create main table
    main_table = Table(title="🔧 Framework Tool Installation Status", show_header=True, header_style="bold magenta")
    main_table.add_column("Category", style="cyan", width=25)
    main_table.add_column("Installed", style="green", justify="center", width=10)
    main_table.add_column("Missing", style="red", justify="center", width=10)
    main_table.add_column("Total", style="yellow", justify="center", width=10)
    main_table.add_column("% Complete", style="blue", justify="center", width=12)
    
    overall_stats = {
        "total": 0,
        "installed": 0,
        "missing": 0
    }
    
    category_details = {}
    
    for category, tools in tool_categories.items():
        installed = []
        missing = []
        
        for tool in tools:
            if check_tool_installed(tool):
                installed.append(tool)
                overall_stats["installed"] += 1
            else:
                missing.append(tool)
                overall_stats["missing"] += 1
            overall_stats["total"] += 1
        
        category_details[category] = {
            "installed": installed,
            "missing": missing,
            "total": len(tools)
        }
        
        percentage = (len(installed) / len(tools) * 100) if tools else 0
        
        main_table.add_row(
            category,
            str(len(installed)),
            str(len(missing)),
            str(len(tools)),
            f"{percentage:.1f}%"
        )
    
    # Create output
    console.print(main_table)
    
    # Overall statistics
    overall_percentage = (overall_stats["installed"] / overall_stats["total"] * 100) if overall_stats["total"] > 0 else 0
    
    stats_text = f"""
[bold]Overall Statistics:[/bold]
  ✓ Installed: [green]{overall_stats['installed']}[/green]
  ✗ Missing: [red]{overall_stats['missing']}[/red]
  📊 Total: [yellow]{overall_stats['total']}[/yellow]
  📈 Completion: [blue]{overall_percentage:.1f}%[/blue]
"""
    
    console.print(Panel(stats_text, title="Summary", border_style="green"))
    
    # Show missing critical tools
    critical_tools = ["nmap", "subfinder", "httpx", "nuclei", "gobuster", "sqlmap", 
                     "searchsploit", "hashcat", "ntlmrelayx.py", "metasploit", "arjun", "jq"]
    
    missing_critical = []
    for tool in critical_tools:
        if not check_tool_installed(tool):
            missing_critical.append(tool)
    
    if missing_critical:
        console.print("\n[bold red]⚠️  Missing Critical Tools:[/bold red]")
        for tool in missing_critical:
            console.print(f"  • {tool}")
        
        import platform
        if platform.system().lower() == "linux":
            console.print("\n[bold yellow]Quick Fix (Linux):[/bold yellow]")
            console.print("  # Install Impacket (fixes ntlmrelayx.py, GetUserSPNs.py, etc.)")
            console.print("  sudo apt install impacket-scripts -y")
            console.print("  # OR: pip install impacket")
            console.print("\n  # Install Go tools")
            console.print("  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            console.print("  go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
            console.print("  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            console.print("  go install github.com/projectdiscovery/alterx/cmd/alterx@latest")
            console.print("  go install github.com/owasp-amass/amass/v4/...@master")
            console.print("\n  # Install common recon tools")
            console.print("  sudo apt install nmap gobuster sqlmap hashcat jq -y")
            console.print("\n  # Install Python tools for API security & parameter discovery")
            console.print("  pip install arjun pyjwt")
            console.print("  # Note: xsstrike requires Python <3.11, jwt_tool is standalone from GitHub")
            console.print("\n  # Install AD & Post-Exploitation tools (Phase 1-3)")
            console.print("  pip install certipy-ad lsassy coercer sprayhound donpapi plumhound roadrecon")
            console.print("  gem install evil-winrm")
            console.print("  pip install pwntools ropgadget angr villain msolspray")
            console.print("  sudo apt install radare2 gdb -y")
            console.print("\n  # Install Metasploit Framework")
            console.print("  curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall")
            console.print("\n  # Install C2 Frameworks")
            console.print("  pip install villain  # Python C2")
            console.print("  # Havoc C2: https://github.com/HavocFramework/Havoc")
            console.print("  # Sliver C2: https://github.com/BishopFox/sliver/releases")
            console.print("\n  # Install Chisel for pivoting")
            console.print("  wget https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz")
            console.print("  gunzip chisel_linux_amd64.gz && chmod +x chisel_linux_amd64 && sudo mv chisel_linux_amd64 /usr/local/bin/chisel")
        else:
            console.print("\n[bold yellow]Quick Fix:[/bold yellow]")
            console.print("  # Install Impacket (fixes ntlmrelayx.py, GetUserSPNs.py, etc.)")
            console.print("  pip install impacket")
            console.print("\n  # Fix naabu (needs libpcap-dev)")
            console.print("  sudo apt install libpcap-dev")
            console.print("  go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
        console.print("\n[dim]Then run 'tools check' to verify[/dim]")
    
    # Detailed breakdown (optional)
    console.print("\n[bold]Detailed Breakdown:[/bold]")
    for category, details in category_details.items():
        if details["missing"]:
            console.print(f"\n{category} - Missing ({len(details['missing'])}):")
            for tool in details["missing"][:5]:  # Show first 5
                console.print(f"  • {tool}")
            if len(details["missing"]) > 5:
                console.print(f"  ... and {len(details['missing']) - 5} more")
    
    return "Tool check complete. See output above."


def check_category_tools(category: str) -> str:
    """
    Check tools for a specific category only.
    
    Args:
        category: Category name (recon, web, exploit, ad, forensics, network, core)
    
    Returns:
        Tool status for that category
    """
    category_map = {
        "recon": ["subfinder", "httpx", "nuclei", "nmap", "masscan", "whois", "dig", "amass", "alterx", "arjun", "gowitness", "aquatone"],
        "web": ["gobuster", "dirsearch", "sqlmap", "nikto", "wfuzz", "ffuf", "curl", "arjun", "kiterunner", "jwt_tool", "gopherus", "corsy", "graphql-cop", "inql"],
        "exploit": ["searchsploit", "msfconsole", "msfvenom", "ysoserial", "nc", "pwntools", "angr", "radare2", "tplmap"],
        "ad": ["enum4linux-ng", "bloodhound-python", "kerbrute", "ntlmrelayx.py", "crackmapexec", "netexec", "certipy", "lsassy", "evil-winrm", "coercer", "sprayhound", "petitpotam", "certify"],
        "forensics": ["volatility", "autopsy", "binwalk", "exiftool", "foremost", "jadx", "upx", "wasm-decompile", "wasm2wat", "wasm-objdump", "javap", "unzip", "zipgrep"],
        "network": ["wireshark", "tcpdump", "ettercap", "bettercap", "mitmproxy", "chisel", "sshuttle"],
        "creds": ["hashcat", "john", "hydra", "medusa", "cewl"],
        "cloud": ["pacu", "scoutsuite", "prowler", "cloud_enum", "aws", "az", "gcloud"],
        "privesc": ["linpeas", "winpeas", "pspy", "traitor", "seatbelt"],
        "c2": ["sliver", "empire", "havoc", "villain"],
        "core": ["python", "python3", "pip", "go", "git", "gcc", "jq", "pip-audit", "npm", "trufflehog", "gitleaks"]
    }
    
    tools = category_map.get(category.lower(), [])
    if not tools:
        return f"Unknown category: {category}. Use: recon, web, exploit, ad, forensics, network, creds, core"
    
    table = Table(title=f"Tools for {category.upper()}", show_header=True)
    table.add_column("Tool", style="cyan", width=25)
    table.add_column("Status", style="white", width=15)
    
    for tool in tools:
        status = "[green]✓ Installed[/green]" if check_tool_installed(tool) else "[red]✗ Missing[/red]"
        table.add_row(tool, status)
    
    console.print(table)
    return ""


def get_installation_commands() -> str:
    """
    Provide installation commands for all missing tools by platform.
    
    Returns:
        Platform-specific installation commands
    """
    import platform
    
    os_type = platform.system().lower()
    
    commands = {
        "linux": {
            "Reconnaissance": "sudo apt install nmap masscan dnsutils whois dnsrecon dnsenum theharvester rustscan -y && pip install arjun sublist3r cloudflair",
            "Web Security": "sudo apt install gobuster nikto sqlmap curl wget dirb feroxbuster jq -y && pip install dirsearch wfuzz arjun pyjwt dalfox",
            "Exploitation": "sudo apt install exploitdb metasploit-framework netcat-openbsd socat radare2 gdb -y && pip install pwntools ropgadget angr",
            "Active Directory": "sudo apt install impacket-scripts smbclient rpcclient ldap-utils -y && pip install bloodhound mitm6 certipy-ad lsassy coercer sprayhound donpapi plumhound roadrecon && gem install evil-winrm && go install github.com/ropnop/kerbrute@latest",
            "Credential Tools": "sudo apt install hashcat john hydra medusa cewl -y && pip install msolspray",
            "Forensics": "sudo apt install volatility3 foremost binwalk exiftool -y",
            "Network": "sudo apt install wireshark tcpdump ettercap-text-only -y && pip install mitmproxy && wget -O chisel https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz && gunzip chisel_linux_amd64.gz && chmod +x chisel && sudo mv chisel /usr/local/bin/",
            "Go Tools": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && go install github.com/projectdiscovery/httpx/cmd/httpx@latest && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && go install github.com/projectdiscovery/alterx/cmd/alterx@latest && go install github.com/projectdiscovery/katana/cmd/katana@latest && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && go install github.com/owasp-amass/amass/v4/...@master",
            "C2 Frameworks": "sudo apt install powershell-empire -y && pip install villain && echo 'Download Sliver: https://github.com/BishopFox/sliver/releases' && echo 'Download Havoc: https://github.com/HavocFramework/Havoc'"
        },
        "darwin": {
            "Reconnaissance": "brew install nmap masscan whois bind dnsrecon dnsenum theharvester jq && pip install arjun sublist3r cloudflair",
            "Web Security": "brew install gobuster nikto sqlmap curl wget jq && pip install dirsearch wfuzz arjun pyjwt dalfox",
            "Exploitation": "brew install metasploit netcat socat && searchsploit --update",
            "Active Directory": "pip install impacket bloodhound && brew install crackmapexec",
            "Credential Tools": "brew install hashcat john-jumbo hydra",
            "Forensics": "brew install volatility autopsy foremost binwalk exiftool",
            "Network": "brew install wireshark ettercap && pip install mitmproxy",
            "Go Tools": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && go install github.com/projectdiscovery/httpx/cmd/httpx@latest && go install github.com/projectdiscovery/alterx/cmd/alterx@latest && go install github.com/owasp-amass/amass/v4/...@master"
        },
        "windows": {
            "Reconnaissance": "choco install nmap whois jq && go install subfinder httpx nuclei alterx amass && pip install arjun sublist3r",
            "Web Security": "choco install curl wget jq && pip install dirsearch sqlmap gobuster arjun pyjwt dalfox",
            "Exploitation": "Download Metasploit from https://metasploit.com && choco install netcat",
            "Active Directory": "pip install impacket && download Rubeus/Mimikatz from GitHub",
            "Credential Tools": "choco install hashcat && download John from https://www.openwall.com/john/",
            "Network": "choco install wireshark && pip install mitmproxy",
            "Go Tools": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        }
    }
    
    os_commands = commands.get(os_type, commands["linux"])
    
    output = [f"\n[bold]Installation Commands for {os_type.upper()}:[/bold]\n"]
    
    for category, cmd in os_commands.items():
        output.append(f"[cyan]{category}:[/cyan]")
        output.append(f"  {cmd}\n")
    
    console.print("\n".join(output))
    return ""


# ── Session pre-flight check ───────────────────────────────────────────────────

# Tools that must be present for core workflows, grouped by severity.
_CRITICAL_TOOLS = {
    "nmap": "port scanning",
    "sqlmap": "SQL injection exploitation",
    "curl": "HTTP probing",
}
_RECOMMENDED_TOOLS = {
    "subfinder": "subdomain enumeration",
    "httpx": "HTTP discovery",
    "nuclei": "vulnerability scanning",
    "gobuster": "directory brute-force",
    "ffuf": "fuzzing",
    "nikto": "web server scan",
    "hydra": "credential bruteforce",
    "ghauri": "WAF-bypass SQLi",
    "interactsh-client": "OOB/OAST callbacks",
}
_PYTHON_PKGS = {
    "pyee": "playwright event emitter (browser automation)",
    "playwright": "headless browser testing",
    "chromadb": "vector memory / RAG",
}


def run_session_preflight(console_obj=None, silent: bool = False) -> dict:
    """Check essential tools at session start and print a compact status panel.

    Args:
        console_obj: Rich Console instance (uses module-level console if None).
        silent: If True, suppress output and just return the result dict.

    Returns:
        Dict with keys 'missing_critical', 'missing_recommended', 'missing_python'.
    """
    import importlib
    _con = console_obj or console

    missing_critical: list[str] = []
    missing_recommended: list[str] = []
    missing_python: list[str] = []

    for tool, desc in _CRITICAL_TOOLS.items():
        if not check_tool_installed(tool):
            missing_critical.append(f"{tool}  [dim]({desc})[/dim]")

    for tool, desc in _RECOMMENDED_TOOLS.items():
        if not check_tool_installed(tool):
            missing_recommended.append(f"{tool}  [dim]({desc})[/dim]")

    for pkg, desc in _PYTHON_PKGS.items():
        try:
            importlib.import_module(pkg)
        except ImportError:
            missing_python.append(f"{pkg}  [dim]({desc})[/dim]")

    if silent:
        return {
            "missing_critical": missing_critical,
            "missing_recommended": missing_recommended,
            "missing_python": missing_python,
        }

    all_ok = not missing_critical and not missing_recommended and not missing_python

    if all_ok:
        _con.print("[dim green]✔ Tool preflight passed — all key tools present.[/dim green]\n")
        return {"missing_critical": [], "missing_recommended": [], "missing_python": []}

    lines: list[str] = []

    if missing_critical:
        lines.append("[bold red]CRITICAL — engagement will be impaired:[/bold red]")
        for m in missing_critical:
            lines.append(f"  [red]✘[/red] {m}")
        lines.append("")

    if missing_recommended:
        lines.append("[yellow]Recommended — some workflows may fall back:[/yellow]")
        for m in missing_recommended:
            lines.append(f"  [yellow]○[/yellow] {m}")
        lines.append("")

    if missing_python:
        lines.append("[cyan]Python packages missing:[/cyan]")
        for m in missing_python:
            lines.append(f"  [cyan]○[/cyan] {m}")
        lines.append(
            "  [dim]Fix: pip install "
            + " ".join(p.split()[0] for p in missing_python)
            + "[/dim]"
        )
        lines.append("")

    lines.append("[dim]Run 'tools install all' for full install commands.[/dim]")

    _con.print(
        Panel(
            "\n".join(lines),
            title="[bold yellow]⚡ Pre-flight Check[/bold yellow]",
            border_style="yellow",
            expand=False,
        )
    )

    return {
        "missing_critical": missing_critical,
        "missing_recommended": missing_recommended,
        "missing_python": missing_python,
    }
