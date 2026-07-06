"""
Code Analysis Tools - Static and Dynamic Analysis for Security

Provides static analysis, secret detection, and dependency scanning.
"""

import subprocess
import re
import json
import shutil
from typing import List, Optional
from pathlib import Path
from src.sdk.tool import function_tool


def _rg(path: str, pattern: str, timeout: int = 30) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            ["rg", "-n", "--no-heading", "--color=never", "-i",
             "--max-count=500", pattern, path],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return -2, "", "rg not found"
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"


# Vulnerability patterns by category
VULN_PATTERNS = {
    # ── Injection ────────────────────────────────────────────────────────────
    "sql_injection": [
        (r'execute\s*\(\s*["\'].*%s', "String formatting in SQL query"),
        (r'cursor\.execute\s*\([^,]+\+', "String concat in cursor.execute"),
        (r'mysql_query\s*\(\s*["\'].*\$', "Variable interpolation in mysql_query"),
        (r'\.raw\s*\(.*\+', "Django .raw() with concatenation"),
        (r'f["\'].*SELECT.*\{', "f-string SQL query"),
        (r'%\s*\(.*\)\s*["\'].*(?:WHERE|INSERT|UPDATE)', "%-format SQL query"),
        (r'text\s*\(\s*["\'].*\+', "SQLAlchemy text() with concat"),
    ],
    "command_injection": [
        (r'os\.system\s*\(', "os.system — direct command execution"),
        (r'subprocess\.[a-z]+\(.*shell\s*=\s*True', "subprocess with shell=True"),
        (r'eval\s*\(', "eval — arbitrary code execution"),
        (r'exec\s*\(', "exec — arbitrary code execution"),
        (r'__import__\s*\(', "Dynamic __import__"),
        (r'os\.popen\s*\(', "os.popen — command execution"),
        (r'commands\.getoutput\s*\(', "commands.getoutput"),
        (r'pty\.spawn\s*\(', "pty.spawn — shell spawn"),
        (r'child_process\.exec\s*\(', "Node child_process.exec"),
        (r'child_process\.execSync\s*\(', "Node execSync"),
        (r'passthru\s*\(|shell_exec\s*\(|system\s*\(', "PHP command functions"),
        (r'proc_open\s*\(', "PHP proc_open"),
    ],
    "ssti": [
        (r'render_template_string\s*\(', "Flask render_template_string — classic SSTI"),
        (r'jinja2\.Template\s*\([^)]*\+', "Jinja2 Template with user concat"),
        (r'Template\s*\(\s*.*request', "Template from request input"),
        (r'Handlebars\.compile\s*\(', "Handlebars compile — client SSTI"),
        (r'\.render\s*\(\s*.*\{.*request', "Template render with request data"),
        (r'nunjucks\.renderString\s*\(', "Nunjucks renderString — SSTI"),
        (r'pebble\.getTemplate\s*\(', "Pebble SSTI (Java)"),
        (r'freemarker\.template\.Template', "FreeMarker SSTI (Java)"),
        (r'velocity\.evaluate\s*\(', "Velocity SSTI (Java)"),
    ],
    "xss": [
        (r'\.innerHTML\s*=', "innerHTML — DOM XSS sink"),
        (r'document\.write\s*\(', "document.write — DOM XSS sink"),
        (r'echo\s+\$_(?:GET|POST|REQUEST|COOKIE)', "PHP direct echo of input"),
        (r'print.*request\.args', "Flask direct print of request arg"),
        (r'dangerouslySetInnerHTML', "React dangerouslySetInnerHTML"),
        (r'v-html\s*=', "Vue v-html — XSS risk"),
        (r'\.outerHTML\s*=', "outerHTML assignment — DOM XSS"),
        (r'eval\s*\(.*location\.', "eval with location data — DOM XSS"),
        (r'document\.location\s*=.*\+', "document.location with concat — open redirect/XSS"),
        (r'mark_safe\s*\(', "Django mark_safe — bypasses escaping"),
        (r'Markup\s*\(', "Jinja2/Markupsafe Markup() — bypasses escaping"),
    ],
    "path_traversal": [
        (r'open\s*\(.*(?:request|args|param|query)', "User input in file open"),
        (r'send_file\s*\(.*(?:request|args)', "send_file with user input — LFI"),
        (r'send_from_directory\s*\(.*(?:request|args)', "send_from_directory with user input"),
        (r'os\.path\.join\s*\(.*(?:request|args|param)', "os.path.join with user input"),
        (r'extractall\s*\(', "ZipFile.extractall — Zip Slip / path traversal"),
        (r'tarfile.*extract(?:all)?\s*\(', "tarfile extraction — path traversal"),
        (r'\.\./|%2e%2e%2f|%252e%252e', "Path traversal pattern in string"),
        (r'include\s*\(\s*\$_(?:GET|POST)', "PHP LFI via include"),
        (r'require(?:_once)?\s*\(\s*\$_', "PHP LFI via require"),
    ],
    "deserialization": [
        (r'pickle\.loads?\s*\(', "Python pickle deserialization — RCE"),
        (r'yaml\.load\s*\([^,)]*\)', "PyYAML yaml.load without Loader — RCE"),
        (r'marshal\.loads?\s*\(', "Python marshal deserialization"),
        (r'jsonpickle\.decode\s*\(', "jsonpickle decode — code execution"),
        (r'unserialize\s*\(', "PHP unserialize — object injection"),
        (r'ObjectInputStream\s*\(', "Java ObjectInputStream — deserialization RCE"),
        (r'readObject\s*\(\)', "Java readObject — deserialization"),
        (r'JSON\.parse\s*\(.*eval', "JSON.parse + eval"),
        (r'node-serialize|serialize\.unserialize', "Node.js node-serialize RCE"),
    ],
    "xxe": [
        (r'DOCTYPE.*ENTITY', "XXE: DOCTYPE with ENTITY declaration"),
        (r'XMLParser\s*\(.*resolve_entities\s*=\s*True', "lxml with resolve_entities=True"),
        (r'etree\.parse\s*\(', "ElementTree parse — check for XXE"),
        (r'lxml.*fromstring\s*\(', "lxml fromstring — check for XXE"),
        (r'parseString\s*\(', "xml.dom.minidom parseString"),
        (r'SAXParser|DocumentBuilderFactory', "Java XML parser — check XXE config"),
        (r'FEATURE_EXTERNAL_GENERAL_ENTITIES', "External entity feature enabled"),
    ],
    "ssrf": [
        (r'requests\.(get|post|put)\s*\(.*(?:request\.|args\.|param\.|url)', "SSRF: user-controlled URL in requests"),
        (r'urllib\.(request\.urlopen|urlopen)\s*\(.*(?:request\.|args\.|param)', "SSRF: urllib with user input"),
        (r'curl_exec\s*\(', "PHP SSRF via curl_exec"),
        (r'curl_setopt.*CURLOPT_URL.*\$_', "PHP SSRF: user URL in curl"),
        (r'fetch\s*\(.*(?:req\.(body|query|params)|req\.)', "Node.js fetch with user input — SSRF"),
        (r'http\.(get|post)\s*\(.*(?:req\.|request\.)', "Node.js http with user input — SSRF"),
        (r'socket\.connect\s*\(.*(?:request|args|param)', "Socket connect with user input — SSRF"),
        (r'smtplib\.SMTP\s*\(.*(?:request|args)', "SMTP with user input — SSRF"),
    ],
    "prototype_pollution": [
        (r'__proto__', "Prototype pollution: __proto__ access"),
        (r'constructor\[.{0,10}prototype.{0,10}\]', "Prototype via constructor[prototype]"),
        (r'Object\.assign\s*\(\s*\{\}.*req\.(body|query)', "Object.assign with user input"),
        (r'merge\s*\(.*req\.(body|query|params)', "Deep merge with user input — prototype pollution"),
        (r'deepmerge|deepAssign|extend\s*\(.*req\.', "Deep extend with user input"),
        (r'\[.*request\[.*\]\s*\]\s*=', "Bracket assignment from request — pollution risk"),
    ],
    "open_redirect": [
        (r'redirect\s*\(.*(?:request\.args|request\.form|req\.query)', "Open redirect with user input"),
        (r'res\.redirect\s*\(.*(?:req\.(body|query|params))', "Express open redirect"),
        (r'header\s*\(\s*["\']Location.*\$_(?:GET|POST|REQUEST)', "PHP header redirect with user input"),
        (r'next\s*=\s*request\.(args|form)', "Unvalidated 'next' redirect parameter"),
    ],
    "insecure_crypto": [
        (r'hashlib\.md5\s*\(', "MD5 — not suitable for passwords/signing"),
        (r'hashlib\.sha1\s*\(', "SHA1 — deprecated, avoid for security"),
        (r'md5\s*\(', "MD5 function call"),
        (r'(?:random|Math\.random)\s*\(\)', "Weak PRNG for security purposes"),
        (r'secrets\s*=\s*random', "random module used for secrets"),
        (r'DES\s*\(|TripleDES|3DES', "DES/3DES cipher — weak, broken"),
        (r'RC4\s*\(|ARCFOUR', "RC4 cipher — broken"),
        (r'Blowfish\s*\(', "Blowfish — use AES instead"),
        (r'ECB\)', "ECB mode — patterns not hidden"),
        (r'IV\s*=\s*["\'][0-9a-fA-F]{16}["\']', "Hardcoded IV — not random"),
    ],
    "jwt_issues": [
        (r'verify\s*=\s*False', "JWT signature verification disabled"),
        (r'algorithms\s*=\s*\[\s*["\']none["\']', "JWT alg:none allowed — unsigned token accepted"),
        (r'algorithm\s*=\s*["\']none["\']', "JWT alg:none"),
        (r'decode\s*\(.*options\s*=\s*\{.*verify', "JWT decode with verify option — check value"),
        (r'jwt\.decode\s*\([^,]+,\s*["\'][^"\']{1,12}["\']', "JWT with short/weak secret"),
    ],
    "mass_assignment": [
        (r'Model\s*\(\s*\*\*request\.(?:json|form|args)', "SQLAlchemy mass assignment from request"),
        (r'from_dict\s*\(.*request\.json', "from_dict with full request body"),
        (r'update_or_create\s*\(.*request\.data', "Django mass assignment"),
        (r'\.create\s*\(\*\*request\.(?:json|data|POST)', "ORM create with full request data"),
        (r'req\.body\b(?!\.)', "Express route using raw req.body — check for mass assignment"),
    ],
    "nosql_injection": [
        (r'\$where\s*[=:]', "MongoDB $where — JS injection"),
        (r'\$regex.*(?:request|args|param)', "MongoDB $regex with user input"),
        (r'find\s*\(\s*(?:request|req\.)', "MongoDB find with user input"),
        (r'eval\s*:\s*(?:request|args)', "MongoDB eval operator"),
        (r'\$ne\s*:\s*null|\$gt\s*:\s*["\']', "NoSQL authentication bypass pattern"),
    ],
    "cors_misconfiguration": [
        (r'Access-Control-Allow-Origin.*\*', "CORS wildcard origin — allows any site"),
        (r'Access-Control-Allow-Credentials.*true', "CORS credentials with wildcard — data theft"),
        (r'origin\s*=\s*req\.headers\[.{0,10}origin.{0,10}\]', "CORS reflects arbitrary origin"),
        (r'CORS\s*\(\s*origins\s*=\s*["\*"\']', "Flask-CORS wildcard"),
        (r'cors\s*\(\s*\{.*origin\s*:\s*["\'\*]', "Express cors() with wildcard"),
    ],
    "file_ops": [
        (r'send_file\s*\(', "send_file — check for LFI"),
        (r'open\s*\(.*(?:\+|format|%)', "Dynamic file open with string ops"),
        (r'extractall\s*\(', "ZipFile.extractall — Zip Slip risk"),
        (r'tarfile.*extract', "tarfile extract — path traversal risk"),
        (r'shutil\.copy\s*\(.*(?:request|args)', "shutil.copy with user input"),
    ],
    "secrets": [
        (r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', "Hardcoded password"),
        (r'(?:api_key|apikey|api_secret)\s*=\s*["\'][A-Za-z0-9_\-]{10,}["\']', "Hardcoded API key"),
        (r'-----BEGIN(?:\s\w+)?\s+PRIVATE KEY-----', "Hardcoded private key"),
        (r'AKIA[0-9A-Z]{16}', "Hardcoded AWS access key"),
        (r'ghp_[A-Za-z0-9]{36}', "Hardcoded GitHub token"),
        (r'sk_live_[A-Za-z0-9]{24,}', "Hardcoded Stripe key"),
        (r'(?:secret|token|jwt_secret)\s*=\s*["\'][^"\']{6,}["\']', "Hardcoded token/secret"),
        (r'(?:DB_PASS|DATABASE_PASSWORD|MYSQL_PASS)\s*=\s*\S+', "Database password in code"),
    ],
    "broken_auth": [
        (r'if\s+.*==\s*True\s*:\s*#\s*TODO', "Auth check stubbed out"),
        (r'@login_required\s*#\s*disabled', "Login required decorator disabled"),
        (r'bypass_auth|skip_auth|no_auth', "Auth bypass flag/variable"),
        (r'if\s+debug\s*(?:and|or|==)', "Auth bypassed in debug mode"),
        (r'admin\s*=\s*True\b', "Hardcoded admin=True"),
    ],
}


@function_tool()
def static_code_analysis(path: str, language: str = "") -> str:
    """
    Perform static code analysis to find vulnerabilities.
    
    Args:
        path: File or directory to analyze
        language: Programming language (auto-detected if empty)
    
    Returns:
        Vulnerability analysis results
    """
    results = ["## Static Code Analysis\n"]
    path_obj = Path(path)
    
    if not path_obj.exists():
        return f"Error: Path not found: {path_obj}"
    
    files = [path_obj] if path_obj.is_file() else list(path_obj.rglob("*.py")) + list(path_obj.rglob("*.js")) + list(path_obj.rglob("*.php"))
    files = [f for f in files if "node_modules" not in str(f) and "venv" not in str(f)][:50]
    
    results.append(f"Scanning {len(files)} files\n")
    findings = []
    
    for file_path in files:
        try:
            content = file_path.read_text(errors="ignore")
            lines = content.split("\n")
            
            for vuln_type, patterns in VULN_PATTERNS.items():
                for pattern, desc in patterns:
                    for line_num, line in enumerate(lines, 1):
                        if re.search(pattern, line, re.IGNORECASE):
                            findings.append({"file": str(file_path), "line": line_num, 
                                           "type": vuln_type, "desc": desc, "code": line.strip()[:60]})
        except Exception:
            pass
    
    if findings:
        for f in findings[:20]:
            severity = "🔴" if f["type"] in ["sql_injection", "command_injection"] else "🟠"
            results.append(f"{severity} **{f['type']}**: {f['file']}:{f['line']}")
            results.append(f"   {f['desc']}: `{f['code']}`\n")
    else:
        results.append("✅ No vulnerabilities detected")
    
    results.append(f"\n**Summary**: {len(findings)} findings in {len(files)} files")
    return "\n".join(results)


@function_tool()
def secret_scanner(path: str) -> str:
    """
    Scan for hardcoded secrets and credentials.
    
    Args:
        path: File or directory to scan
    
    Returns:
        Secret detection results
    """
    results = ["## Secret Scanner\n"]
    path_obj = Path(path)
    
    if not path_obj.exists():
        return "Error: Path not found"
    
    patterns = [
        (r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']', "Password", "HIGH"),
        (r'(?:api_key|apikey)\s*[=:]\s*["\'][A-Za-z0-9]{10,}["\']', "API Key", "HIGH"),
        (r'-----BEGIN.*PRIVATE KEY-----', "Private Key", "CRITICAL"),
        (r'AKIA[0-9A-Z]{16}', "AWS Key", "CRITICAL"),
        (r'ghp_[A-Za-z0-9]{36}', "GitHub Token", "CRITICAL"),
        (r'sk-[A-Za-z0-9]{48}', "OpenAI Key", "HIGH"),
    ]
    
    files = [path_obj] if path_obj.is_file() else list(path_obj.rglob("*.*"))
    files = [f for f in files if f.is_file() and "node_modules" not in str(f)][:100]
    
    findings = []
    for file_path in files:
        try:
            content = file_path.read_text(errors="ignore")
            for pattern, secret_type, severity in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append({"file": str(file_path), "type": secret_type, "severity": severity})
        except Exception:
            pass
    
    if findings:
        for f in findings[:15]:
            icon = "🔴" if f["severity"] == "CRITICAL" else "🟠"
            results.append(f"{icon} **{f['type']}** in {f['file']}")
    else:
        results.append("✅ No hardcoded secrets detected")
    
    results.append(f"\n**Summary**: {len(findings)} secrets found")
    return "\n".join(results)


@function_tool()
def dependency_scan(path: str) -> str:
    """
    Scan dependencies for known vulnerabilities.
    
    Args:
        path: Project directory
    
    Returns:
        Dependency vulnerability report
    """
    results = ["## Dependency Scan\n"]
    path_obj = Path(path)
    
    # Python
    if (path_obj / "requirements.txt").exists():
        results.append("### Python Dependencies")
        try:
            result = subprocess.run(["pip-audit", "-r", str(path_obj / "requirements.txt")],
                                  capture_output=True, text=True, timeout=60)
            results.append(result.stdout[:1000] if result.stdout else "✅ No vulnerabilities")
        except FileNotFoundError:
            results.append("⚠️ pip-audit not installed")
    
    # Node.js
    if (path_obj / "package.json").exists():
        results.append("\n### Node.js Dependencies")
        try:
            result = subprocess.run(["npm", "audit", "--json"], capture_output=True, 
                                  text=True, timeout=60, cwd=str(path_obj))
            data = json.loads(result.stdout) if result.stdout else {}
            vulns = data.get("metadata", {}).get("vulnerabilities", {})
            if vulns:
                results.append(f"Critical: {vulns.get('critical', 0)}, High: {vulns.get('high', 0)}")
            else:
                results.append("✅ No vulnerabilities")
        except Exception:
            results.append("⚠️ npm audit failed")
    
    return "\n".join(results)


@function_tool()
def find_dangerous_functions(path: str) -> str:
    """
    Find dangerous function calls that could lead to vulnerabilities.
    
    Args:
        path: Directory to scan
    
    Returns:
        Dangerous function report
    """
    results = ["## Dangerous Functions\n"]
    path_obj = Path(path)
    
    dangerous = {
        "eval(": "Code execution",
        "exec(": "Code execution", 
        "os.system(": "Command injection",
        "subprocess.run(..., shell=True": "Command injection",
        "pickle.loads(": "Deserialization",
        "yaml.load(": "Deserialization",
        "render_template_string(": "SSTI (Flask)",
        "send_file(": "LFI / Arbitrary File Read",
        "innerHTML": "XSS risk",
        "document.write(": "XSS risk",
        "dangerouslySetInnerHTML": "React XSS",
        "extractall(": "Zip Slip / Path Traversal",
        "mark_safe(": "Django XSS bypass",
    }
    
    files = list(path_obj.rglob("*.py")) + list(path_obj.rglob("*.js")) if path_obj.is_dir() else [path_obj]
    files = [f for f in files if "node_modules" not in str(f)][:50]
    
    findings = []
    for file_path in files:
        try:
            content = file_path.read_text(errors="ignore")
            for func, risk in dangerous.items():
                if func in content:
                    findings.append({"file": str(file_path), "func": func, "risk": risk})
        except Exception:
            pass
    
    if findings:
        for f in findings[:20]:
            results.append(f"🔴 `{f['func']}` in {f['file']} - {f['risk']}")
    else:
        results.append("✅ No dangerous functions found")
    
    return "\n".join(results)


@function_tool()
def summarize_project(path: str) -> str:
    """
    Get a high-level strategic summary of the project structure and identifying 
    potential attack surfaces (entry points, controllers, DB configs).
    
    Args:
        path: Root directory of the project
    
    Returns:
        Strategic summary of the codebase
    """
    results = ["## Project Strategic Summary\n"]
    root = Path(path)
    
    if not root.exists():
        return "Error: Path not found"
    
    # 1. Map the structure (limited depth)
    structure = []
    for p in root.rglob("*"):
        if any(x in str(p) for x in ["node_modules", "venv", ".git", "__pycache__"]):
            continue
        rel = p.relative_to(root)
        if len(rel.parts) <= 3:  # Only top 3 levels
            indent = "  " * (len(rel.parts) - 1)
            type_icon = "📁" if p.is_dir() else "📄"
            structure.append(f"{indent}{type_icon} {rel.name}")
    
    results.append("### Directory Structure (Top-level)")
    results.append("```\n" + "\n".join(structure[:50]) + "\n```\n")
    
    # 2. Identify Key Files
    key_files = {
        "Entry Points": ["app.py", "main.py", "index.js", "server.js", "manage.py", "run.py"],
        "Routes/Controllers": ["routes.py", "views.py", "controllers/", "api/"],
        "Config/Secrets": [".env", "config.py", "settings.py", "database.py", "Dockerfile", "docker-compose.yml"],
        "Dependencies": ["requirements.txt", "package.json", "composer.json"]
    }
    
    results.append("### High-Interest Targets")
    for category, patterns in key_files.items():
        found = []
        for pattern in patterns:
            for p in root.rglob(pattern if not pattern.endswith("/") else pattern + "*"):
                if any(x in str(p) for x in ["node_modules", "venv"]): continue
                found.append(p.name)
        if found:
            results.append(f"- **{category}**: {', '.join(set(found))}")
            
    # 3. Security Recommendations
    results.append("\n### Strategic Attack Plan")
    results.append("1. **Analyze Entry Points**: Start with the main app/server file to find route definitions.")
    results.append("2. **Audit Controllers**: Look for files in `routes/` or `controllers/` using `find_dangerous_functions`.")
    results.append("3. **Check Config**: Audit `Dockerfile` or `.env` for hardcoded creds or internal service URLs.")
    results.append("4. **Dependency Audit**: Run `dependency_scan` on found manifest files.")

    return "\n".join(results)


# ─────────────────────────────────────────────────────────────────────────────
# Fast codebase explorer tools  (from code_explorer.py)
# ─────────────────────────────────────────────────────────────────────────────

IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".idea", "dist", "build"}


@function_tool()
def repo_map(path: str) -> str:
    """
    Generate a full directory tree structure (like the 'tree' command) ignoring common irrelevant folders.
    This gives you a fast, instant overview of the repository layout.
    """
    path_obj = Path(path)
    if not path_obj.exists():
        return f"Error: Path not found: {path}"
    if not path_obj.is_dir():
        return f"Error: Path is not a directory: {path}"

    tree_str = [f"📁 {path_obj.name}/"]

    def generate_tree(dir_path: Path, prefix: str = ""):
        try:
            items = list(dir_path.iterdir())
        except PermissionError:
            return

        items.sort(key=lambda x: (not x.is_dir(), x.name.lower()))

        # Filter out ignored dirs
        filtered_items = [i for i in items if i.name not in IGNORE_DIRS and not i.name.startswith(".")]

        for i, item in enumerate(filtered_items):
            connector = "└── " if i == len(filtered_items) - 1 else "├── "

            if item.is_dir():
                tree_str.append(f"{prefix}{connector}📁 {item.name}/")
                next_prefix = prefix + ("    " if i == len(filtered_items) - 1 else "│   ")
                generate_tree(item, next_prefix)
            else:
                tree_str.append(f"{prefix}{connector}📄 {item.name}")

    generate_tree(path_obj)
    return "\n".join(tree_str)


@function_tool()
def pattern_search(path: str, pattern: str) -> str:
    """
    Fast global pattern scanning (like grep -rn).
    Uses ripgrep (rg) when available — 10-50x faster than Python walker.
    Falls back to Python regex on every readable file if rg is absent.

    Useful for instantly locating vulnerable sinks:
      pattern_search(path, "eval|exec|render_template_string|system|os.popen")
    """
    path_obj = Path(path)
    if not path_obj.exists():
        return f"Error: Path not found: {path}"

    # ── ripgrep fast path ────────────────────────────────────────────────────
    if shutil.which("rg"):
        rc, out, err = _rg(str(path_obj), pattern, timeout=30)
        if rc == 0 and out.strip():
            lines = out.strip().splitlines()
            header = f"Pattern: '{pattern}' — {len(lines)} match(es) (via rg)\n"
            return header + "\n".join(lines[:500])
        if rc == 1:
            return f"No matches found for pattern: '{pattern}' in {path}"
        # rc == -2 means rg exec failed despite which() succeeding — fall through

    # ── Python fallback ──────────────────────────────────────────────────────
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return f"Error: Invalid regex pattern: {e}"

    results = []
    files_to_read = [path_obj] if path_obj.is_file() else list(path_obj.rglob("*.*"))

    for file_path in files_to_read:
        if not file_path.is_file():
            continue
        if any(ignored in file_path.parts for ignored in IGNORE_DIRS):
            continue
        try:
            content = file_path.read_text(errors="ignore")
            for i, line in enumerate(content.splitlines(), 1):
                if regex.search(line):
                    results.append(f"{file_path}:{i}: {line.strip()}")
        except Exception:
            continue

    if not results:
        return f"No matches found for pattern: '{pattern}' in {path}"

    header = f"Pattern: '{pattern}' — {len(results)} match(es) (Python fallback)\n"
    return header + "\n".join(results[:500])


@function_tool()
def concat_code(path: str, extensions: Optional[List[str]] = None) -> str:
    """
    Code concatenation tool for small-to-medium apps.
    Dumps the content of all files matching the given extensions (e.g., ['.py', '.js']).
    Instead of calling 'cat' multiple times, this returns the entire backend code in one prompt.
    """
    path_obj = Path(path)
    if not path_obj.exists():
        return f"Error: Path not found: {path}"

    if not extensions:
        extensions = ['.py', '.js', '.ts', '.tsx', '.php', '.html', '.mjs', '.cjs']
    else:
        # Accept both a list and a comma-separated string like ".mjs,html,json"
        if isinstance(extensions, str):
            extensions = [e.strip() for e in extensions.split(',') if e.strip()]
        extensions = [ext if ext.startswith('.') else f".{ext}" for ext in extensions]

    results = []
    total_size = 0
    MAX_SIZE = 100_000  # Keep LLM context from blowing out

    files_to_read = [path_obj] if path_obj.is_file() else list(path_obj.rglob("*.*"))

    for file_path in files_to_read:
        if not file_path.is_file():
            continue

        if any(ignored in file_path.parts for ignored in IGNORE_DIRS):
            continue

        if extensions and file_path.suffix not in extensions:
            continue

        try:
            content = file_path.read_text(errors="ignore")
            if total_size + len(content) > MAX_SIZE:
                results.append(f"\n... [Truncated: Max size {MAX_SIZE} reached] ...")
                break

            results.append(f"\n{'='*50}\nFILE: {file_path}\n{'='*50}\n")
            results.append(content)
            total_size += len(content)
        except Exception:
            continue

    if not results:
        return f"No files matched extensions {extensions} in {path}"

    return "".join(results)


@function_tool()
def ast_symbol_search(path: str) -> str:
    """
    Semantic/Graph-based tool (TOC Generator).
    Scans Python and JavaScript/TypeScript files in a directory and extracts class, function,
    and method signatures to provide a high-level "Table of Contents" of the codebase context.
    Provides instant semantic understanding without reading full bodies.
    """
    path_obj = Path(path)
    if not path_obj.exists():
        return f"Error: Path not found: {path}"

    results = ["🔍 AST / Symbol Table of Contents:\n"]
    files_to_read = [path_obj] if path_obj.is_file() else list(path_obj.rglob("*.*"))

    # Regex basic parsers
    py_func_pattern = re.compile(r'^\s*(def|class)\s+([a-zA-Z0-9_]+)\s*\(')
    py_route_pattern = re.compile(r'^\s*@[\w\.]+(route|app\.|router\.|get|post|put|delete)\(')
    js_func_pattern = re.compile(r'^\s*(function|class)\s+([a-zA-Z0-9_]+)|(const|let|var)\s+([a-zA-Z0-9_]+)\s*=\s*(?:async\s*)?(?:function|\()')

    found_any = False

    for file_path in files_to_read:
        if not file_path.is_file():
            continue

        if any(ignored in file_path.parts for ignored in IGNORE_DIRS):
            continue

        is_py = file_path.suffix == '.py'
        is_js = file_path.suffix in ['.js', '.ts', '.tsx', '.jsx']

        if not (is_py or is_js):
            continue

        try:
            content = file_path.read_text(errors="ignore")
            lines = content.splitlines()
            file_symbols = []

            for i, line in enumerate(lines, 1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith('//') or clean_line.startswith('#'):
                    continue

                if is_py:
                    if py_route_pattern.search(line):
                        file_symbols.append(f"  [Line {i}] Route: {clean_line}")
                    else:
                        match = py_func_pattern.search(line)
                        if match:
                            file_symbols.append(f"  [Line {i}] {match.group(1).capitalize()}: {match.group(2)}")
                elif is_js:
                    match = js_func_pattern.search(line)
                    if match:
                        if match.group(1):  # function or class
                            file_symbols.append(f"  [Line {i}] {match.group(1).capitalize()}: {match.group(2)}")
                        elif match.group(4):  # const/let arrow function
                            file_symbols.append(f"  [Line {i}] Function (arrow): {match.group(4)}")

            if file_symbols:
                found_any = True
                results.append(f"📄 {file_path}")
                results.extend(file_symbols)
                results.append("")  # empty line spacing

        except Exception:
            continue

    if not found_any:
        return f"No functions/classes found in {path}"

    return "\n".join(results)


# ─────────────────────────────────────────────────────────────────────────────
# semgrep_scan — Deep static analysis via Semgrep rules
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def semgrep_scan(path: str, ruleset: str = "auto") -> str:
    """
    Run Semgrep static analysis for security vulnerabilities.

    Much deeper than regex pattern_search — Semgrep understands AST, data-flow,
    and taint tracking. Use after pattern_search narrows the area of interest.

    Rulesets:
      auto            — auto-detect language and apply best rules (default)
      p/python        — Python security rules
      p/javascript    — JavaScript/TypeScript security
      p/php           — PHP security
      p/java          — Java security
      p/go            — Go security
      p/owasp-top-ten — OWASP Top 10 across all languages
      p/security-audit — Comprehensive security audit pack

    Args:
        path:    File or directory to scan
        ruleset: Semgrep ruleset identifier (default: auto)
    """
    if not shutil.which("semgrep"):
        return (
            "semgrep not installed.\n"
            "Install: pip install semgrep\n"
            "Or: brew install semgrep  /  https://semgrep.dev/docs/getting-started/"
        )

    p = Path(path)
    if not p.exists():
        return f"Error: Path not found: {path}"

    cmd = [
        "semgrep",
        "--config", ruleset,
        "--json",
        "--no-git-ignore",
        "--timeout", "60",
        str(p),
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return "semgrep timed out after 5 minutes"
    except Exception as e:
        return f"semgrep error: {e}"

    if not result.stdout.strip():
        return f"semgrep: no output (stderr: {result.stderr[:300]})"

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return f"semgrep output not JSON:\n{result.stdout[:500]}"

    findings = data.get("results", [])
    errors   = data.get("errors", [])

    if not findings:
        msg = f"✅ Semgrep ({ruleset}): No findings in {path}"
        if errors:
            msg += f"\n⚠ {len(errors)} parse error(s): {errors[0].get('message','')[:100]}"
        return msg

    # Group by severity
    by_sev: dict[str, list] = {"ERROR": [], "WARNING": [], "INFO": []}
    for f in findings:
        sev = f.get("extra", {}).get("severity", "INFO").upper()
        by_sev.setdefault(sev, []).append(f)

    out = [f"## Semgrep ({ruleset}): {len(findings)} finding(s)\n"]

    sev_icons = {"ERROR": "🔴", "WARNING": "🟠", "INFO": "🔵"}
    for sev in ("ERROR", "WARNING", "INFO"):
        items = by_sev.get(sev, [])
        if not items:
            continue
        out.append(f"### {sev_icons.get(sev, '')} {sev} ({len(items)})")
        for item in items[:20]:
            check  = item.get("check_id", "?")
            fpath  = item.get("path", "?")
            start  = item.get("start", {}).get("line", "?")
            msg    = item.get("extra", {}).get("message", "")[:120]
            code   = item.get("extra", {}).get("lines", "").strip()[:80]
            out.append(f"  {fpath}:{start}  [{check}]")
            out.append(f"    {msg}")
            if code:
                out.append(f"    `{code}`")
        if len(items) > 20:
            out.append(f"  ... +{len(items)-20} more")
        out.append("")

    if errors:
        out.append(f"⚠ {len(errors)} parse error(s) — some files may have been skipped")

    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# framework_audit — Framework-specific security checks
# ─────────────────────────────────────────────────────────────────────────────

_FRAMEWORK_SIGNATURES = {
    "Flask": {
        "files": ["app.py", "wsgi.py", "run.py"],
        "imports": ["from flask import", "import flask"],
        "checks": [
            (r'app\.secret_key\s*=\s*["\'][^"\']{1,15}["\']', "Weak Flask secret_key (< 16 chars)", "HIGH"),
            (r'app\.config\[.SECRET_KEY.\]\s*=\s*["\']', "Hardcoded Flask secret_key", "HIGH"),
            (r'DEBUG\s*=\s*True', "Flask DEBUG=True — exposes interactive debugger", "CRITICAL"),
            (r'render_template_string\s*\(', "render_template_string — SSTI risk", "CRITICAL"),
            (r'app\.run\s*\(.*debug\s*=\s*True', "app.run(debug=True) — Werkzeug debugger exposed", "CRITICAL"),
            (r'SQLALCHEMY_DATABASE_URI.*sqlite://', "SQLite DB in Flask — fine for dev, not prod", "INFO"),
            (r'WTF_CSRF_ENABLED\s*=\s*False', "Flask-WTF CSRF protection disabled", "HIGH"),
            (r'SESSION_COOKIE_SECURE\s*=\s*False', "Session cookie sent over HTTP", "MEDIUM"),
            (r'SESSION_COOKIE_HTTPONLY\s*=\s*False', "Session cookie accessible to JS", "MEDIUM"),
        ],
    },
    "Django": {
        "files": ["settings.py", "manage.py"],
        "imports": ["from django", "import django"],
        "checks": [
            (r"SECRET_KEY\s*=\s*['\"][^'\"]{1,30}['\"]", "Short Django SECRET_KEY", "HIGH"),
            (r'DEBUG\s*=\s*True', "Django DEBUG=True — stack traces exposed", "HIGH"),
            (r'ALLOWED_HOSTS\s*=\s*\[.*\*.*\]', "Django ALLOWED_HOSTS=* — host header injection", "HIGH"),
            (r'CSRF_COOKIE_SECURE\s*=\s*False', "CSRF cookie not Secure", "MEDIUM"),
            (r'SESSION_COOKIE_SECURE\s*=\s*False', "Session cookie not Secure", "MEDIUM"),
            (r'CORS_ORIGIN_ALLOW_ALL\s*=\s*True', "Django CORS allows all origins", "HIGH"),
            (r'\.extra\s*\(.*select\s*=.*%s', "Django .extra() with string format — SQLi risk", "CRITICAL"),
            (r'RawSQL\s*\(.*%s', "RawSQL with %s format", "CRITICAL"),
            (r'mark_safe\s*\(', "mark_safe() bypasses escaping — XSS risk", "HIGH"),
            (r'SECURE_SSL_REDIRECT\s*=\s*False', "HTTPS redirect disabled", "MEDIUM"),
        ],
    },
    "Express": {
        "files": ["app.js", "server.js", "index.js"],
        "imports": ["require('express')", 'require("express")', "from 'express'"],
        "checks": [
            (r'app\.disable\s*\(["\']x-powered-by["\']\)', None, None),  # good — skip
            (r'helmet\s*\(\)', None, None),  # good — skip
            (r'eval\s*\(.*req\.(body|query|params)', "eval with user input — RCE", "CRITICAL"),
            (r'child_process\.exec\s*\(.*req\.', "child_process.exec with user input — command injection", "CRITICAL"),
            (r'res\.send\s*\(.*req\.(query|body|params)', "Direct res.send of user input — XSS", "HIGH"),
            (r'mongoose\.connect\s*\([^,)]+\)', "Mongoose connection string — check for hardcoded creds", "MEDIUM"),
            (r'app\.use\s*\(cors\s*\(\s*\)\s*\)', "Express cors() with no options — wildcard CORS", "MEDIUM"),
            (r'cookie-session.*secret.*["\'][^"\']{1,8}["\']', "Short cookie-session secret", "HIGH"),
            (r'NODE_ENV\s*!==?\s*["\']production', "NODE_ENV check — ensure prod env is set", "INFO"),
            (r'process\.env\.\w+\s*\|\|\s*["\'][^"\']{4,}["\']', "Fallback hardcoded secret in env read", "MEDIUM"),
        ],
    },
    "FastAPI": {
        "files": ["main.py", "app.py"],
        "imports": ["from fastapi import", "import fastapi"],
        "checks": [
            (r'allow_origins\s*=\s*\[.*\*.*\]', "FastAPI CORS wildcard origin", "HIGH"),
            (r'allow_credentials\s*=\s*True.*allow_origins\s*=\s*\[.*\*', "CORS credentials + wildcard", "CRITICAL"),
            (r'SECRET_KEY\s*=\s*["\'][^"\']{1,20}["\']', "Short JWT secret key", "HIGH"),
            (r'algorithms\s*=\s*\[.*none.*\]', "JWT alg:none allowed", "CRITICAL"),
            (r'verify\s*=\s*False', "JWT verification disabled", "CRITICAL"),
            (r'Depends\s*\(\s*\)', "Empty Depends() — auth dependency may be stub", "MEDIUM"),
        ],
    },
    "Laravel": {
        "files": [".env", "artisan", "composer.json"],
        "imports": ["use Illuminate\\", "use Laravel\\"],
        "checks": [
            (r'APP_DEBUG\s*=\s*true', "Laravel APP_DEBUG=true — stack traces exposed", "HIGH"),
            (r'APP_KEY\s*=\s*base64:[A-Za-z0-9+/]{20,}', None, None),  # good key, skip
            (r'APP_KEY\s*=\s*(?!base64:)', "Laravel APP_KEY not using base64: format", "HIGH"),
            (r'DB_PASSWORD\s*=\s*(?!$)\S+', "Database password in .env", "MEDIUM"),
            (r'\$request->all\(\)', "Laravel $request->all() — mass assignment risk", "MEDIUM"),
            (r'DB::select\s*\(.*\\.', "DB::select with concatenation — SQLi risk", "HIGH"),
            (r'->whereRaw\s*\(.*\\.', "whereRaw with concatenation", "HIGH"),
            (r'html_entity_decode\s*\(', "html_entity_decode — may bypass XSS protection", "MEDIUM"),
            (r'\{\!!\s*\$', "Blade {!! !!} — unescaped output", "HIGH"),
        ],
    },
}


@function_tool()
def framework_audit(path: str) -> str:
    """
    Detect web framework and run framework-specific security checks.

    Detects: Flask, Django, Express/Node.js, FastAPI, Laravel.
    Each framework has tailored checks for its common misconfigurations.

    Args:
        path: Project root directory or specific source file
    """
    root = Path(path)
    if not root.exists():
        return f"Error: Path not found: {path}"

    # Collect all relevant source files
    all_files = list(root.rglob("*")) if root.is_dir() else [root]
    all_files = [
        f for f in all_files if f.is_file()
        and not any(ign in f.parts for ign in IGNORE_DIRS)
    ]

    # Detect framework(s)
    detected: list[str] = []
    for fw, sig in _FRAMEWORK_SIGNATURES.items():
        for f in all_files:
            if f.name in sig["files"]:
                detected.append(fw)
                break
            try:
                snippet = f.read_text(errors="ignore")[:500]
                if any(imp in snippet for imp in sig["imports"]):
                    detected.append(fw)
                    break
            except Exception:
                pass

    if not detected:
        return (
            "No recognized framework detected.\n"
            "Supported: Flask, Django, Express, FastAPI, Laravel\n"
            "Run static_code_analysis() for language-agnostic pattern scan."
        )

    out = [f"## Framework Audit: {root.name}", f"Detected: {', '.join(detected)}", ""]

    for fw in detected:
        checks = _FRAMEWORK_SIGNATURES[fw]["checks"]
        out.append(f"### {fw}")
        findings = []

        for file_path in all_files:
            try:
                content = file_path.read_text(errors="ignore")
            except Exception:
                continue
            for pattern, desc, severity in checks:
                if desc is None:
                    continue  # explicitly "good" pattern, skip
                for i, line in enumerate(content.splitlines(), 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "file": str(file_path.relative_to(root) if root.is_dir() else file_path),
                            "line": i,
                            "desc": desc,
                            "severity": severity,
                            "code": line.strip()[:80],
                        })

        if not findings:
            out.append(f"  ✅ No {fw}-specific misconfigurations found")
        else:
            _sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "🔵"}
            for f in findings[:25]:
                icon = _sev_icon.get(f["severity"], "⚪")
                out.append(f"  {icon} [{f['severity']}] {f['file']}:{f['line']} — {f['desc']}")
                out.append(f"       `{f['code']}`")
            if len(findings) > 25:
                out.append(f"  ... +{len(findings)-25} more")

        out.append("")

    return "\n".join(out)
