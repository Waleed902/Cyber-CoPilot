"""
Crypto Tools: Password cracking with John the Ripper and Hashcat.
"""

import subprocess
from src.sdk.tool import function_tool


@function_tool()
def john_crack(hash_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt", format: str | None = None) -> str:
    """
    Crack password hashes using John the Ripper.
    
    Args:
        hash_file: Path to file containing hashes
        wordlist: Path to wordlist file (default: rockyou.txt)
        format: Hash format (e.g., 'md5', 'sha256', 'raw-sha1', 'bcrypt')
    
    Returns:
        Cracked passwords and status
    """
    try:
        cmd = ["john"]
        if wordlist:
            cmd.extend(["--wordlist=" + wordlist])
        if format:
            cmd.extend(["--format=" + format])
        cmd.append(hash_file)
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        # Show cracked passwords
        show_result = subprocess.run(
            ["john", "--show", hash_file],
            capture_output=True, text=True, timeout=30
        )
        
        return f"John the Ripper Results:\n{result.stdout}\n\nCracked:\n{show_result.stdout}"
    except subprocess.TimeoutExpired:
        return "John the Ripper: Still running (timeout). Check with 'john --show'"
    except FileNotFoundError:
        return "Error: john not found. Install with: apt install john"
    except Exception as e:
        return f"Error: {str(e)}"


@function_tool()
def john_show(hash_file: str) -> str:
    """
    Show cracked passwords from John the Ripper.
    
    Args:
        hash_file: Path to file containing hashes
    
    Returns:
        Previously cracked passwords
    """
    try:
        result = subprocess.run(
            ["john", "--show", hash_file],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout if result.stdout else "No passwords cracked yet."
    except Exception as e:
        return f"Error: {str(e)}"


@function_tool()
def hashcat_crack(
    hash_file: str, 
    hash_type: int,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    rules: str | None = None
) -> str:
    """
    Crack password hashes using Hashcat (GPU-accelerated).
    
    Args:
        hash_file: Path to file containing hashes
        hash_type: Hashcat hash type code (e.g., 0=MD5, 100=SHA1, 1400=SHA256, 3200=bcrypt)
        wordlist: Path to wordlist file
        rules: Optional rules file for mutations
    
    Returns:
        Cracked passwords and status
    """
    try:
        cmd = [
            "hashcat",
            "-m", str(hash_type),
            "-a", "0",  # Dictionary attack
            "--potfile-disable",  # Don't use potfile for cleaner output
            "-o", f"{hash_file}.cracked",
            hash_file,
            wordlist
        ]
        
        if rules:
            cmd.extend(["-r", rules])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        # Read cracked passwords
        try:
            with open(f"{hash_file}.cracked", "r") as f:
                cracked = f.read()
        except:
            cracked = "No passwords cracked."
        
        return f"Hashcat Results:\n{result.stdout}\n\nCracked:\n{cracked}"
    except subprocess.TimeoutExpired:
        return "Hashcat: Still running (timeout reached)."
    except FileNotFoundError:
        return "Error: hashcat not found. Install with: apt install hashcat"
    except Exception as e:
        return f"Error: {str(e)}"


@function_tool()
def hash_identifier(hash_value: str) -> str:
    """
    Identify hash type using hash-identifier.
    
    Args:
        hash_value: The hash string to identify
    
    Returns:
        Possible hash types
    """
    try:
        # Use hashid for identification
        result = subprocess.run(
            ["hashid", hash_value],
            capture_output=True, text=True, timeout=30
        )
        if result.stdout:
            return result.stdout
        
        # Fallback: basic identification by length
        length = len(hash_value)
        types = {
            32: "MD5, NTLM, MD4",
            40: "SHA1, MySQL5",
            56: "SHA224",
            64: "SHA256, SHA3-256",
            96: "SHA384",
            128: "SHA512, SHA3-512"
        }
        return f"Hash length: {length}\nPossible types: {types.get(length, 'Unknown')}"
    except FileNotFoundError:
        # Fallback
        length = len(hash_value)
        if length == 32:
            return "Likely MD5 (32 chars)"
        elif length == 40:
            return "Likely SHA1 (40 chars)"
        elif length == 64:
            return "Likely SHA256 (64 chars)"
        return f"Hash length: {length} chars"
    except Exception as e:
        return f"Error: {str(e)}"


@function_tool()
def create_hash(text: str, algorithm: str = "md5") -> str:
    """
    Create a hash from text (for testing).
    
    Args:
        text: Text to hash
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)
    
    Returns:
        Hash value
    """
    import hashlib
    
    algorithms = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512
    }
    
    if algorithm.lower() not in algorithms:
        return f"Unknown algorithm. Use: {', '.join(algorithms.keys())}"
    
    hash_func = algorithms[algorithm.lower()]
    hash_value = hash_func(text.encode()).hexdigest()
    return f"{algorithm.upper()}: {hash_value}"


@function_tool()
def nth_identify(hash_value: str) -> str:
    """
    Identify hash type using Name-That-Hash (nth) - better than hash-identifier.
    Shows hashcat mode and john format for cracking.
    
    Args:
        hash_value: The hash string to identify
    
    Returns:
        Hash type identification with cracking tool modes
    """
    try:
        result = subprocess.run(
            ["nth", "-t", hash_value, "--no-banner"],
            capture_output=True,
            text=True,
            timeout=30
        )
        output = result.stdout or result.stderr
        if output:
            return output
        return "Could not identify hash type"
    except FileNotFoundError:
        return "Error: nth (Name-That-Hash) not found. Install with: pip install name-that-hash"
    except Exception as e:
        return f"Error identifying hash: {str(e)}"


@function_tool()
def ssh_key_crack(
    key_file: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    hash_output: str = "",
) -> str:
    """
    Crack an encrypted SSH private key passphrase using ssh2john + John the Ripper.

    Workflow:
      1. Run ssh2john (or python3 ssh2john.py) on the key file to extract a
         John-compatible hash.
      2. Run john --wordlist against that hash.
      3. Return the cracked passphrase so it can be used with ssh_exec.

    Args:
        key_file: Absolute path to the SSH private key (e.g. /tmp/id_ed25519).
        wordlist: Path to wordlist (default: rockyou.txt).
        hash_output: Optional path where the extracted hash should be saved
                     (defaults to <key_file>.hash).

    Returns:
        Cracked passphrase on success, or descriptive error.
    """
    import os
    import shutil

    out = [f"=== SSH Key Crack: {key_file} ==="]

    hash_file = hash_output or f"{key_file}.hash"

    # ── Step 1: convert key → john hash via ssh2john ──────────────────────────
    ssh2john_bin = shutil.which("ssh2john") or shutil.which("ssh2john.py")
    if not ssh2john_bin:
        # Try common python path
        candidates = [
            "/usr/share/john/ssh2john.py",
            "/usr/share/john/ssh2john",
            "/opt/john/run/ssh2john.py",
        ]
        for c in candidates:
            if os.path.exists(c):
                ssh2john_bin = c
                break

    if not ssh2john_bin:
        return ("Error: ssh2john not found. Install John the Ripper full suite:\n"
                "  apt install john  (Debian/Ubuntu)\n"
                "  or locate ssh2john.py in your john installation.")

    try:
        # ssh2john can be a standalone binary or a python script
        if ssh2john_bin.endswith(".py"):
            cmd = ["python3", ssh2john_bin, key_file]
        else:
            cmd = [ssh2john_bin, key_file]

        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        hash_data = res.stdout.strip()
        if not hash_data:
            err = res.stderr.strip()
            if "not an RSA" in err or "not encrypted" in err.lower() or "no encrypted" in err.lower():
                return f"  [-] Key '{key_file}' is NOT passphrase-protected — no cracking needed."
            return f"  [!] ssh2john failed: {err or 'no output'}"

        with open(hash_file, "w") as f:
            f.write(hash_data + "\n")
        out.append(f"  [+] Hash extracted → {hash_file}")

    except subprocess.TimeoutExpired:
        return "Error: ssh2john timed out."
    except Exception as e:
        return f"Error running ssh2john: {e}"

    # ── Step 2: crack with john ───────────────────────────────────────────────
    out.append(f"  [*] Running john with wordlist: {wordlist}")
    try:
        john_res = subprocess.run(
            ["john", f"--wordlist={wordlist}", hash_file],
            capture_output=True, text=True, timeout=300
        )
        show_res = subprocess.run(
            ["john", "--show", hash_file],
            capture_output=True, text=True, timeout=30
        )
        cracked_output = show_res.stdout.strip()
        out.append(f"  John output:\n{john_res.stdout.strip() or john_res.stderr.strip()}")

        # Parse passphrase from "filename:passphrase:..."
        passphrase = ""
        for line in cracked_output.splitlines():
            if ":" in line and not line.startswith("0 "):
                parts = line.split(":")
                if len(parts) >= 2:
                    passphrase = parts[1]
                    break

        if passphrase:
            out.append(f"  [+] CRACKED! Passphrase: {passphrase}")
            out.append(f"  Use with: ssh_exec(target, username, key_file='{key_file}', passphrase='{passphrase}')")
        else:
            out.append("  [-] Passphrase not found in wordlist.")

    except subprocess.TimeoutExpired:
        out.append("  [!] John timed out — still running. Check with: john --show " + hash_file)
    except FileNotFoundError:
        out.append("  [!] john not found. Install with: apt install john")
    except Exception as e:
        out.append(f"  [!] John error: {e}")

    return "\n".join(out)


@function_tool()
def smart_contract_audit(contract_address: str = "", rpc_url: str = "", source_code: str = "") -> str:
    """
    Basic Web3 Smart Contract Auditing.
    Can analyze a provided solidity code snippet using an LLM or use basic static analysis.
    
    Args:
        contract_address: The address of the deployed smart contract (optional).
        rpc_url: RPC URL to connect to the blockchain (optional).
        source_code: The raw Solidity source code of the contract to analyze.
        
    Returns:
        Security assessment of the smart contract, highlighting potential reentrancy, 
        access control, and integer overflow issues.
    """
    results = ["## Smart Contract / Web3 Security Audit\n"]
    if contract_address:
        results.append(f"**Target Address:** {contract_address}")
        
    if not source_code:
        results.append("[-] Error: No source code provided for analysis. Please provide the Solidity source code via the 'source_code' argument.")
        return "\n".join(results)
        
    results.append("[+] Initializing Semantic Solidity Analyzer...")
    
    # Very basic static analysis regexes as fallback/quick heuristic
    import re
    vulnerabilities = []
    
    if re.search(r'\.call\{.*value:.*\}\(.*\)', source_code):
        vulnerabilities.append("- **Possible Reentrancy**: Low-level '.call{value: }' pattern detected.")
    if "tx.origin" in source_code:
        vulnerabilities.append("- **tx.origin Authorization Bypass**: Use of tx.origin instead of msg.sender for authorization.")
    if "selfdestruct(" in source_code or "suicide(" in source_code:
        vulnerabilities.append("- **Unprotected Selfdestruct**: Contract might be randomly destructible.")
    if re.search(r'function\s+[a-zA-Z0-9_]+\s*\(.*\)\s*public\s*\{', source_code) and \
       "msg.sender" not in source_code and "require(" not in source_code:
        vulnerabilities.append("- **Insecure Access Control**: Public functions modifying state unconditionally.")
        
    if vulnerabilities:
        results.append("\n### Heuristic Findings:")
        results.extend(vulnerabilities)
    else:
        results.append("\n### Heuristic Findings:\nNo obvious anti-patterns detected via static regex.")
        
    try:
        from src.sdk.llm import get_llm
        llm = get_llm()
        results.append("\n[+] Running Deep LLM Semantic Analysis (finding logic bugs)...")
        prompt = f'''
Analyze this Solidity smart contract source code for critical vulnerabilities including:
1. Reentrancy
2. Access Control Flaws
3. Flash Loan / Price Oracle Manipulation risks
4. Integer Overflow/Underflow
5. Logic flaws (e.g. infinite minting, missing withdrawal control)

Source Code:
```solidity
{source_code[:5000]}
```

Provide a very concise markdown summary of the vulnerabilities found (do not repeat the code).
'''
        llm_report = llm.generate_response(prompt)
        results.append("\n### LLM Audit Report:")
        results.append(llm_report)
    except Exception as e:
        results.append(f"\n[-] LLM Analysis failed: {e}")
        
    return "\n".join(results)



# ═══════════════════════════════════════════════════════════════════════════════
# RSA CTF Attack Suite
# ═══════════════════════════════════════════════════════════════════════════════

def _iroot(n, k):
    """Compute integer k-th root of n via Newton method. Returns (root, exact)."""
    if n == 0:
        return 0, True
    if k == 1:
        return n, True
    r = int(round(n ** (1 / k)))
    for _ in range(100):
        rk = r ** (k - 1)
        if rk == 0:
            break
        r1 = ((k - 1) * r + n // rk) // k
        if abs(r1 - r) <= 1:
            break
        r = r1
    while r ** k > n:
        r -= 1
    while (r + 1) ** k <= n:
        r += 1
    return r, r ** k == n


def _continued_fraction(num, den):
    """Compute continued fraction coefficients for num/den."""
    cf = []
    while den:
        q = num // den
        cf.append(q)
        num, den = den, num - q * den
    return cf


def _convergents(cf):
    """Compute (p, q) convergents from continued fraction coefficients."""
    convs = []
    if not cf:
        return convs
    p_prev, p_curr = 1, cf[0]
    q_prev, q_curr = 0, 1
    convs.append((p_curr, q_curr))
    for a in cf[1:]:
        p_prev, p_curr = p_curr, a * p_curr + p_prev
        q_prev, q_curr = q_curr, a * q_curr + q_prev
        convs.append((p_curr, q_curr))
    return convs


def _isqrt_exact(n):
    """Return (isqrt, is_perfect_square)."""
    import math
    r = math.isqrt(n)
    return r, r * r == n


@function_tool()
def rsa_attack(
    n: str,
    e: str = "65537",
    c: str = "",
    p: str = "",
    q: str = "",
) -> str:
    """
    Attempt common RSA CTF attacks to factor the modulus or decrypt ciphertext.

    Attacks tried (in order):
    1. Known p, q: Direct key recovery (instant)
    2. Small n trial division (factors < 10^6)
    3. Fermat factorization (works when p and q are close)
    4. Small exponent e=3 cube-root / Hastad broadcast attack
    5. Wiener's attack (small private exponent d via continued fractions)
    6. FactorDB.com lookup (known factorizations database)

    All pure Python - no third-party libraries required.

    Args:
        n: RSA modulus (decimal or 0x-prefixed hex string).
        e: Public exponent (default 65537).
        c: Ciphertext to decrypt (decimal or 0x-prefixed hex, optional).
        p: Known prime factor p (skips factoring if both p and q provided).
        q: Known prime factor q.

    Returns:
        Attack results, recovered factors, private key d, and decrypted plaintext.
    """
    import math
    import json
    import re
    import urllib.request
    import urllib.error

    def _parse_int(s, name):
        s = s.strip()
        if not s:
            return None
        try:
            return int(s, 0)
        except ValueError:
            try:
                return int(s, 16)
            except ValueError:
                raise ValueError(f"Cannot parse {name}={s!r} as integer")

    try:
        N = _parse_int(n, "n")
        E = _parse_int(e, "e") or 65537
        C = _parse_int(c, "c") if c.strip() else None
        P = _parse_int(p, "p") if p.strip() else None
        Q = _parse_int(q, "q") if q.strip() else None
    except ValueError as ve:
        return f"[rsa_attack] Input error: {ve}"

    if N is None:
        return "[rsa_attack] Error: modulus n is required"

    out = [
        "=" * 64,
        "              RSA CTF ATTACK SUITE",
        "=" * 64,
        f"  n = {n[:80]}{'...' if len(n) > 80 else ''}",
        f"  e = {E}",
        f"  c = {'(not provided)' if C is None else str(c)[:60]}",
        f"  n bit-length = {N.bit_length()} bits",
        "-" * 64,
    ]

    def _decrypt_with_factors(pp, qq):
        phi = (pp - 1) * (qq - 1)
        try:
            d = pow(E, -1, phi)
        except (ValueError, ZeroDivisionError):
            return f"  d recovery failed (gcd(e,phi)!=1)"
        lines = [f"  p = {pp}", f"  q = {qq}", f"  phi(n) = {phi}", f"  d = {d}"]
        if C is not None:
            m = pow(C, d, N)
            m_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")
            try:
                plaintext = m_bytes.decode("utf-8")
                lines.append(f"  plaintext (UTF-8) = {plaintext[:200]}")
            except UnicodeDecodeError:
                lines.append(f"  plaintext (hex) = {m_bytes.hex()[:200]}")
                lines.append(f"  plaintext (repr) = {repr(m_bytes)[:200]}")
            flag_hits = re.findall(r'[A-Z]{2,8}\{[^}]{3,60}\}|flag\{[^}]+\}',
                                   m_bytes.decode("utf-8", errors="replace"), re.IGNORECASE)
            if flag_hits:
                lines.append(f"  FLAG: {flag_hits[0]}")
        return "\n".join(lines)

    # Attack 1: Known factors
    if P and Q:
        out.append("\n[1] Known factors (p, q provided)")
        if P * Q == N:
            out.append("  PASS: p x q = n confirmed!")
            out.append(_decrypt_with_factors(P, Q))
            return "\n".join(out)
        else:
            out.append("  FAIL: p x q != n")

    # Attack 2: Trial division
    out.append("\n[2] Trial division (factors < 10^6)")
    limit = min(10**6, math.isqrt(N) + 1)
    found_p = None
    for i in range(2, limit):
        if N % i == 0:
            found_p = i
            break
    if found_p:
        found_q = N // found_p
        out.append("  PASS: Factored!")
        out.append(_decrypt_with_factors(found_p, found_q))
        return "\n".join(out)
    else:
        out.append(f"  FAIL: No factor < {limit:,}")

    # Attack 3: Fermat factorization
    out.append("\n[3] Fermat factorization (p approx q)")
    a = math.isqrt(N) + 1
    found_factor = None
    for i in range(50000):
        b2 = a * a - N
        if b2 >= 0:
            b, exact = _isqrt_exact(b2)
            if exact:
                found_factor = (a - b, a + b)
                break
        a += 1
    if found_factor and found_factor[0] * found_factor[1] == N and found_factor[0] > 1:
        out.append(f"  PASS: Fermat succeeded in {i+1} iterations!")
        out.append(_decrypt_with_factors(found_factor[0], found_factor[1]))
        return "\n".join(out)
    else:
        out.append("  FAIL: p and q not close enough")

    # Attack 4: Small exponent cube-root / Hastad
    if E <= 7 and C is not None:
        out.append(f"\n[4] Small exponent (e={E}) cube-root / Hastad broadcast")
        for k in range(5000):
            candidate = C + k * N
            r, exact = _iroot(candidate, E)
            if exact:
                m_bytes = r.to_bytes((r.bit_length() + 7) // 8, "big")
                plaintext = m_bytes.decode("utf-8", errors="replace")
                out.append(f"  PASS: k={k}, m^(1/e) is exact!")
                out.append(f"  plaintext = {plaintext[:200]}")
                flag_hits = re.findall(r'[A-Z]{2,8}\{[^}]{3,60}\}|flag\{[^}]+\}', plaintext, re.IGNORECASE)
                if flag_hits:
                    out.append(f"  FLAG: {flag_hits[0]}")
                return "\n".join(out)
        out.append(f"  FAIL: No perfect {E}-th root found")
    elif E <= 7:
        out.append(f"\n[4] Small exponent e={E} -- provide c= to attempt decryption")

    # Attack 5: Wiener's attack
    out.append("\n[5] Wiener's attack (small d via continued fractions)")
    cf = _continued_fraction(E, N)
    convs = _convergents(cf)
    wiener_found = False
    for k_w, d_w in convs:
        if k_w == 0:
            continue
        ed1 = E * d_w - 1
        if ed1 % k_w != 0:
            continue
        phi_c = ed1 // k_w
        b = N - phi_c + 1
        disc = b * b - 4 * N
        if disc < 0:
            continue
        sqrt_d, exact = _isqrt_exact(disc)
        if exact:
            pp = (b + sqrt_d) // 2
            qq = (b - sqrt_d) // 2
            if pp * qq == N and pp > 1 and qq > 1:
                out.append(f"  PASS: Wiener succeeded! d={d_w}")
                out.append(_decrypt_with_factors(pp, qq))
                return "\n".join(out)
    out.append("  FAIL: d is not small enough for Wiener's attack")

    # Attack 6: FactorDB
    out.append("\n[6] FactorDB.com lookup")
    try:
        url = f"http://factordb.com/api?query={N}"
        req = urllib.request.Request(url, headers={"User-Agent": "CTF-RSA-Tool/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        status = data.get("status", "")
        factors = data.get("factors", [])
        out.append(f"  FactorDB status: {status!r}")
        if status in ("FF", "P", "Prp") and factors:
            factor_list = []
            for fe in factors:
                if isinstance(fe, list):
                    prime_str, exp = fe[0], int(fe[1])
                    factor_list.extend([int(prime_str)] * exp)
                else:
                    factor_list.append(int(fe))
            out.append(f"  Factors: {factor_list}")
            if len(factor_list) == 2:
                out.append("  PASS: Fully factored!")
                out.append(_decrypt_with_factors(factor_list[0], factor_list[1]))
                return "\n".join(out)
            elif len(factor_list) > 2:
                out.append(f"  Multi-prime RSA ({len(factor_list)} factors)")
                phi_multi = 1
                for fac in factor_list:
                    phi_multi *= (fac - 1)
                try:
                    d_multi = pow(E, -1, phi_multi)
                    if C is not None:
                        m = pow(C, d_multi, N)
                        m_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")
                        out.append(f"  plaintext = {m_bytes.decode('utf-8', errors='replace')[:200]}")
                except Exception as me:
                    out.append(f"  Multi-prime decryption error: {me}")
        else:
            out.append(f"  FAIL: Not in FactorDB -- try: http://factordb.com/?query={N}")
    except Exception as fdb_e:
        out.append(f"  FAIL/ERROR: {fdb_e}")

    # Final summary
    out.append("\n" + "-" * 64)
    out.append("All automated attacks failed.")
    out.append(f"n is {N.bit_length()} bits. Recommendations:")
    if N.bit_length() < 512:
        out.append("  - Small n: try YAFU or MSIEVE")
    out.append("  - ctf_command('yafu \"factor(n)\"')")
    out.append("  - Check for common modulus attack (multiple ciphertexts, same n, different e)")
    out.append("  - Submit n to factordb.com manually")
    return "\n".join(out)
