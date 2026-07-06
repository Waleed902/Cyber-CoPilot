"""
Temp mail utilities for disposable inbox workflows.
Provider: 1secmail public API.
"""

from __future__ import annotations

import random
import asyncio
import time
import urllib.parse
from typing import Tuple

import requests

from src.sdk.tool import function_tool

_API_BASE = "https://www.1secmail.com/api/v1/"
_DOMAINS = [
    "1secmail.com",
    "1secmail.org",
    "1secmail.net",
    "wwjmp.com",
    "esiix.com",
    "xojxe.com",
    "yoggm.com",
]


def _parse_email(email: str) -> Tuple[str, str]:
    if not email or "@" not in email:
        raise ValueError("Invalid email format. Expected local@domain")
    local, domain = email.split("@", 1)
    local = local.strip()
    domain = domain.strip().lower()
    if not local or not domain:
        raise ValueError("Invalid email format. Expected local@domain")
    return local, domain


def _api_get(params: dict, timeout: int = 20):
    return requests.get(_API_BASE, params=params, timeout=timeout)


@function_tool()
def tempmail_generate_address(prefix: str = "cc", domain: str = "") -> str:
    """
    Generate a disposable email address for testing registration and email flows.

    Args:
        prefix: Local-part prefix for readability (default: cc)
        domain: Optional domain; if empty uses a random supported domain

    Returns:
        Disposable mailbox details and next-step commands
    """
    try:
        clean_prefix = "".join(ch for ch in (prefix or "cc") if ch.isalnum())[:16] or "cc"
        local = f"{clean_prefix}{random.randint(1000, 999999)}"
        chosen_domain = (domain or "").strip().lower() or random.choice(_DOMAINS)
        if chosen_domain not in _DOMAINS:
            return (
                "Error: Unsupported tempmail domain. "
                f"Use one of: {', '.join(_DOMAINS)}"
            )

        mailbox = f"{local}@{chosen_domain}"
        return (
            "[TEMPMAIL GENERATED]\n"
            f"email: {mailbox}\n"
            f"local: {local}\n"
            f"domain: {chosen_domain}\n\n"
            "Next steps:\n"
            f"- Use this email in registration flows\n"
            f"- Poll inbox with: tempmail_list_messages('{mailbox}')\n"
            f"- Read a message with: tempmail_read_message('{mailbox}', <id>)"
        )
    except Exception as e:
        return f"Error generating tempmail address: {e}"


@function_tool()
def tempmail_list_messages(email: str) -> str:
    """
    List inbox messages for a disposable email address.

    Args:
        email: Disposable mailbox address (local@domain)

    Returns:
        Message list with IDs, sender, subject, and date
    """
    try:
        login, domain = _parse_email(email)
        resp = _api_get({"action": "getMessages", "login": login, "domain": domain})
        if resp.status_code != 200:
            return f"Error: provider returned HTTP {resp.status_code}"
        messages = resp.json() or []
        if not messages:
            return f"No messages yet for {email}."

        lines = [f"[TEMPMAIL INBOX] {email}"]
        for msg in messages:
            lines.append(
                f"id={msg.get('id')} | from={msg.get('from')} | subject={msg.get('subject')} | date={msg.get('date')}"
            )
        return "\n".join(lines)
    except Exception as e:
        return f"Error listing tempmail messages: {e}"


@function_tool()
def tempmail_read_message(email: str, message_id: int) -> str:
    """
    Read a specific message from a disposable inbox.

    Args:
        email: Disposable mailbox address (local@domain)
        message_id: Message ID returned by tempmail_list_messages

    Returns:
        Message details including body text/html and links
    """
    try:
        login, domain = _parse_email(email)
        resp = _api_get(
            {
                "action": "readMessage",
                "login": login,
                "domain": domain,
                "id": int(message_id),
            }
        )
        if resp.status_code != 200:
            return f"Error: provider returned HTTP {resp.status_code}"

        msg = resp.json() or {}
        subject = msg.get("subject", "")
        sender = msg.get("from", "")
        date = msg.get("date", "")
        text_body = msg.get("textBody", "") or ""
        html_body = msg.get("htmlBody", "") or ""

        links = []
        body_for_links = f"{text_body}\n{html_body}"
        for token in body_for_links.split():
            if token.startswith("http://") or token.startswith("https://"):
                links.append(token.strip("'\"()[]<>.,;"))

        unique_links = []
        seen = set()
        for link in links:
            norm = urllib.parse.urlsplit(link).geturl()
            if norm not in seen:
                seen.add(norm)
                unique_links.append(norm)

        out = [
            f"[TEMPMAIL MESSAGE] {email}",
            f"id: {message_id}",
            f"from: {sender}",
            f"subject: {subject}",
            f"date: {date}",
            "",
            "--- textBody ---",
            text_body[:12000],
            "",
            "--- htmlBody ---",
            html_body[:12000],
        ]
        if unique_links:
            out.append("")
            out.append("--- extracted_links ---")
            out.extend(unique_links[:50])

        return "\n".join(out)
    except Exception as e:
        return f"Error reading tempmail message: {e}"


@function_tool()
async def tempmail_wait_for_message(email: str, timeout_seconds: int = 90, poll_interval_seconds: int = 5) -> str:
    """
    Poll a disposable inbox until a message arrives or timeout is reached.

    Args:
        email: Disposable mailbox address (local@domain)
        timeout_seconds: Max wait time (default: 90)
        poll_interval_seconds: Poll interval (default: 5)

    Returns:
        First message summary or timeout notice
    """
    try:
        deadline = time.time() + max(1, int(timeout_seconds))
        interval = max(1, int(poll_interval_seconds))

        while time.time() < deadline:
            listing = await tempmail_list_messages(email)
            if listing.startswith("[TEMPMAIL INBOX]"):
                # Parse first id from listing lines
                for line in listing.splitlines()[1:]:
                    if line.startswith("id="):
                        first_id = line.split("|", 1)[0].split("=", 1)[1].strip()
                        return (
                            "Message received.\n"
                            f"{line}\n\n"
                            f"Read it with: tempmail_read_message('{email}', {first_id})"
                        )
            await asyncio.sleep(interval)

        return f"Timeout waiting for message on {email}."
    except Exception as e:
        return f"Error waiting for tempmail message: {e}"
