"""WAF bypass strategy variants — for candidates blocked by WAF.

Each variant produces a modified request. Results are recorded as Evidence;
bypass success is NOT taken as vulnerability confirmation.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field


@dataclass
class BypassAttempt:
    strategy: str
    modified_payload: str
    modified_url: str
    modified_headers: dict[str, str] = field(default_factory=dict)
    modified_method: str | None = None
    modified_body: str | None = None


STRATEGIES = [
    "url_encode",
    "double_url_encode",
    "case_swap",
    "comment_insert",
    "param_pollution",
    "method_switch",
    "ua_spoof",
]


def generate_variants(
    url: str,
    payload: str,
    param: str | None = None,
    method: str = "GET",
    body: str | None = None,
) -> list[BypassAttempt]:
    """Generate WAF bypass variants for a blocked payload."""
    variants: list[BypassAttempt] = []

    # 1. URL encoding variant
    variants.append(BypassAttempt(
        strategy="url_encode",
        modified_payload=urllib.parse.quote(payload),
        modified_url=_replace_param(url, param, urllib.parse.quote(payload)),
    ))

    # 2. Double URL encoding
    double_encoded = urllib.parse.quote(urllib.parse.quote(payload))
    variants.append(BypassAttempt(
        strategy="double_url_encode",
        modified_payload=double_encoded,
        modified_url=_replace_param(url, param, double_encoded),
    ))

    # 3. Case swapping
    case_swapped = _case_swap(payload)
    variants.append(BypassAttempt(
        strategy="case_swap",
        modified_payload=case_swapped,
        modified_url=_replace_param(url, param, case_swapped),
    ))

    # 4. Comment insertion
    commented = _insert_comments(payload)
    variants.append(BypassAttempt(
        strategy="comment_insert",
        modified_payload=commented,
        modified_url=_replace_param(url, param, urllib.parse.quote(commented)),
    ))

    # 5. HTTP parameter pollution
    if param:
        polluted_url = url + ("&" if "?" in url else "?") + f"{param}=1"
        variants.append(BypassAttempt(
            strategy="param_pollution",
            modified_payload=payload,
            modified_url=polluted_url,
        ))

    # 6. Method switch (GET→POST)
    if method.upper() == "GET" and param and body is None:
        variants.append(BypassAttempt(
            strategy="method_switch",
            modified_payload=payload,
            modified_url=url.split("?")[0],
            modified_method="POST",
            modified_body=f"{param}={urllib.parse.quote(payload)}",
            modified_headers={"Content-Type": "application/x-www-form-urlencoded"},
        ))

    # 7. User-Agent spoof
    variants.append(BypassAttempt(
        strategy="ua_spoof",
        modified_payload=payload,
        modified_url=url,
        modified_headers={
            "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        },
    ))

    return variants


def _replace_param(url: str, param: str | None, value: str) -> str:
    if param is None:
        return url
    # Replace param=OLD with param=VALUE
    import re
    pattern = rf"({re.escape(param)}=)([^&\s#]*)"
    return re.sub(pattern, rf"\g<1>{value}", url)


def _case_swap(s: str) -> str:
    result = []
    upper = False
    for ch in s:
        if ch.isalpha():
            result.append(ch.upper() if upper else ch.lower())
            upper = not upper
        else:
            result.append(ch)
    return "".join(result)


def _insert_comments(s: str) -> str:
    """Insert inline comments in SQL-like payloads."""
    # Naive but effective: insert /**/ around operators
    for op in [" OR ", " AND ", " UNION ", "SELECT ", " FROM "]:
        if op.upper() in s.upper():
            inner = op.strip()
            replaced = f"/**/{inner}/**/"
            return s.replace(op, f" {replaced} ", 1)
    return s