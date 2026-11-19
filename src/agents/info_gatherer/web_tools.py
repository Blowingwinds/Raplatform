"""Web endpoint discovery via ffuf."""

from __future__ import annotations

import asyncio
import json
import re
import tempfile
from pathlib import Path

from src.agents.shared.tool_paths import resolve_tool

_WORDLIST: list[str] = [
    "admin", "api", "login", "robots.txt", "sitemap.xml",
    ".git/config", ".env", "backup", "config", "dashboard",
    "debug", "docs", "download", "uploads", "test", "dev",
    "status", "version", "swagger", "openapi.json", "graphql",
    "console", "phpinfo.php", "info.php", "wp-admin",
    "administrator", "panel", "manager", ".svn/entries",
    "actuator", "actuator/health", "actuator/env",
    "static", "assets", "css", "js", "images",
    ".htaccess", "web.config", "server-status",
    "wp-content", "wp-includes", "wp-json/",
    "phpmyadmin", "jenkins", "sonarqube",
    "api/v1", "api/v2", "api/docs",
    "products", "product", "items", "item", "detail", "view",
    "search", "comments", "comment", "news", "articles",
    "users", "user", "profile", "account", "register", "reset",
    "cart", "checkout", "orders", "upload", "download",
    "settings", "edit", "delete", "list", "page", "index", "home",
    "exec", "shell", "cmd",
]

# Plain-text ffuf output: "name                   [Status: 200, Size: 123, ...]"
_FFUF_TEXT_RE = re.compile(
    r"^(?P<name>\S+)\s+\[Status:\s*(?P<status>\d+),\s*Size:\s*(?P<size>\d+)",
)


async def discover_endpoints(base_url: str, wordlist: list[str] | None = None) -> list[dict]:
    ffuf_path = resolve_tool("ffuf")
    if ffuf_path is None:
        return []

    wl = wordlist or _WORDLIST
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8",
    ) as f:
        f.write("\n".join(wl))
        wordlist_path = f.name

    try:
        proc = await asyncio.create_subprocess_exec(
            ffuf_path,
            "-u", f"{base_url.rstrip('/')}/FUZZ",
            "-w", wordlist_path,
            "-mc", "200-299,301,302,307,401,405,500",
            "-maxtime", "60", "-noninteractive",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=90.0)
    except asyncio.TimeoutError:
        return []
    finally:
        Path(wordlist_path).unlink(missing_ok=True)

    results: list[dict] = []
    seen_lengths: set[int] = set()

    for line in stdout.decode(errors="replace").splitlines():
        if not line.strip():
            continue

        # Try JSON first (ffuf v2.3+ with -of json)
        if line.strip().startswith("{"):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = entry.get("url", "")
            status = entry.get("status", 0)
            content_length = entry.get("length", 0)
        else:
            # Plain text (ffuf v2.1 without -of json)
            m = _FFUF_TEXT_RE.search(line)
            if not m:
                continue
            name = m.group("name")
            status = int(m.group("status"))
            content_length = int(m.group("size"))
            url = f"{base_url.rstrip('/')}/{name}"

        if status in (404, 403, 0):
            continue
        if content_length in seen_lengths:
            continue
        seen_lengths.add(content_length)

        results.append({"url": url, "status": status, "length": content_length})

    return results[:100]