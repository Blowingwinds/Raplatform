"""DNS resolution and subdomain enumeration tools."""

from __future__ import annotations

import asyncio
from pathlib import Path

import dns.resolver
import httpx

_SUBFINDER_PATH = "C:/Users/ASUS/go/bin/subfinder.exe"


async def resolve_dns(hostname: str, record_types: list[str] | None = None) -> list[dict]:
    if record_types is None:
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]

    results: list[dict] = []
    for rtype in record_types:
        try:
            answers = await asyncio.to_thread(dns.resolver.resolve, hostname, rtype)
            for answer in answers:
                results.append({"type": rtype, "hostname": hostname, "value": str(answer)})
        except Exception:
            continue
    return results[:50]


async def enumerate_subdomains(domain: str) -> list[dict]:
    subdomains: list[str] = []
    subfinder_path = Path(_SUBFINDER_PATH)
    if subfinder_path.exists():
        try:
            proc = await asyncio.create_subprocess_exec(
                str(subfinder_path), "-d", domain, "-silent",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60.0)
            subdomains = [line.strip() for line in stdout.decode().splitlines() if line.strip()]
        except Exception:
            pass

    if not subdomains:
        return []

    sem = asyncio.Semaphore(50)
    results: list[dict] = []

    async def _check(sub: str) -> None:
        async with sem:
            try:
                answers = await asyncio.to_thread(dns.resolver.resolve, sub, "A")
                ips = [str(a) for a in answers]
            except Exception:
                return
            try:
                async with httpx.AsyncClient(timeout=8.0) as client:
                    resp = await client.get(f"http://{sub}", follow_redirects=True)
                    results.append({"hostname": sub, "ips": ips, "http_status": resp.status_code})
            except Exception:
                try:
                    async with httpx.AsyncClient(timeout=8.0) as client:
                        resp = await client.get(f"https://{sub}", follow_redirects=True)
                        results.append({"hostname": sub, "ips": ips, "http_status": resp.status_code})
                except Exception:
                    results.append({"hostname": sub, "ips": ips})

    await asyncio.gather(*(_check(s) for s in subdomains))
    return results[:200]