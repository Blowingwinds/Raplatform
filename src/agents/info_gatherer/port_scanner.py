"""TCP port scanner using asyncio — no admin rights needed."""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field

_BANNER_PROBES: dict[int, bytes] = {
    21: b"\r\n", 22: b"\r\n", 25: b"\r\n",
    80: b"GET / HTTP/1.0\r\nHost: {target}\r\n\r\n",
    110: b"\r\n", 143: b"\r\n", 443: b"", 445: b"", 3306: b"", 3389: b"",
    5432: b"", 6379: b"PING\r\n",
    8080: b"GET / HTTP/1.0\r\nHost: {target}\r\n\r\n", 8443: b"", 27017: b"",
}

_COMMON_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios", 143: "imap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 1723: "pptp", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 9090: "http-alt",
    27017: "mongodb", 5000: "http-alt",
}

TOP_PORTS: list[int] = sorted(_COMMON_SERVICES.keys() | {
    7, 9, 13, 17, 19, 20, 37, 42, 43, 49, 67, 68, 69, 70, 79,
    81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 113, 119,
    123, 137, 138, 146, 161, 162, 179, 199, 211, 212, 220,
    280, 389, 427, 444, 464, 465, 500, 512, 513, 514,
    515, 524, 541, 543, 544, 548, 554, 563, 587, 593, 631, 636,
    646, 691, 873, 902, 989, 990, 1025, 1026, 1027,
    1080, 1194, 1241, 1433, 1434, 1521, 1701, 1720, 1755,
    1812, 1813, 1883, 1900, 2000, 2049, 2082, 2083, 2086, 2087,
    2095, 2096, 2100, 2222, 2301, 2483, 2484, 3000, 3001, 3128,
    3260, 3283, 3478, 3632, 3690, 4000, 4100, 4369, 4444,
    4567, 4662, 4899, 5001, 5050, 5060, 5190, 5222, 5353,
    5555, 5631, 5666, 5672, 5800, 5900, 5984, 6000, 6082,
    6666, 6881, 7000, 7070, 7443, 7777, 8000, 8008, 8009,
    8081, 8088, 8888, 9000, 9200, 9300, 9999,
    10000, 11211, 27018, 27019, 28017, 50000, 50030, 50060,
})


@dataclass
class PortResult:
    port: int
    open: bool
    service: str = "unknown"
    banner: str = ""


async def _scan_one_port(target: str, port: int, timeout: float = 2.0) -> PortResult:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port), timeout=timeout,
        )
        service = _COMMON_SERVICES.get(port, "unknown")
        banner = ""

        probe_template = _BANNER_PROBES.get(port)
        if probe_template and probe_template != b"":
            try:
                probe = (
                    probe_template.replace(b"{target}", target.encode())
                    if b"{target}" in probe_template
                    else probe_template
                )
                writer.write(probe)
                await writer.drain()
                banner_bytes = await asyncio.wait_for(
                    writer.read(1024), timeout=1.5,
                )
                banner = banner_bytes.decode("utf-8", errors="replace")[:200]
            except Exception:
                pass

        writer.close()
        await writer.wait_closed()
        return PortResult(port=port, open=True, service=service, banner=banner)

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return PortResult(port=port, open=False)


async def scan_ports(
    target: str,
    ports: list[int] | None = None,
    *,
    concurrency: int = 100,
    timeout: float = 2.0,
) -> list[dict]:
    if ports is None:
        ports = TOP_PORTS

    sem = asyncio.Semaphore(concurrency)

    async def _limited(port: int) -> PortResult:
        async with sem:
            return await _scan_one_port(target, port, timeout=timeout)

    results = await asyncio.gather(*(_limited(p) for p in ports))
    open_ports = [r for r in results if r.open]

    return [
        {"port": r.port, "service": r.service, "banner": r.banner[:200] if r.banner else ""}
        for r in open_ports
    ][:200]