"""Sqlmap wrapper for SQL injection verification."""

from __future__ import annotations

import asyncio
import json
import re
import tempfile
from pathlib import Path

_SQLMAP_PATH = "E:/PTtools/sqlmap.exe"


async def verify_sqli(url: str, timeout: float = 600.0) -> dict | None:
    """Run sqlmap against *url* and return structured results.

    Returns None if no SQL injection is found.
    """
    sqlmap_path = Path(_SQLMAP_PATH)
    if not sqlmap_path.exists():
        return None

    # SQLmap writes to a temp file (--batch + --output-dir)
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            proc = await asyncio.create_subprocess_exec(
                "python", str(sqlmap_path),
                "-u", url,
                "--batch",
                "--risk", "2",
                "--level", "3",
                "--technique", "BEUSTQ",
                "--dbs",
                "--output-dir", tmpdir,
                "--flush-session",
                "--random-agent",
                "--timeout", "30",
                "--retries", "1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
        except asyncio.TimeoutError:
            return {
                "url": url,
                "injectable": False,
                "error": "timeout",
                "databases": [],
                "technique": None,
            }

    output = stdout.decode(errors="replace")
    stderr_str = stderr.decode(errors="replace")

    # Parse sqlmap output for key indicators
    injectable = _is_injectable(output)
    databases = _extract_databases(output)
    technique = _extract_technique(output)

    if not injectable:
        return {
            "url": url,
            "injectable": False,
            "databases": [],
            "technique": None,
            "raw": output[-2000:],
        }

    return {
        "url": url,
        "injectable": True,
        "technique": technique,
        "databases": databases,
        "verified": len(databases) > 0,
        "raw": output[-2000:],
    }


def _is_injectable(output: str) -> bool:
    markers = [
        "is vulnerable",
        "sqlmap identified the following injection point",
        "the back-end DBMS is",
        "Type: ",
        "payload:",
    ]
    return any(m.lower() in output.lower() for m in markers)


def _extract_technique(output: str) -> str | None:
    match = re.search(r"Type:\s*(.+?)(?:\n|$)", output)
    if match:
        return match.group(1).strip()
    return None


def _extract_databases(output: str) -> list[str]:
    """Extract database names from `--dbs` output."""
    dbs: list[str] = []
    in_dbs = False
    for line in output.splitlines():
        line = line.strip()
        if "available databases" in line.lower():
            in_dbs = True
            continue
        if in_dbs:
            if line.startswith("[*]") and "databases" not in line.lower():
                dbs.append(line.replace("[*]", "").strip())
            if line.startswith("[") and line.endswith("]"):
                # Start of next section
                break
    return dbs[:20]