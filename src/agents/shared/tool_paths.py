"""Tool path resolution — environment-adaptive discovery (决定 17).

Resolves external tool executables without hardcoded machine-specific paths.

Priority:
1. ``RAPLATFORM_TOOLS_DIR`` environment variable — if set, ONLY that directory
   is probed (deterministic mode, skips PATH fallback).
2. Candidate directories probed in order (both dev machines + generic spots).
3. ``shutil.which()`` fallback on PATH.

Returns ``None`` when a tool is unavailable; callers keep their existing
degrade behavior (skip the tool and return empty results).
"""

from __future__ import annotations

import os
import shutil
import sys
from functools import lru_cache
from pathlib import Path

TOOL_NAMES = ("nuclei", "subfinder", "ffuf", "sqlmap")

# Candidate directories probed in order when no env override is set.
# Covers the two dev machines (C:/PTools and ASUS Go/Python setups) plus
# generic per-user locations.
_CANDIDATE_DIRS: tuple[str, ...] = (
    "C:/PTools",
    "C:/Users/ASUS/go/bin",
    "D:/python/Scripts",
)


def _env_dir() -> str | None:
    return os.environ.get("RAPLATFORM_TOOLS_DIR") or None


def _candidate_dirs() -> list[Path]:
    env = _env_dir()
    if env:
        return [Path(env)]
    dirs = [Path(p) for p in _CANDIDATE_DIRS]
    dirs.append(Path(os.path.expanduser("~/go/bin")))
    # pip console-scripts directory next to the running interpreter
    dirs.append(Path(sys.executable).resolve().parent / "Scripts")
    return dirs


@lru_cache(maxsize=None)
def resolve_tool(name: str) -> str | None:
    """Return an existing executable path for *name*, or None if unavailable.

    Windows note: both ``<name>.exe`` and bare ``<name>`` are probed, since
    Go binaries carry ``.exe`` while sqlmap may exist as a plain script.
    """
    if name not in TOOL_NAMES:
        raise ValueError(f"unknown tool: {name}")

    for d in _candidate_dirs():
        for candidate in (d / f"{name}.exe", d / name):
            if candidate.is_file():
                return str(candidate)

    # PATH fallback — skipped in deterministic env mode
    if _env_dir() is None:
        found = shutil.which(name) or shutil.which(f"{name}.exe")
        if found:
            return found
    return None
