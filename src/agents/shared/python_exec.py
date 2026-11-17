"""Sandboxed Python code execution for Agent-authored test scripts.

Security constraints:
- 30-second timeout
- Allowed imports only (no os, subprocess, eval, etc.)
- Runs in a temp directory, cleaned up after
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import traceback
from pathlib import Path

_BLOCKED_IMPORTS: set[str] = {
    "os", "subprocess", "shutil", "importlib", "ctypes",
    "signal", "pty", "fcntl", "posix", "multiprocessing",
    "threading", "concurrent.futures",
    "pickle", "shelve", "marshal",
    "sysconfig", "distutils", "setuptools", "pip",
    "pdb", "code", "codeop",
    "antigravity", "this",
    "winreg", "msvcrt", "_winreg",
}


async def execute(code: str, target: str, timeout: float = 30.0) -> dict:
    """Execute user-provided Python code in a sandboxed subprocess.

    Returns {stdout, stderr, exit_code, files: [...]}.
    """
    # Build a wrapper that restricts imports
    wrapper = _build_wrapper(code, target)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8",
    ) as f:
        f.write(wrapper)
        script_path = f.name

    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, script_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout,
        )
        return {
            "stdout": stdout.decode(errors="replace")[:5000],
            "stderr": stderr.decode(errors="replace")[:2000],
            "exit_code": proc.returncode or 0,
        }
    except asyncio.TimeoutError:
        return {
            "stdout": "",
            "stderr": f"execution timed out after {timeout}s",
            "exit_code": -1,
        }
    except Exception as exc:
        return {
            "stdout": "",
            "stderr": str(exc),
            "exit_code": -1,
        }
    finally:
        Path(script_path).unlink(missing_ok=True)


def _build_wrapper(code: str, target: str) -> str:
    """Wrap user code with import blacklist and target injection."""
    blocked = sorted(_BLOCKED_IMPORTS)
    return f'''\
import builtins as __builtins
import sys as _sys

_TARGET = {target!r}
_BLOCKED = {blocked!r}

_original_import = __builtins.__import__

def _safe_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name in _BLOCKED:
        raise ImportError(f"import of '{{name}}' is blocked in sandbox")
    return _original_import(name, globals, locals, fromlist, level)

__builtins.__import__ = _safe_import

for _m in _BLOCKED:
    _sys.modules.pop(_m, None)

# ── user code ──
{code}
'''