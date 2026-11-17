"""``python -m src`` entry point — works without ``pip install``."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure src/ is importable without pip install
_src_dir = Path(__file__).resolve().parent
if str(_src_dir) not in sys.path:
    sys.path.insert(0, str(_src_dir))

from cli.main import main

if __name__ == "__main__":
    main()