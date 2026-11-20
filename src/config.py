"""Runtime configuration — .env loading and LLM provider settings.

The project deliberately keeps zero extra dependencies: ``.env`` is parsed with
a tiny reader instead of python-dotenv.

Environment variables (all optional unless noted):

    RAPLATFORM_LLM_BASE_URL   OpenAI-compatible base URL (required for LLM provider)
    RAPLATFORM_LLM_API_KEY    API key (required for LLM provider)
    RAPLATFORM_LLM_MODEL      Model name (required for LLM provider)
    RAPLATFORM_LLM_TIMEOUT    Request timeout in seconds (default 120)
    RAPLATFORM_LLM_TEMPERATURE  Sampling temperature (default 0.2)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ENV_FILE = _PROJECT_ROOT / ".env"

_loaded = False


def load_dotenv(path: Path | None = None) -> None:
    """Parse ``KEY=VALUE`` lines from ``.env`` into ``os.environ`` (no overwrite).

    Idempotent: runs at most once per process.  Existing environment variables
    always win, so CI/shell overrides keep working.
    """
    global _loaded
    if _loaded:
        return
    _loaded = True

    env_path = path or _ENV_FILE
    if not env_path.is_file():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


@dataclass(frozen=True)
class LLMConfig:
    """Settings for an OpenAI-compatible Chat Completions endpoint."""

    base_url: str
    api_key: str
    model: str
    timeout: float = 120.0
    temperature: float = 0.2

    @property
    def chat_url(self) -> str:
        return self.base_url.rstrip("/") + "/chat/completions"

    def describe(self) -> str:
        """Human-readable summary with the key masked."""
        masked = (self.api_key[:6] + "…" + self.api_key[-4:]) if len(self.api_key) > 12 else "***"
        return f"{self.model} @ {self.base_url} (key={masked})"


def get_llm_config() -> LLMConfig | None:
    """Return LLM settings, or None when any of the three required vars is missing."""
    load_dotenv()

    base_url = os.environ.get("RAPLATFORM_LLM_BASE_URL", "").strip()
    api_key = os.environ.get("RAPLATFORM_LLM_API_KEY", "").strip()
    model = os.environ.get("RAPLATFORM_LLM_MODEL", "").strip()

    if not (base_url and api_key and model):
        return None
    if api_key == "sk-your-key-here":
        # Template value left untouched — treat as unconfigured.
        return None

    try:
        timeout = float(os.environ.get("RAPLATFORM_LLM_TIMEOUT", "120"))
    except ValueError:
        timeout = 120.0
    try:
        temperature = float(os.environ.get("RAPLATFORM_LLM_TEMPERATURE", "0.2"))
    except ValueError:
        temperature = 0.2

    return LLMConfig(
        base_url=base_url,
        api_key=api_key,
        model=model,
        timeout=timeout,
        temperature=temperature,
    )