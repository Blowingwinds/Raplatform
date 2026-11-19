"""Tests for environment-adaptive tool path resolution (决定 17)."""

from __future__ import annotations

import pytest

from src.agents.shared.tool_paths import TOOL_NAMES, resolve_tool


@pytest.fixture(autouse=True)
def _clear_cache():
    yield
    resolve_tool.cache_clear()


def test_known_tool_names():
    assert set(TOOL_NAMES) == {"nuclei", "subfinder", "ffuf", "sqlmap"}


def test_env_dir_priority_with_exe(tmp_path, monkeypatch):
    (tmp_path / "ffuf.exe").write_text("fake", encoding="utf-8")
    monkeypatch.setenv("RAPLATFORM_TOOLS_DIR", str(tmp_path))
    assert resolve_tool("ffuf") == str(tmp_path / "ffuf.exe")


def test_env_dir_bare_script(tmp_path, monkeypatch):
    # sqlmap may exist as a plain script without extension
    (tmp_path / "sqlmap").write_text("fake", encoding="utf-8")
    monkeypatch.setenv("RAPLATFORM_TOOLS_DIR", str(tmp_path))
    assert resolve_tool("sqlmap") == str(tmp_path / "sqlmap")


def test_env_dir_exe_wins_over_bare(tmp_path, monkeypatch):
    (tmp_path / "nuclei.exe").write_text("fake", encoding="utf-8")
    (tmp_path / "nuclei").write_text("fake", encoding="utf-8")
    monkeypatch.setenv("RAPLATFORM_TOOLS_DIR", str(tmp_path))
    assert resolve_tool("nuclei") == str(tmp_path / "nuclei.exe")


def test_env_dir_missing_returns_none(tmp_path, monkeypatch):
    # Deterministic mode: only the env dir is probed, no PATH fallback
    monkeypatch.setenv("RAPLATFORM_TOOLS_DIR", str(tmp_path))
    assert resolve_tool("nuclei") is None


def test_unknown_tool_raises():
    with pytest.raises(ValueError):
        resolve_tool("definitely-not-a-tool")


def test_caching_returns_same_path(tmp_path, monkeypatch):
    (tmp_path / "subfinder.exe").write_text("fake", encoding="utf-8")
    monkeypatch.setenv("RAPLATFORM_TOOLS_DIR", str(tmp_path))
    first = resolve_tool("subfinder")
    second = resolve_tool("subfinder")
    assert first == second
