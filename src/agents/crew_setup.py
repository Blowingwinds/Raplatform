"""CrewAI integration — Hive model (Queen Bee + Worker Bees).

The ``HiveOrchestrator`` is the main entry point for the penetration testing
lifecycle.  It reads the blackboard, dispatches worker bee crews, and loops
until completion.

For backward compatibility, ``build_red_team_crew()`` is kept as a deprecated
shim that returns a single sequential Crew with the three vulnerability agents.
New code should use ``HiveOrchestrator`` directly.
"""

from __future__ import annotations

import warnings

from crewai import Agent, Crew, Process, Task

from src.agents.hive.orchestrator import HiveOrchestrator, HiveRunSummary
from src.agents.hive.phases import HivePhase
from src.domain.storage import SQLiteStore

__all__ = [
    "HiveOrchestrator",
    "HivePhase",
    "HiveRunSummary",
    "build_red_team_crew",
]


# ── deprecated shim ─────────────────────────────────────────────────────

def build_red_team_crew(
    store: SQLiteStore,
    llm_model: str = "gpt-4o",
    verbose: bool = False,
) -> Crew:
    """Deprecated — use ``HiveOrchestrator`` instead.

    Returns a single sequential Crew with the three vulnerability-detection
    agents (framework, web, component).  No blackboard integration, no gateway
    security layer, no dynamic task creation.
    """
    warnings.warn(
        "build_red_team_crew is deprecated; use HiveOrchestrator instead",
        DeprecationWarning,
        stacklevel=2,
    )

    # Minimal inline agent definitions for backward compat
    framework_agent = Agent(
        role="Framework Vulnerability Specialist",
        goal="Detect vulnerabilities in web frameworks and runtimes.",
        backstory="Veteran framework security researcher.",
        llm=llm_model,
        verbose=verbose,
        allow_delegation=False,
    )

    web_agent = Agent(
        role="Web Attack Specialist",
        goal="Find and verify common web vulnerabilities.",
        backstory="Battle-hardened web penetration tester.",
        llm=llm_model,
        verbose=verbose,
        allow_delegation=False,
    )

    component_agent = Agent(
        role="Component & Plugin Vulnerability Specialist",
        goal="Detect vulnerabilities in third-party components and services.",
        backstory="Software supply chain security expert.",
        llm=llm_model,
        verbose=verbose,
        allow_delegation=False,
    )

    return Crew(
        agents=[framework_agent, web_agent, component_agent],
        tasks=[],
        process=Process.sequential,
        verbose=verbose,
    )