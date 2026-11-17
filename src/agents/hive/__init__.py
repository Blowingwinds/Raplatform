"""Hive model — Queen Bee + Worker Bees penetration testing orchestrator.

Exports:
    HiveOrchestrator — the main entry point for the hive loop.
    HivePhase — phase enum.
    HiveRunSummary — result of a complete hive run.
    CrewContext — shared context for one crew execution.
    FakeCrewRunner — test runner that bypasses the LLM.
"""

from src.agents.hive.crews import CrewContext, FakeCrewRunner
from src.agents.hive.orchestrator import HiveOrchestrator, HiveRunSummary
from src.agents.hive.phases import HivePhase

__all__ = [
    "CrewContext",
    "FakeCrewRunner",
    "HiveOrchestrator",
    "HivePhase",
    "HiveRunSummary",
]