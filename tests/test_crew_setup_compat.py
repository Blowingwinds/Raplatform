"""Backward-compatibility test for deprecated build_red_team_crew."""

import warnings

import pytest

from src.agents.crew_setup import build_red_team_crew
from src.domain.storage import SQLiteStore


@pytest.fixture
def store():
    s = SQLiteStore(":memory:")
    yield s
    s.close()


class TestBackwardCompat:
    def test_build_red_team_crew_returns_crew(self, store):
        """The deprecated function still returns a Crew with 3 agents."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            crew = build_red_team_crew(store, llm_model="gpt-4o")

            # Should emit DeprecationWarning
            deprecation_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecation_warnings) >= 1

        # Should return a Crew object
        from crewai import Crew
        assert isinstance(crew, Crew)

        # Should have 3 agents
        assert len(crew.agents) == 3
        roles = {a.role for a in crew.agents}
        assert "Framework Vulnerability Specialist" in roles
        assert "Web Attack Specialist" in roles
        assert "Component & Plugin Vulnerability Specialist" in roles

    def test_build_red_team_crew_uses_sequential(self, store):
        """The deprecated crew uses Process.sequential."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            crew = build_red_team_crew(store)

        from crewai import Process
        assert crew.process == Process.sequential

    def test_build_red_team_crew_tasks_empty(self, store):
        """The deprecated crew has no tasks (caller adds them)."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            crew = build_red_team_crew(store)

        assert crew.tasks == []


class TestHiveImports:
    def test_hive_orchestrator_importable(self):
        from src.agents.crew_setup import HiveOrchestrator, HivePhase, HiveRunSummary
        assert HiveOrchestrator is not None
        assert HivePhase is not None
        assert HiveRunSummary is not None

    def test_hive_package_exports(self):
        from src.agents.hive import (
            CrewContext,
            FakeCrewRunner,
            HiveOrchestrator,
            HivePhase,
            HiveRunSummary,
        )
        assert all([CrewContext, FakeCrewRunner, HiveOrchestrator,
                    HivePhase, HiveRunSummary])