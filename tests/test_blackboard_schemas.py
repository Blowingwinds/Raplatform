import json
from pathlib import Path

from src.domain.models import AgentObservation, BlackboardEvent, BlackboardFact


def test_blackboard_contract_schemas_match_models():
    root = Path(__file__).resolve().parents[1] / "schemas"
    for name, model in {
        "agent-observation": AgentObservation,
        "blackboard-event": BlackboardEvent,
        "blackboard-fact": BlackboardFact,
    }.items():
        actual = json.loads((root / f"{name}.schema.json").read_text(encoding="utf-8"))
        assert actual == model.model_json_schema()
