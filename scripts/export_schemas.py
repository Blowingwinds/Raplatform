"""Export stable JSON Schemas for the domain contracts."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.domain.models import (
    AgentCapability,
    AuditEvent,
    BlackboardEvent,
    BlackboardFact,
    Evidence,
    ExecutionSession,
    Lease,
    Project,
    Scope,
    TaskNode,
)


SCHEMAS = {
    "task-node": TaskNode,
    "agent-capability": AgentCapability,
    "blackboard-fact": BlackboardFact,
    "blackboard-event": BlackboardEvent,
    "evidence": Evidence,
    "project": Project,
    "scope": Scope,
    "execution-session": ExecutionSession,
    "lease": Lease,
    "audit-event": AuditEvent,
}


def main() -> None:
    output_dir = Path("schemas")
    output_dir.mkdir(exist_ok=True)
    for name, model in SCHEMAS.items():
        path = output_dir / f"{name}.schema.json"
        path.write_text(json.dumps(model.model_json_schema(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
