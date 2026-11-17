"""Convert structured Agent observations into stable blackboard facts."""

import hashlib
import json

from src.domain.models import AgentObservation, BlackboardFact, Evidence


IDENTITY_FIELDS: dict[str, tuple[str, ...]] = {
    "asset.discovered": ("ip",),
    "subdomain.discovered": ("hostname",),
    "service.exposed": ("protocol", "port"),
    "network.relation": ("relation", "peer_ref"),
    "vulnerability.detected": ("vulnerability_id", "service_ref"),
    "credential.validated": ("credential_type", "principal", "credential", "service_ref"),
}


def normalize_observations(evidence: Evidence) -> list[BlackboardFact]:
    raw_observations = evidence.raw_payload.get("observations")
    if not isinstance(raw_observations, list):
        raise ValueError("agent result requires an observations list")

    facts: list[BlackboardFact] = []
    for raw_observation in raw_observations:
        observation = AgentObservation.model_validate(raw_observation)
        if observation.fact_type == "service.exposed":
            if "protocol" in observation.data:
                protocol = observation.data["protocol"]
                if not isinstance(protocol, str):
                    raise ValueError("invalid service protocol")
                observation.data["protocol"] = protocol.strip().lower()
            if "port" in observation.data:
                raw_port = observation.data["port"]
                if isinstance(raw_port, bool) or not str(raw_port).isdigit():
                    raise ValueError("invalid service port")
                port = int(raw_port)
                if not 1 <= port <= 65535:
                    raise ValueError("invalid service port")
                observation.data["port"] = port
        fields = IDENTITY_FIELDS.get(observation.fact_type)
        if fields is None:
            identity = observation.identity
            if not identity:
                raise ValueError(f"fact type {observation.fact_type} requires identity fields")
        else:
            identity = {}
            for field in fields:
                value = observation.data.get(field)
                if value is None or value == "":
                    raise ValueError(f"missing identity field: {field}")
                identity[field] = value

        key = json.dumps(
            [evidence.project_id, observation.fact_type, observation.asset_ref, identity],
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        fact_id = f"fact-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:24]}"
        facts.append(
            BlackboardFact(
                fact_id=fact_id,
                project_id=evidence.project_id,
                fact_type=observation.fact_type,
                asset_ref=observation.asset_ref,
                data=observation.data,
                confidence=observation.confidence,
                source_agent=evidence.agent_id,
                session_id=evidence.session_id,
                evidence_ref=evidence.evidence_id,
                observed_at=observation.observed_at,
                state=observation.state,
            )
        )
    return facts
