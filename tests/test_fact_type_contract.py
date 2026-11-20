"""Guard against contract/normalizer drift on fact-type whitelists."""

from __future__ import annotations

from src.blackboard.normalizer import IDENTITY_FIELDS
from src.planner.contract import ALLOWED_FACT_TYPES


def test_validator_accepts_every_persistable_fact_type():
    """Anything the blackboard can store must be declarable in expected_outputs."""
    missing = set(IDENTITY_FIELDS) - ALLOWED_FACT_TYPES
    assert not missing, f"validator rejects persistable fact types: {sorted(missing)}"


def test_prompt_fact_types_are_all_allowed():
    """The LLM prompt advertises exactly the types the validator accepts."""
    from src.planner.providers.llm_provider import _SYSTEM_PROMPT

    advertised = {
        "asset.discovered", "subdomain.discovered", "service.exposed",
        "network.relation", "fingerprint.detected", "vulnerability.detected",
        "credential.validated",
    }
    for fact_type in advertised:
        assert fact_type in _SYSTEM_PROMPT, f"prompt does not mention {fact_type}"
        assert fact_type in ALLOWED_FACT_TYPES, f"prompt advertises unsupported {fact_type}"