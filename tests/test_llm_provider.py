"""Tests for the LLM planner provider (OpenAI-compatible, mocked transport)."""

from __future__ import annotations

import json

import httpx
import pytest

from src.config import LLMConfig
from src.domain.models import Scope
from src.planner.provider import PlanRequest
from src.planner.providers import LLMProvider, LLMProviderError

PLAN_JSON = {
    "goal": "执行完整渗透测试",
    "tactics": [
        {
            "tactic_id": "reconnaissance",
            "name": "侦察",
            "techniques": [
                {
                    "technique_id": "T1595",
                    "name": "主动扫描",
                    "actions": [
                        {
                            "action_id": "act-scan-ports",
                            "name": "端口扫描",
                            "description": "扫描授权目标的端口",
                            "target_refs": ["*"],
                            "expected_outputs": ["service.exposed"],
                            "risk_level": "low",
                        }
                    ],
                }
            ],
        },
        {
            "tactic_id": "initial-access",
            "name": "初始访问",
            "techniques": [
                {
                    "technique_id": "T1190",
                    "name": "利用对外应用",
                    "actions": [
                        {
                            "action_id": "act-vuln-scan",
                            "name": "漏洞扫描",
                            "description": "扫描 Web 漏洞",
                            "target_refs": ["*"],
                            "expected_outputs": ["vulnerability.detected"],
                            "risk_level": "medium",
                        }
                    ],
                }
            ],
        },
    ],
}


def _config() -> LLMConfig:
    return LLMConfig(
        base_url="http://llm.test/v1",
        api_key="sk-test-1234567890",
        model="test-model",
        timeout=5,
        temperature=0.0,
    )


def _scope() -> Scope:
    return Scope(
        scope_id="scope-1",
        project_id="proj-1",
        target_type="ip",
        target="192.168.240.128",
        authorization_ref="auth-1",
    )


def _request() -> PlanRequest:
    return PlanRequest(
        goal="执行完整渗透测试",
        scope=_scope(),
        project_id="proj-1",
        available_techniques=["T1595", "T1190", "T1046"],
    )


def _client_returning(contents: list[str], status: int = 200) -> httpx.Client:
    """Build a client whose successive responses carry the given contents."""
    queue = list(contents)

    def handler(request: httpx.Request) -> httpx.Response:
        content = queue.pop(0) if queue else contents[-1]
        return httpx.Response(
            status,
            json={"choices": [{"message": {"content": content}}]},
        )

    return httpx.Client(transport=httpx.MockTransport(handler))


class TestLLMProviderHappyPath:
    def test_generates_plan_with_wildcard_resolution(self):
        provider = LLMProvider(_config(), client=_client_returning([json.dumps(PLAN_JSON)]))
        plan = provider.plan(_request())

        assert plan.generated_by == "llm"
        assert [t.tactic_id for t in plan.tactics] == ["reconnaissance", "initial-access"]
        actions = plan.all_actions()
        assert len(actions) == 2
        # "*" resolved to the authorized scope target
        assert actions[0].target_refs == ["192.168.240.128"]

    def test_tolerates_fenced_json(self):
        fenced = "```json\n" + json.dumps(PLAN_JSON) + "\n```"
        provider = LLMProvider(_config(), client=_client_returning([fenced]))
        plan = provider.plan(_request())
        assert len(plan.all_actions()) == 2

    def test_action_inherits_technique_when_missing(self):
        data = json.loads(json.dumps(PLAN_JSON))
        # The fixture action has no technique_id → must inherit from its technique
        data["tactics"][0]["techniques"][0]["actions"][0].pop("technique_id", None)
        provider = LLMProvider(_config(), client=_client_returning([json.dumps(data)]))
        plan = provider.plan(_request())
        assert plan.all_actions()[0].technique_id == "T1595"


class TestLLMProviderRepair:
    def test_retries_after_bad_json(self):
        provider = LLMProvider(
            _config(),
            client=_client_returning(["not json", json.dumps(PLAN_JSON)]),
        )
        plan = provider.plan(_request())
        assert plan.generated_by == "llm"

    def test_gives_up_after_retries(self):
        provider = LLMProvider(_config(), client=_client_returning(["bad", "still bad"]))
        with pytest.raises(LLMProviderError):
            provider.plan(_request())

    def test_structural_error_triggers_retry(self):
        empty = json.dumps({"goal": "x", "tactics": []})
        provider = LLMProvider(
            _config(), client=_client_returning([empty, json.dumps(PLAN_JSON)]),
        )
        plan = provider.plan(_request())
        assert len(plan.all_actions()) == 2


class TestLLMProviderErrors:
    def test_http_error_surfaces(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"error": {"message": "invalid key"}})

        provider = LLMProvider(_config(), client=httpx.Client(transport=httpx.MockTransport(handler)))
        with pytest.raises(LLMProviderError) as exc:
            provider.plan(_request())
        assert "401" in str(exc.value)

    def test_missing_config_raises(self, monkeypatch):
        for var in (
            "RAPLATFORM_LLM_BASE_URL",
            "RAPLATFORM_LLM_API_KEY",
            "RAPLATFORM_LLM_MODEL",
        ):
            monkeypatch.delenv(var, raising=False)
        # Point .env loading at a non-existent file so the fixture env is used
        import src.config as config_module

        monkeypatch.setattr(config_module, "_ENV_FILE", config_module.Path("/nonexistent/.env"))
        monkeypatch.setattr(config_module, "_loaded", True, raising=False)
        with pytest.raises(LLMProviderError):
            LLMProvider()