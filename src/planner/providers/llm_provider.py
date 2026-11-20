"""LLM-backed planner provider (OpenAI-compatible Chat Completions).

The provider asks a model to produce a PTT plan as JSON.  Two guardrails:

1. The system prompt enumerates the ATT&CK tactic/technique whitelist and the
   exact JSON shape — the model chooses within that space.
2. Whatever comes back goes through ``plan_from_dict`` (structural
   normalisation) and then the Planner's six-layer ``PTTValidator``
   (ATT&CK legitimacy, capabilities, scope, risk, output contract,
   tactic/technique ownership).  A rejected plan never reaches the hive.

No SDK dependency: plain ``httpx`` calls.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from src.config import LLMConfig, get_llm_config
from src.planner.attack_kb import AttackKB
from src.planner.errors import PTTError
from src.planner.provider import PlanRequest, plan_from_dict
from src.planner.ptt_schema import PTTPlan


class LLMProviderError(PTTError):
    """Raised when the LLM backend fails or returns an unusable plan."""


_SYSTEM_PROMPT = """You are the planning module of an automated penetration-testing
platform. Turn the operator's goal into a PTT plan (Goal → Tactic → Technique →
Action), returned as a single JSON object. No prose, no markdown fences.

Hard rules:
1. Output EXACTLY this shape:
{"goal": "...", "tactics": [{"tactic_id": "...", "name": "...", "techniques": [
  {"technique_id": "Txxxx", "name": "...", "actions": [
    {"action_id": "...", "name": "...", "description": "...",
     "technique_id": "Txxxx", "target_refs": ["*"],
     "expected_outputs": ["service.exposed"], "risk_level": "low",
     "side_effects": [], "stop_conditions": []}]}]}]}
2. technique_id MUST sit under the tactic that OWNS it in this whitelist
   (technique → owning tactic is fixed, a mismatch is rejected):
{whitelist}
3. Each tactic needs ≥1 technique, each technique ≥1 action.
4. target_refs: use ["*"] for "everything in the authorized scope"; only use
   concrete hosts the operator explicitly named.
5. expected_outputs MUST be fact types, chosen from:
   asset.discovered, subdomain.discovered, service.exposed, network.relation,
   fingerprint.detected, vulnerability.detected, credential.validated
6. risk_level ∈ {low, medium, high, critical}. Use high/critical ONLY for
   exploitation/verification actions.
7. action_id: lowercase, hyphenated, unique (e.g. "act-scan-ports").
8. Order tactics so reconnaissance precedes exploitation. Keep the plan lean:
   at most 6 actions unless the goal demands more.
9. Do not invent techniques outside the whitelist; do not add extra keys.
10. Only include tactics you actually use — never emit an empty tactic.
11. If the goal involves vulnerability detection / penetration testing, the plan
    MUST contain at least one action whose expected_outputs includes
    "vulnerability.detected" (put it under initial-access with T1190,
    risk_level "medium"), ordered AFTER the reconnaissance/scanning actions.
    A plan without any vulnerability-detection action is invalid for such goals.
"""


class LLMProvider:
    """PlannerProvider implementation backed by an OpenAI-compatible endpoint."""

    def __init__(
        self,
        config: LLMConfig | None = None,
        *,
        client: httpx.Client | None = None,
        retries: int = 1,
        kb: AttackKB | None = None,
    ) -> None:
        self._config = config or get_llm_config()
        if self._config is None:
            raise LLMProviderError(
                "LLM 未配置：请在项目根目录 .env 中填写 "
                "RAPLATFORM_LLM_BASE_URL / RAPLATFORM_LLM_API_KEY / RAPLATFORM_LLM_MODEL"
            )
        self._client = client
        self._retries = max(0, retries)
        self._kb = kb or AttackKB()

    # ── PlannerProvider protocol ───────────────────────────────────────

    def plan(self, request: PlanRequest) -> PTTPlan:
        messages = self._build_messages(request)
        last_error: Exception | None = None

        for attempt in range(self._retries + 1):
            try:
                content = self._chat(messages)
                data = self._parse_json(content)
                self._pre_validate(data)
                return plan_from_dict(data, request, generated_by="llm")
            except (LLMProviderError, ValueError) as exc:
                last_error = exc
                # Feed the failure back so the model can repair its output.
                messages = self._build_messages(
                    request,
                    retry_hint=f"Previous output was rejected: {exc}. "
                               f"Return corrected JSON only.",
                )

        raise LLMProviderError(f"LLM plan generation failed: {last_error}")

    # ── internals ──────────────────────────────────────────────────────

    def _pre_validate(self, data: dict[str, Any]) -> None:
        """Cheap ATT&CK checks so obvious mistakes get repaired inside the retry loop.

        The Planner's PTTValidator remains the authoritative gate; this only
        catches the two errors models make most often (unknown technique,
        technique filed under the wrong tactic).
        """
        for t_data in data.get("tactics", []) or []:
            tactic_id = t_data.get("tactic_id", "")
            for tech_data in t_data.get("techniques", []) or []:
                technique_id = tech_data.get("technique_id", "")
                if not technique_id:
                    continue
                if not self._kb.validate_technique(technique_id):
                    raise LLMProviderError(
                        f"technique {technique_id} is not in the ATT&CK whitelist"
                    )
                owner = self._kb.tactic_for(technique_id)
                if owner and owner != tactic_id:
                    raise LLMProviderError(
                        f"technique {technique_id} belongs to tactic '{owner}', "
                        f"not '{tactic_id}'"
                    )

    def _build_messages(self, request: PlanRequest, retry_hint: str = "") -> list[dict[str, str]]:
        tactics = ", ".join(self._kb.all_tactic_ids())
        techniques = ", ".join(self._kb.all_technique_ids())
        # technique → owning tactic map (prevents the most common model error)
        whitelist_lines: list[str] = []
        for tactic_id in self._kb.all_tactic_ids():
            owned = self._kb.techniques_for_tactic(tactic_id)
            if owned:
                detail = ", ".join(
                    f"{tid} ({self._kb.technique_name(tid) or tid})" for tid in owned
                )
                whitelist_lines.append(f"   - {tactic_id}: {detail}")
        whitelist = "\\n".join(whitelist_lines)
        system = (
            _SYSTEM_PROMPT
            .replace("{whitelist}", whitelist)
            .replace("{tactics}", tactics)
            .replace("{techniques}", techniques)
        )

        scope_desc = (
            f"target_type={request.scope.target_type}, target={request.scope.target}"
        )
        user = (
            f"Goal: {request.goal}\n"
            f"Authorized scope: {scope_desc}\n"
            f"Agent-supported techniques: {', '.join(sorted(request.available_techniques))}\n"
        )
        if request.context:
            user += f"Blackboard context: {json.dumps(request.context, ensure_ascii=False)}\n"
        if retry_hint:
            user += f"\n{retry_hint}\n"

        return [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]

    def _chat(self, messages: list[dict[str, str]]) -> str:
        assert self._config is not None
        payload: dict[str, Any] = {
            "model": self._config.model,
            "messages": messages,
            "temperature": self._config.temperature,
            "response_format": {"type": "json_object"},
        }
        headers = {
            "Authorization": f"Bearer {self._config.api_key}",
            "Content-Type": "application/json",
        }

        try:
            if self._client is not None:
                response = self._client.post(
                    self._config.chat_url, json=payload, headers=headers,
                )
            else:
                with httpx.Client(timeout=self._config.timeout) as client:
                    response = client.post(
                        self._config.chat_url, json=payload, headers=headers,
                    )
        except httpx.HTTPError as exc:
            raise LLMProviderError(f"LLM request failed: {exc}") from exc

        if response.status_code >= 400:
            raise LLMProviderError(
                f"LLM HTTP {response.status_code}: {response.text[:300]}"
            )

        try:
            body = response.json()
            return body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, ValueError) as exc:
            raise LLMProviderError(
                f"unexpected LLM response shape: {response.text[:300]}"
            ) from exc

    @staticmethod
    def _parse_json(content: str) -> dict[str, Any]:
        text = content.strip()
        # Tolerate fenced output some models still emit.
        if text.startswith("```"):
            text = text.split("```", 2)[1] if text.count("```") >= 2 else text.strip("`")
            text = text.removeprefix("json").strip()
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise LLMProviderError(f"LLM returned invalid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise LLMProviderError("LLM JSON root must be an object")
        return data