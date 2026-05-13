"""
AI Attack Planner (Reasoning Layer)
=====================================
AI-assisted attack planning. Supports:
  - Local models via Ollama  (provider: local, no API key needed)
  - OpenAI cloud API         (provider: openai)
  - Anthropic cloud API      (provider: anthropic)

This is the reasoning brain of the tool. It takes scan context
and generates:
  1. Targeted test hypotheses for suspicious endpoints
  2. Vulnerability chain reasoning ("IDOR → XSS → account takeover")
  3. Next-step recommendations based on what was found
  4. PoC writing guidance for confirmed findings

Uses a ReAct-style (Reason + Act) loop:
  Observe → Reason → Plan → Act → Observe (next iteration)

Default model: qwen2.5-coder:7b via local Ollama at http://localhost:11434
"""

import json
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any

# FIX AP1: The default model is a Claude model, so prefer the Anthropic SDK.
# Fall back to the OpenAI SDK when an OpenAI model string is explicitly passed.
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

def _is_claude_model(model: str) -> bool:
    return model.startswith("claude")


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class AttackHypothesis:
    """A testable hypothesis about a potential vulnerability."""
    endpoint: str
    parameter: str
    vuln_type: str
    reasoning: str
    confidence: float           # 0.0 - 1.0
    test_steps: List[str]
    priority: int               # 1 = highest

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ChainReasoning:
    """AI reasoning about a vulnerability chain."""
    chain_name: str
    vulnerabilities: List[str]
    attack_narrative: str       # Step-by-step story
    impact: str                 # What the attacker achieves
    real_world_example: str
    confidence: float
    recommended_proof: List[str]

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class PlannerContext:
    """Context fed to the AI planner for reasoning."""
    target: str
    discovered_endpoints: List[str]
    confirmed_findings: List[Dict]
    asis_scores: List[Dict]       # Attack Surface Intelligence scores
    recon_summary: Dict
    scan_phase: str               # "initial", "active", "verification", "reporting"

    def to_prompt_context(self) -> str:
        """Format context as text for AI reasoning."""
        lines = [
            f"Target: {self.target}",
            f"Scan Phase: {self.scan_phase}",
            f"Endpoints Discovered: {len(self.discovered_endpoints)}",
            f"\nTop Endpoints by Risk Score:",
        ]

        for ep in self.asis_scores[:10]:
            lines.append(
                f"  [{ep.get('risk_level', '?').upper()}] {ep.get('endpoint', '')} "
                f"(score={ep.get('total_score', 0)}, "
                f"tests={ep.get('recommended_tests', [])})"
            )

        if self.confirmed_findings:
            lines.append(f"\nConfirmed Findings ({len(self.confirmed_findings)}):")
            for finding in self.confirmed_findings:
                lines.append(
                    f"  - {finding.get('vuln_type', '?')} @ {finding.get('endpoint', '')} "
                    f"(confidence={finding.get('confidence', '?')})"
                )

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# AI Planner
# ---------------------------------------------------------------------------

class AttackPlanner:
    """
    AI-powered attack planning and reasoning engine.

    Acts as a "senior security researcher" that reviews scan findings
    and suggests the most promising next steps.
    """

    SYSTEM_PROMPT = """You are a senior bug bounty researcher with expertise in
web application security. You help analyze scan results and plan targeted
attack strategies.

Your responses must be:
- Technically precise and actionable
- Focused on high-impact vulnerabilities
- Based on the actual evidence provided (no speculation without basis)
- Structured as JSON when requested

You understand: OWASP Top 10, business logic flaws, authentication bypasses,
IDOR, SSRF, XSS, SQLi, vulnerability chaining, and real-world exploit techniques."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "qwen2.5-coder:7b",
        provider: str = "local",
        base_url: Optional[str] = None,
    ):
        self.model = model
        self.provider = provider
        self._anthropic_client = None
        self._openai_client = None
        self._conversation_history: List[Dict] = []

        # ------------------------------------------------------------------ #
        # LOCAL OLLAMA  (provider="local") — no API key required              #
        # Uses the OpenAI-compatible endpoint exposed by Ollama               #
        # ------------------------------------------------------------------ #
        if provider == "local":
            if OPENAI_AVAILABLE:
                _base = base_url or "http://localhost:11434/v1"
                self._openai_client = openai.OpenAI(
                    api_key="ollama",   # Ollama ignores this value
                    base_url=_base,
                )
                import logging as _l
                _l.getLogger(__name__).info(
                    f"[AttackPlanner] Using LOCAL model '{model}' via Ollama at {_base}"
                )
            else:
                import logging as _l
                _l.getLogger(__name__).warning(
                    "[AttackPlanner] 'openai' package not installed — "
                    "cannot connect to Ollama. Run: pip install openai"
                )

        # ------------------------------------------------------------------ #
        # CLOUD ANTHROPIC  (provider="anthropic")                             #
        # ------------------------------------------------------------------ #
        elif provider == "anthropic":
            _key = api_key or __import__("os").environ.get("ANTHROPIC_API_KEY", "")
            if _key and ANTHROPIC_AVAILABLE:
                self._anthropic_client = anthropic.Anthropic(api_key=_key)
            else:
                import logging as _l
                _l.getLogger(__name__).warning(
                    "[AttackPlanner] Anthropic provider selected but no API key found. "
                    "Set ANTHROPIC_API_KEY env var or switch to provider=local."
                )

        # ------------------------------------------------------------------ #
        # CLOUD OPENAI  (provider="openai")                                   #
        # ------------------------------------------------------------------ #
        elif provider == "openai":
            _key = api_key or __import__("os").environ.get("OPENAI_API_KEY", "")
            if _key and OPENAI_AVAILABLE:
                self._openai_client = openai.OpenAI(api_key=_key)
            else:
                import logging as _l
                _l.getLogger(__name__).warning(
                    "[AttackPlanner] OpenAI provider selected but no API key found. "
                    "Set OPENAI_API_KEY env var or switch to provider=local."
                )

    def _call_ai(self, prompt: str, expect_json: bool = False) -> Optional[str]:
        """Make an AI API call with error handling."""
        # FIX AP1: Dispatch to whichever client was initialised.
        if self._anthropic_client:
            return self._call_anthropic(prompt)
        if self._openai_client:
            return self._call_openai(prompt)
        return self._fallback_reasoning(prompt)

    def _call_anthropic(self, prompt: str) -> Optional[str]:
        """Call the Anthropic Messages API (Claude models)."""
        self._conversation_history.append({"role": "user", "content": prompt})
        try:
            response = self._anthropic_client.messages.create(
                model=self.model,
                max_tokens=1000,
                system=self.SYSTEM_PROMPT,
                messages=self._conversation_history,
            )
            content = response.content[0].text
            self._conversation_history.append({"role": "assistant", "content": content})
            return content
        except Exception as _e:
            return self._fallback_reasoning(prompt)

    def _call_openai(self, prompt: str) -> Optional[str]:
        """Call the OpenAI Chat Completions API."""
        self._conversation_history.append({"role": "user", "content": prompt})
        try:
            response = self._openai_client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    *self._conversation_history,
                ],
                max_tokens=1000,
                temperature=0.3,
            )
            content = response.choices[0].message.content
            self._conversation_history.append({"role": "assistant", "content": content})
            return content
        except Exception as _e:
            return self._fallback_reasoning(prompt)

    def _fallback_reasoning(self, context: str) -> str:
        """
        Rule-based fallback when AI API is unavailable.
        Provides deterministic recommendations.
        """
        recommendations = []

        if "admin" in context.lower() or "critical" in context.lower():
            recommendations.append("Priority: Test admin endpoints for authentication bypass")
        if "id=" in context.lower() or "idor" in context.lower():
            recommendations.append("Test IDOR: Change numeric IDs to access other users' resources")
        if "upload" in context.lower():
            recommendations.append("File upload: Test with PHP/JSP shell, path traversal in filename")
        if "redirect" in context.lower() or "url=" in context.lower():
            recommendations.append("SSRF/Open Redirect: Try internal IP ranges and cloud metadata URLs")
        if "xss" in context.lower():
            recommendations.append("XSS confirmed: Test for session theft and CSP bypass")
        if not recommendations:
            recommendations.append("Run full parameter discovery on high-risk endpoints")
            recommendations.append("Check for JWT algorithm confusion and token manipulation")

        return "\n".join(f"- {r}" for r in recommendations)

    # -------------------------------------------------------------------------
    # Planning Functions
    # -------------------------------------------------------------------------

    def generate_hypotheses(self, context: PlannerContext) -> List[AttackHypothesis]:
        """
        Generate testable attack hypotheses from scan context.
        """
        prompt = f"""Based on this scan context, generate the 5 most promising attack hypotheses.

{context.to_prompt_context()}

For each hypothesis, provide:
- endpoint and parameter to target
- vulnerability type
- specific reasoning why this is likely vulnerable
- confidence (0.0-1.0)
- 3 concrete test steps

Respond ONLY with a JSON array of hypothesis objects."""

        response = self._call_ai(prompt, expect_json=True)
        hypotheses = []

        try:
            # Try to parse JSON response
            clean = response.strip().lstrip("```json").rstrip("```").strip()
            data = json.loads(clean)
            if isinstance(data, list):
                for i, item in enumerate(data[:5]):
                    hypotheses.append(AttackHypothesis(
                        endpoint=item.get("endpoint", ""),
                        parameter=item.get("parameter", ""),
                        vuln_type=item.get("vuln_type", ""),
                        reasoning=item.get("reasoning", ""),
                        confidence=float(item.get("confidence", 0.5)),
                        test_steps=item.get("test_steps", []),
                        priority=i + 1,
                    ))
        except (json.JSONDecodeError, KeyError, TypeError):
            # Fallback: create a hypothesis from the text response
            if response:
                hypotheses.append(AttackHypothesis(
                    endpoint=context.target,
                    parameter="*",
                    vuln_type="general",
                    reasoning=response[:500],
                    confidence=0.5,
                    test_steps=["Review AI reasoning", "Manual verification required"],
                    priority=1,
                ))

        return hypotheses

    def reason_about_chains(
        self,
        findings: List[Dict],
        target: str,
    ) -> List[ChainReasoning]:
        """
        Given a list of confirmed findings, reason about possible attack chains.
        """
        if not findings:
            return []

        finding_summary = "\n".join(
            f"- {f.get('vuln_type', '?')} @ {f.get('endpoint', '')} "
            f"(param: {f.get('parameter', '?')}, confidence: {f.get('confidence', '?')})"
            for f in findings
        )

        prompt = f"""Target: {target}
Confirmed vulnerabilities:
{finding_summary}

Analyze these findings and identify vulnerability chains.
For each chain:
1. Name the chain (e.g., "XSS → CSRF → Account Takeover")
2. Explain the step-by-step attack narrative
3. State what the attacker ultimately achieves
4. Estimate chain confidence (0.0-1.0)
5. Provide recommended PoC steps

Focus on chains with HIGH business impact. Respond as JSON array."""

        response = self._call_ai(prompt, expect_json=True)
        chains = []

        try:
            clean = response.strip().lstrip("```json").rstrip("```").strip()
            data = json.loads(clean)
            if isinstance(data, list):
                for item in data:
                    chains.append(ChainReasoning(
                        chain_name=item.get("chain_name", ""),
                        vulnerabilities=item.get("vulnerabilities", []),
                        attack_narrative=item.get("attack_narrative", ""),
                        impact=item.get("impact", ""),
                        real_world_example=item.get("real_world_example", ""),
                        confidence=float(item.get("confidence", 0.5)),
                        recommended_proof=item.get("recommended_proof", []),
                    ))
        except (json.JSONDecodeError, KeyError, TypeError):
            # Fallback chain reasoning
            vuln_types = list({f.get("vuln_type", "") for f in findings})
            if len(vuln_types) >= 2:
                chains.append(ChainReasoning(
                    chain_name=" + ".join(vuln_types[:2]),
                    vulnerabilities=vuln_types[:2],
                    attack_narrative=f"Chain {vuln_types[0]} with {vuln_types[1]} for elevated impact",
                    impact="Combined exploitation may allow privilege escalation",
                    real_world_example="Manual analysis required",
                    confidence=0.4,
                    recommended_proof=["Verify each finding independently", "Test chain manually"],
                ))

        return chains

    def suggest_next_steps(self, context: PlannerContext) -> List[str]:
        """
        Given current scan state, suggest the most impactful next steps.
        """
        prompt = f"""Current scan state:
{context.to_prompt_context()}

Suggest the 5 most impactful next testing steps.
Be specific: name the endpoint, parameter, and exact test to run.
Prioritize by potential impact.
Return as a simple numbered list."""

        response = self._call_ai(prompt)
        if not response:
            return ["Continue fuzzing high-risk endpoints", "Verify anomaly detection findings"]

        lines = [
            line.strip().lstrip("0123456789.-) ").strip()
            for line in response.split("\n")
            if line.strip() and len(line.strip()) > 10
        ]
        return lines[:5]

    def write_poc_guidance(self, finding: Dict) -> str:
        """
        Generate PoC writing guidance for a confirmed finding.
        """
        prompt = f"""Write a bug bounty PoC report section for this finding:
Vulnerability: {finding.get('vuln_type', '')}
Endpoint: {finding.get('endpoint', '')}
Parameter: {finding.get('parameter', '')}
Evidence: {json.dumps(finding.get('evidence', {}), indent=2)}

Include:
1. Summary (1 sentence)
2. Steps to reproduce (numbered)
3. Expected vs actual result
4. Business impact
5. CVSS score estimate

Keep it professional and concise."""

        return self._call_ai(prompt) or "PoC guidance unavailable — AI API not configured"

    def reset_conversation(self) -> None:
        """Reset the multi-turn conversation history."""
        self._conversation_history = []


def create_attack_planner(api_key: Optional[str] = None) -> AttackPlanner:
    """Factory: creates AttackPlanner from config/ai.yaml (preferred).
    Falls back to a local Ollama planner using qwen2.5-coder:7b if config
    cannot be loaded.
    """
    return create_attack_planner_from_config(api_key=api_key)


def create_attack_planner_from_config(api_key: Optional[str] = None) -> AttackPlanner:
    """
    Read config/ai.yaml and build an AttackPlanner with the correct
    provider, model, and base_url.

    Priority:
      1. config/ai.yaml  (provider / model fields)
      2. Environment variables (ANTHROPIC_API_KEY / OPENAI_API_KEY)
      3. Argument api_key
      4. Hardcoded default: local Ollama + qwen2.5-coder:7b
    """
    import logging
    _log = logging.getLogger(__name__)

    # --- Load config ---
    try:
        import yaml
        from pathlib import Path
        _cfg_path = Path("config/ai.yaml")
        if _cfg_path.exists():
            with open(_cfg_path) as _f:
                _cfg = yaml.safe_load(_f) or {}
        else:
            _cfg = {}
    except Exception as _e:
        _log.warning(f"[AttackPlanner] Could not load config/ai.yaml: {_e}. Using local defaults.")
        _cfg = {}

    if not _cfg.get("enabled", True):
        _log.info("[AttackPlanner] AI disabled in config. Using rule-based fallback only.")
        return AttackPlanner(provider="local", model="qwen2.5-coder:7b")

    provider = _cfg.get("provider", "local")
    model    = _cfg.get("model", "qwen2.5-coder:7b")

    if provider == "local":
        base_url = _cfg.get("local", {}).get("base_url", "http://localhost:11434/v1")
        _log.info(f"[AttackPlanner] LOCAL provider -> model='{model}', base_url='{base_url}'")
        return AttackPlanner(provider="local", model=model, base_url=base_url)

    elif provider == "anthropic":
        _key = api_key or __import__("os").environ.get("ANTHROPIC_API_KEY", "") \
               or _cfg.get("cloud", {}).get("api_key", "")
        _model = _cfg.get("cloud", {}).get("anthropic_model", model)
        _log.info(f"[AttackPlanner] ANTHROPIC cloud -> model='{_model}'")
        return AttackPlanner(provider="anthropic", model=_model, api_key=_key)

    elif provider == "openai":
        _key = api_key or __import__("os").environ.get("OPENAI_API_KEY", "") \
               or _cfg.get("cloud", {}).get("api_key", "")
        _model = _cfg.get("cloud", {}).get("openai_model", model)
        _log.info(f"[AttackPlanner] OPENAI cloud -> model='{_model}'")
        return AttackPlanner(provider="openai", model=_model, api_key=_key)

    else:
        _log.warning(f"[AttackPlanner] Unknown provider '{provider}', falling back to local Ollama.")
        return AttackPlanner(provider="local", model="qwen2.5-coder:7b")
