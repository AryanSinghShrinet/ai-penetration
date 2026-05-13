"""
ai_analyst.py — Central AI call gateway
========================================
All other ai_*.py modules (ai_explain, ai_report, ai_logic_reasoning,
ai_payload_reasoning) route through ask_ai() defined here.

Provider routing reads config/ai.yaml (same file as AttackPlanner) so
there is ONE place to configure the AI model for the whole project.

Supports:
  provider: local    → Ollama at http://localhost:11434  (no API key)
  provider: openai   → OpenAI cloud (needs OPENAI_API_KEY)
  provider: anthropic → Anthropic cloud (needs ANTHROPIC_API_KEY)
"""

import os
import logging

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Load config/ai.yaml once at import time (cached in module-level var)
# ---------------------------------------------------------------------------
def _load_ai_cfg():
    try:
        import yaml
        from pathlib import Path
        p = Path("config/ai.yaml")
        if p.exists():
            return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception as _e:
        _log.debug(f"[ai_analyst] Could not load config/ai.yaml: {_e}")
    return {}

_AI_CFG = _load_ai_cfg()

# ---------------------------------------------------------------------------
# System prompt (shared across all ai_*.py helpers)
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """
You are a senior bug bounty analyst.
You explain vulnerabilities, assess impact, and suggest safe testing ideas.
You NEVER provide exploit code or instructions.
You NEVER suggest bypassing authentication or controls.
"""

# ---------------------------------------------------------------------------
# ask_ai() — main public function used by all helper modules
# ---------------------------------------------------------------------------
def ask_ai(prompt: str) -> str:
    """
    Send a prompt to the configured AI model and return the response text.
    Returns a plain-string fallback message if AI is disabled or unavailable.
    """
    # Reload config each call so live switches via /api/ai/config take effect
    cfg = _load_ai_cfg()

    if not cfg.get("enabled", True):
        return "AI analysis disabled in config/ai.yaml."

    provider = cfg.get("provider", "local")
    model    = cfg.get("model", "qwen2.5-coder:7b")
    max_tok  = cfg.get("safety", {}).get("max_tokens", 800)

    # ------------------------------------------------------------------ #
    # LOCAL OLLAMA                                                         #
    # ------------------------------------------------------------------ #
    if provider == "local":
        base_url = cfg.get("local", {}).get("base_url", "http://localhost:11434/v1")
        try:
            import openai
            client = openai.OpenAI(api_key="ollama", base_url=base_url)
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT.strip()},
                    {"role": "user",   "content": prompt},
                ],
                max_tokens=max_tok,
                temperature=0.2,
            )
            return resp.choices[0].message.content
        except Exception as e:
            _log.warning(f"[ai_analyst] Local Ollama call failed: {e}")
            return f"AI analysis skipped (Ollama unreachable): {e}"

    # ------------------------------------------------------------------ #
    # OPENAI CLOUD                                                         #
    # ------------------------------------------------------------------ #
    elif provider == "openai":
        api_key = (
            os.getenv("OPENAI_API_KEY", "")
            or cfg.get("cloud", {}).get("api_key", "")
        )
        if not api_key:
            return "AI analysis skipped: No OPENAI_API_KEY found."
        cloud_model = cfg.get("cloud", {}).get("openai_model", model)
        try:
            import openai
            client = openai.OpenAI(api_key=api_key)
            resp = client.chat.completions.create(
                model=cloud_model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT.strip()},
                    {"role": "user",   "content": prompt},
                ],
                max_tokens=max_tok,
                temperature=0.2,
            )
            return resp.choices[0].message.content
        except Exception as e:
            _log.warning(f"[ai_analyst] OpenAI call failed: {e}")
            return f"AI Analysis Failed: {e}"

    # ------------------------------------------------------------------ #
    # ANTHROPIC CLOUD                                                      #
    # ------------------------------------------------------------------ #
    elif provider == "anthropic":
        api_key = (
            os.getenv("ANTHROPIC_API_KEY", "")
            or cfg.get("cloud", {}).get("api_key", "")
        )
        if not api_key:
            return "AI analysis skipped: No ANTHROPIC_API_KEY found."
        cloud_model = cfg.get("cloud", {}).get("anthropic_model", model)
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            resp = client.messages.create(
                model=cloud_model,
                max_tokens=max_tok,
                system=SYSTEM_PROMPT.strip(),
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.content[0].text
        except Exception as e:
            _log.warning(f"[ai_analyst] Anthropic call failed: {e}")
            return f"AI Analysis Failed: {e}"

    else:
        return f"AI analysis skipped: Unknown provider '{provider}' in config/ai.yaml."
