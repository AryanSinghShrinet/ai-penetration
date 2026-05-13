from core.ai_analyst import ask_ai

def explain_finding(finding):
    prompt = f"""
Explain this security finding clearly for a bug bounty report.

Finding:
{finding}

Explain:
- What the issue is
- Why it matters
- Potential impact
- High-level reproduction steps (no exploit code)
"""
    return ask_ai(prompt)
