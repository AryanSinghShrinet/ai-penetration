from core.ai_analyst import ask_ai

def suggest_payload_variations(payload, context):
    prompt = f"""
A payload was blocked.

Payload:
{payload}

Context:
{context}

Suggest SAFE, high-level variations (encoding ideas only).
Do NOT generate actual exploit payloads.
"""
    return ask_ai(prompt)
