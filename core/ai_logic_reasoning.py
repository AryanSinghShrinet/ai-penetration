from core.ai_analyst import ask_ai

def analyze_workflow(workflow, observations):
    prompt = f"""
Analyze this application workflow for potential business logic flaws.

Workflow:
{workflow}

Observed behavior:
{observations}

Identify possible logic weaknesses or invariants to test.
No exploitation instructions.
"""
    return ask_ai(prompt)
