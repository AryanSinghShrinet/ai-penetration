from core.ai_analyst import ask_ai

def summarize_run(run_data):
    prompt = f"""
Summarize this security testing run for a bug bounty submission.

Run data:
{run_data}

Include:
- Key findings
- Severity overview
- Suggested next manual checks
"""
    return ask_ai(prompt)
