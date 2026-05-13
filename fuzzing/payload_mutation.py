import urllib.parse
import html
import random
from core.learning_memory import load_memory, target_key

def url_encode(payload):
    return urllib.parse.quote(payload)

def double_url_encode(payload):
    return urllib.parse.quote(urllib.parse.quote(payload))

def html_entity_encode(payload):
    return html.escape(payload)

def case_mutate(payload):
    return "".join(
        c.upper() if i % 2 == 0 else c.lower()
        for i, c in enumerate(payload)
    )

def sql_comment_mutate(payload):
    if " " in payload:
        return payload.replace(" ", "/**/")
    return payload

MUTATORS = {
    "url": url_encode,
    "double_url": double_url_encode,
    "html": html_entity_encode,
    "case": case_mutate,
    "sql_comment": sql_comment_mutate
}

def infer_block_reason(evidence):
    # (Existing logic)
    if not evidence: return "unknown"
    ev = str(evidence).lower()
    if "waf" in ev or "firewall" in ev: return "waf"
    if "filter" in ev: return "filter"
    if "encoding" in ev: return "encoding"
    return "unknown"

def choose_mutations(target, vuln, payload):
    memory = load_memory()
    tkey = target_key(target)
    
    candidates = list(MUTATORS.keys())
    
    # Phase C: Research Influence
    if PATTERN_FILE.exists():
        patterns = PATTERN_FILE.read_text().lower()
        if "encoding" in patterns:
            # If research suggests encoding bypasses are trending/relevant
            if "double_url" in candidates:
                candidates.remove("double_url")
                candidates.insert(0, "double_url")
    
    # Learning prioritization (Phase A1/A2)
    scores = {m: 0 for m in candidates}
    
    if tkey in memory and vuln in memory[tkey]:
        for mut_name, stats in memory[tkey][vuln].items():
            if mut_name in scores:
                scores[mut_name] += stats.get("success", 0) * 2
                scores[mut_name] -= stats.get("blocked", 0)

    # Sort candidates by score
    candidates.sort(key=lambda m: scores[m], reverse=True)
    
    # Limit to top 3 to avoid infinite loops
    return candidates[:3]
