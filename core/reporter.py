from pathlib import Path
import json
from datetime import datetime

def generate_report(state, recon, context, learning, chains):
    run_id = state["run_id"]
    out_dir = Path("reports") / f"run_{run_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    # JSON (machine-readable)
    report_json = {
        "run_id": run_id,
        "created_at": datetime.utcnow().isoformat(),
        "target": state.get("target"),
        "checklist": state.get("checklist"),
        "recon_summary": {
            "endpoints": len(recon.get("endpoints", [])),
            "parameters": recon.get("parameters", []),
            "forms": recon.get("forms", [])
        },
        "context": context,
        "learning": {
            "promoted": list(map(list, learning.get("promote", {}).keys())),
            "demoted": list(map(list, learning.get("demote", {}).keys())),
            "blocked_patterns": list(learning.get("blocked_patterns", []))
        },
        "chains": chains,
        "raw_results": state.get("layer_4", {})
    }
    (out_dir / "report.json").write_text(json.dumps(report_json, indent=2))

    # Markdown (human-readable)
    md = []
    md.append(f"# Bug Bounty Report — Run {run_id}\n")
    md.append(f"**Target:** {state.get('target')}\n")
    md.append("## Checklist\n")
    for v, s in state.get("checklist", {}).items():
        md.append(f"- **{v}**: {s}\n")

    md.append("\n## Recon Summary\n")
    md.append(f"- Endpoints discovered: {len(recon.get('endpoints', []))}\n")
    md.append(f"- Parameters: {', '.join(recon.get('parameters', []))}\n")

    md.append("\n## Context\n")
    md.append(f"- Application type: {context.get('application_type')}\n")
    md.append(f"- Response type: {context.get('response_type')}\n")
    md.append(f"- Likely vulnerabilities: {', '.join(context.get('likely_vulnerabilities', []))}\n")

    md.append("\n## Findings\n")
    for vuln, results in state.get("layer_4", {}).items():
        md.append(f"### {vuln}\n")
        for r in results:
            md.append(f"- Status: **{r.get('status')}** | Payload: `{r.get('payload')}`\n")

    if chains:
        md.append("\n## Suggested Vulnerability Chains (Manual Verification Required)\n")
        for c in chains:
            chain_name = c.get('name', c.get('chain', 'Unknown Chain'))
            impact = c.get('impact', 'Unknown impact')
            reason = c.get('reason', c.get('why', 'See details'))
            md.append(f"- **{chain_name}** → {impact}\n  - Why: {reason}\n")

    (out_dir / "report.md").write_text("".join(md), encoding="utf-8")

    return out_dir
