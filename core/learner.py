import hashlib
from collections import defaultdict

def fingerprint_response(text):
    """Lightweight response fingerprinting for de-duplication."""
    return hashlib.sha256(text.encode(errors="ignore")).hexdigest()[:16]

def get_payload_str(payload):
    """Convert payload to string for hashing/storage."""
    if isinstance(payload, dict):
        return payload.get("original", str(payload))
    return str(payload)

def learn_from_execution(layer4_results, logger):
    """
    Input: layer4_results[vuln] = list of execution results
    Output: learning summary with priority hints
    """
    learning = {
        "promote": defaultdict(int),
        "demote": defaultdict(int),
        "blocked_patterns": set(),
        "fingerprints": set()
    }

    for vuln, results in layer4_results.items():
        for r in results:
            payload = r.get("payload")
            payload_str = get_payload_str(payload)
            status = r.get("status")
            evidence = r.get("evidence", "")

            if status == "SUCCESS":
                learning["promote"][(vuln, payload_str)] += 2
            elif status == "FAILED":
                learning["demote"][(vuln, payload_str)] += 1
            elif status == "BLOCKED":
                learning["blocked_patterns"].add(payload_str)

            if isinstance(evidence, str) and evidence:
                learning["fingerprints"].add(fingerprint_response(evidence))

    logger.info(f"Learning summary: promote={len(learning['promote'])}, "
                f"demote={len(learning['demote'])}, "
                f"blocked={len(learning['blocked_patterns'])}")
    return learning
