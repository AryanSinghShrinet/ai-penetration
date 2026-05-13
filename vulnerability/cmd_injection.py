SAFE_SEPARATORS = [";", "&&", "||", "|"]

def generate_cmd_payloads(base_value):
    return [f"{base_value}{sep}" for sep in SAFE_SEPARATORS]

def analyze_cmd_behavior(baseline, test):
    indicators = []

    if baseline.status_code != test.status_code:
        indicators.append("status_code_changed")

    if abs(len(baseline.text) - len(test.text)) > 120:
        indicators.append("response_length_changed")

    if test.elapsed.total_seconds() > baseline.elapsed.total_seconds() + 2:
        indicators.append("response_delay")

    return indicators
