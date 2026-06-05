SEVERITY_MAP = [
    (90, "Critical"),
    (70, "High"),
    (45, "Medium"),
    (0, "Low"),
]


def calculate_risk_score(matches: list[dict]) -> tuple[int, str]:
    score = 5
    for match in matches:
        if match.get("reputation") == "Malicious":
            score += 25
        if match.get("threat_actor"):
            score += 20
        if match.get("malware_family"):
            score += 15
        score += min(len(match.get("mitre_attack", [])) * 8, 16)
        if match.get("cves"):
            score += 10

    score = min(score, 100)
    severity = next(label for threshold, label in SEVERITY_MAP if score >= threshold)
    return score, severity


def recommended_action(severity: str) -> str:
    mapping = {
        "Critical": "Block IP, isolate endpoint, and open incident ticket",
        "High": "Block indicator, quarantine host, and notify IR team",
        "Medium": "Monitor activity and create analyst investigation case",
        "Low": "Log event and continue monitoring",
    }
    return mapping[severity]

