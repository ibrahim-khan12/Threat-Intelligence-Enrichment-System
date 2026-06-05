from typing import Any


SIGMA_RULES = [
    {
        "id": "sigma-phish-portal-clone",
        "title": "Suspicious phishing portal domain",
        "pattern": "malicious-login.com",
        "severity": "high",
    },
    {
        "id": "sigma-suricata-trojan",
        "title": "Suricata Trojan delivery signature",
        "pattern": "ET TROJAN",
        "severity": "critical",
    },
]

YARA_RULES = [
    {
        "id": "yara-trickbot-demo",
        "title": "Demo TrickBot loader hash",
        "hashes": {"44d88612fea8a8f36de82e1278abb02f"},
        "severity": "critical",
    }
]


def run_sigma_matches(alert_payload: dict[str, Any]) -> list[dict[str, Any]]:
    content = " ".join(str(value) for value in _flatten(alert_payload))
    matches = []
    for rule in SIGMA_RULES:
        if rule["pattern"].lower() in content.lower():
            matches.append(rule)
    return matches


def run_yara_matches(alert_payload: dict[str, Any]) -> list[dict[str, Any]]:
    hashes = {str(value) for value in _flatten(alert_payload) if isinstance(value, str)}
    matches = []
    for rule in YARA_RULES:
        if hashes.intersection(rule["hashes"]):
            matches.append(rule)
    return matches


def classify_alert(alert_payload: dict[str, Any], ioc_matches: list[dict[str, Any]]) -> dict[str, Any]:
    labels = []
    confidence = 0.35
    if any("phishing" in match.get("tags", []) for match in ioc_matches):
        labels.append("phishing")
        confidence += 0.2
    if any(match.get("malware_family") in {"TrickBot", "Emotet", "EvilProxy"} for match in ioc_matches):
        labels.append("malware-delivery")
        confidence += 0.25
    if any(match.get("campaign") for match in ioc_matches):
        labels.append("campaign-linked")
        confidence += 0.1
    if alert_payload.get("source") in {"EDR", "Suricata"}:
        confidence += 0.1

    label = labels[0] if labels else "benign-or-unknown"
    return {
        "label": label,
        "supporting_labels": labels,
        "confidence": round(min(confidence, 0.98), 2),
    }


def anomaly_score(alert_payload: dict[str, Any], ioc_matches: list[dict[str, Any]]) -> int:
    score = 10
    score += min(len(ioc_matches) * 12, 40)
    score += 20 if alert_payload.get("source") in {"Suricata", "EDR"} else 0
    score += 15 if alert_payload.get("file_hash") else 0
    score += 15 if any(match.get("reputation") == "Malicious" for match in ioc_matches) else 0
    return min(score, 100)


def _flatten(value: Any) -> list[Any]:
    if isinstance(value, dict):
        result = []
        for item in value.values():
            result.extend(_flatten(item))
        return result
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(_flatten(item))
        return result
    return [value]
