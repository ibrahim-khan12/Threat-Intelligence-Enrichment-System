from app.integrations.demo_data import IOC_FIXTURES


def lookup_reputation(indicator: str) -> dict:
    for item in IOC_FIXTURES:
        if item["value"] == indicator:
            return {
                "reputation": item.get("reputation", "Suspicious"),
                "country": item.get("country", "Unknown"),
                "whois": item.get("whois", {}),
                "dns": item.get("dns", {}),
                "geo": item.get("geo", {}),
            }
    return {
        "reputation": "Unknown",
        "country": "Unknown",
        "whois": {},
        "dns": {},
        "geo": {},
    }

