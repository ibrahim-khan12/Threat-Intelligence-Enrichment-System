import re

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
URL_PATTERN = re.compile(r"https?://[^\s]+")
HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{64}\b")


def extract_iocs(payload: dict) -> list[dict]:
    discovered: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(ioc_type: str, value: str) -> None:
        key = (ioc_type, value)
        if value and key not in seen:
            seen.add(key)
            discovered.append({"ioc_type": ioc_type, "value": value})

    for key in ("src_ip", "dest_ip"):
        if payload.get(key):
            add("ip", payload[key])
    if payload.get("domain"):
        add("domain", payload["domain"])
    if payload.get("url"):
        add("url", payload["url"])
    if payload.get("file_hash"):
        hash_type = "sha256" if len(payload["file_hash"]) == 64 else "md5"
        add(hash_type, payload["file_hash"])

    flattened = " ".join(str(value) for value in payload.values() if value is not None)
    for match in IP_PATTERN.findall(flattened):
        add("ip", match)
    for match in DOMAIN_PATTERN.findall(flattened):
        add("domain", match)
    for match in URL_PATTERN.findall(flattened):
        add("url", match)
    for match in HASH_PATTERN.findall(flattened):
        add("sha256" if len(match) == 64 else "md5", match)

    return discovered

