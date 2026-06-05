from datetime import datetime, timezone

from app.models.ioc import IOC


STIX_TYPE_MAP = {
    "ip": "ipv4-addr",
    "domain": "domain-name",
    "url": "url",
    "md5": "file",
    "sha256": "file",
}


def export_iocs_to_stix(iocs: list[IOC]) -> dict:
    objects = []
    now = datetime.now(timezone.utc).isoformat()
    for ioc in iocs:
        stix_type = STIX_TYPE_MAP.get(ioc.ioc_type, "indicator")
        pattern = _pattern_for_ioc(ioc.ioc_type, ioc.value)
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{ioc.id:012d}",
                "created": now,
                "modified": now,
                "name": ioc.value,
                "pattern_type": "stix",
                "pattern": pattern,
                "labels": ioc.tags,
                "description": ioc.description or "",
                "x_threat_level": ioc.threat_level,
                "x_source": ioc.source,
                "x_ioc_type": stix_type,
            }
        )
    return {"type": "bundle", "id": "bundle--local-export", "objects": objects}


def import_iocs_from_stix(bundle: dict) -> list[dict]:
    imported = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        value, ioc_type = _parse_pattern(pattern)
        if not value:
            continue
        imported.append(
            {
                "ioc_type": ioc_type,
                "value": value,
                "threat_level": obj.get("x_threat_level", "medium"),
                "source": obj.get("x_source", "STIX"),
                "tags": obj.get("labels", []),
                "description": obj.get("description") or None,
            }
        )
    return imported


def _pattern_for_ioc(ioc_type: str, value: str) -> str:
    if ioc_type == "ip":
        return f"[ipv4-addr:value = '{value}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{value}']"
    if ioc_type == "url":
        return f"[url:value = '{value}']"
    if ioc_type == "md5":
        return f"[file:hashes.MD5 = '{value}']"
    if ioc_type == "sha256":
        return f"[file:hashes.'SHA-256' = '{value}']"
    return f"[x-observed-data:value = '{value}']"


def _parse_pattern(pattern: str) -> tuple[str | None, str]:
    if "ipv4-addr:value" in pattern:
        return pattern.split("'")[1], "ip"
    if "domain-name:value" in pattern:
        return pattern.split("'")[1], "domain"
    if "url:value" in pattern:
        return pattern.split("'")[1], "url"
    if "hashes.MD5" in pattern:
        return pattern.split("'")[1], "md5"
    if "SHA-256" in pattern:
        return pattern.split("'")[1], "sha256"
    return None, "unknown"
