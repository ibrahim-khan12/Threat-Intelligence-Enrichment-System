import httpx

from app.core.config import settings
from app.integrations.demo_data import IOC_FIXTURES


class MISPClient:
    def search_indicator(self, indicator: str) -> dict | None:
        if settings.misp_live_mode:
            live = self._search_live(indicator)
            if live:
                return live
        for item in IOC_FIXTURES:
            if item["value"] == indicator:
                return {
                    "source": "MISP",
                    "threat_level": item["threat_level"],
                    "tags": item["tags"],
                    "event_id": f"MISP-{item['id']}",
                }
        return None

    def sync_iocs(self) -> list[dict]:
        if settings.misp_live_mode:
            live = self._sync_live()
            if live:
                return live
        return IOC_FIXTURES

    def _search_live(self, indicator: str) -> dict | None:
        client = self._pymisp_client()
        if client:
            try:
                result = client.search(controller="attributes", value=indicator, pythonify=False)
                attributes = result.get("Attribute", []) if isinstance(result, dict) else []
                if attributes:
                    return self._attribute_to_summary(attributes[0])
            except Exception:
                pass

        response = httpx.post(
            f"{settings.misp_url.rstrip('/')}/attributes/restSearch",
            headers={"Authorization": settings.misp_api_key, "Accept": "application/json"},
            json={"value": indicator, "returnFormat": "json"},
            timeout=settings.misp_timeout_seconds,
            verify=settings.misp_verify_ssl,
        )
        response.raise_for_status()
        data = response.json()
        attributes = data.get("response", {}).get("Attribute", [])
        if not attributes:
            return None
        return self._attribute_to_summary(attributes[0])

    def _sync_live(self) -> list[dict]:
        client = self._pymisp_client()
        if client:
            try:
                result = client.search(controller="attributes", limit=250, pythonify=False)
                attributes = result.get("Attribute", []) if isinstance(result, dict) else []
                imported = self._normalize_attributes(attributes)
                if imported:
                    return imported
            except Exception:
                pass

        response = httpx.post(
            f"{settings.misp_url.rstrip('/')}/attributes/restSearch",
            headers={"Authorization": settings.misp_api_key, "Accept": "application/json"},
            json={"limit": 250, "returnFormat": "json"},
            timeout=settings.misp_timeout_seconds,
            verify=settings.misp_verify_ssl,
        )
        response.raise_for_status()
        data = response.json()
        attributes = data.get("response", {}).get("Attribute", [])
        return self._normalize_attributes(attributes)

    def _pymisp_client(self):
        try:
            from pymisp import ExpandedPyMISP

            return ExpandedPyMISP(
                settings.misp_url,
                settings.misp_api_key,
                ssl=settings.misp_verify_ssl,
            )
        except Exception:
            return None

    def _normalize_attributes(self, attributes: list[dict]) -> list[dict]:
        normalized = []
        for attribute in attributes:
            value = attribute.get("value")
            if not value:
                continue
            normalized.append(
                {
                    "ioc_type": _misp_type_to_ioc_type(attribute.get("type", "")),
                    "value": value,
                    "threat_level": _normalize_threat_level(attribute.get("threat_level_id")),
                    "source": "MISP",
                    "tags": [tag.get("name") for tag in attribute.get("Tag", [])],
                    "description": attribute.get("comment"),
                }
            )
        return normalized

    def _attribute_to_summary(self, attribute: dict) -> dict:
        return {
            "source": "MISP",
            "threat_level": _normalize_threat_level(attribute.get("threat_level_id")),
            "tags": [tag.get("name") for tag in attribute.get("Tag", [])],
            "event_id": attribute.get("event_id"),
        }


def _misp_type_to_ioc_type(value: str) -> str:
    mapping = {
        "ip-src": "ip",
        "ip-dst": "ip",
        "domain": "domain",
        "url": "url",
        "md5": "md5",
        "sha256": "sha256",
    }
    return mapping.get(value, "domain")


def _normalize_threat_level(value: str | int | None) -> str:
    mapping = {
        "1": "high",
        "2": "medium",
        "3": "low",
        "4": "undefined",
        1: "high",
        2: "medium",
        3: "low",
        4: "undefined",
    }
    return mapping.get(value, "medium")
