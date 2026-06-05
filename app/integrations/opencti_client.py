import json
import ssl
import subprocess
from base64 import b64encode
from pathlib import Path

import httpx

from app.core.config import settings
from app.integrations.demo_data import IOC_FIXTURES


class OpenCTIClient:
    def __init__(self) -> None:
        document_store = Path(settings.document_store_path)
        if not document_store.is_absolute():
            document_store = Path(__file__).resolve().parents[2] / document_store
        self._cache_path = document_store / "opencti_live_cache.json"
        self._runtime_supports_tls = hasattr(ssl, "create_default_context")

    def lookup_indicator(self, indicator: str) -> dict | None:
        if settings.opencti_live_mode:
            live = self._lookup_live(indicator)
            if live:
                return live
        for item in IOC_FIXTURES:
            if item["value"] == indicator:
                return {
                    "threat_actor": item.get("threat_actor"),
                    "malware_family": item.get("malware_family"),
                    "campaign": item.get("campaign"),
                    "mitre_attack": item.get("mitre_attack", []),
                    "cves": item.get("cves", []),
                }
        return None

    def relationship_graph(self) -> list[dict]:
        graph: list[dict] = []
        for item in IOC_FIXTURES:
            if item.get("threat_actor"):
                graph.append(
                    {
                        "indicator": item["value"],
                        "threat_actor": item["threat_actor"],
                        "malware_family": item.get("malware_family"),
                        "campaign": item.get("campaign"),
                    }
                )
        return graph

    def _lookup_live(self, indicator: str) -> dict | None:
        # The local Windows Python runtime used by this project ships with a
        # stubbed ssl module, so direct HTTPS calls from httpx are not usable.
        # In that environment, prefer the local live cache and then fall back
        # to mock fixtures instead of hanging or throwing 500s in demo flows.
        if not self._runtime_supports_tls:
            return self._lookup_cached(indicator)
        try:
            observable_result = self._query_opencti(
                """
                query ObservableSearch($search: String!) {
                  stixCyberObservables(search: $search, first: 1) {
                    edges {
                      node {
                        id
                        observable_value
                        objectLabel { value }
                      }
                    }
                  }
                }
                """,
                {"search": indicator},
            )
        except Exception:
            return self._lookup_cached(indicator)
        observable_edges = (
            observable_result.get("data", {})
            .get("stixCyberObservables", {})
            .get("edges", [])
        )

        indicator_result = self._query_opencti(
            """
            query IndicatorSearch($search: String!) {
              indicators(search: $search, first: 5) {
                edges {
                  node {
                    id
                    name
                    pattern
                    objectLabel { value }
                  }
                }
              }
            }
            """,
            {"search": indicator},
        )
        indicator_edges = indicator_result.get("data", {}).get("indicators", {}).get("edges", [])
        if not observable_edges and not indicator_edges:
            return None

        labels = []
        if observable_edges:
            labels.extend([item["value"] for item in observable_edges[0]["node"].get("objectLabel", [])])
        if indicator_edges:
            labels.extend([item["value"] for item in indicator_edges[0]["node"].get("objectLabel", [])])

        relationships = self._lookup_relationships(indicator)
        result = {
            "threat_actor": relationships.get("threat_actor"),
            "malware_family": relationships.get("malware_family"),
            "campaign": relationships.get("campaign"),
            "mitre_attack": sorted(set(relationships.get("mitre_attack", []))),
            "cves": [label for label in labels if str(label).startswith("CVE-")],
            "labels": sorted(set(labels)),
        }
        self._store_cached(indicator, result)
        return result

    def _lookup_relationships(self, indicator: str) -> dict:
        result = self._query_opencti(
            """
            query RelationshipSearch($search: String!) {
              stixCoreObjects(search: $search, first: 10) {
                edges {
                  node {
                    entity_type
                    ... on ThreatActor {
                      name
                    }
                    ... on IntrusionSet {
                      name
                    }
                    ... on Malware {
                      name
                    }
                    ... on Campaign {
                      name
                    }
                    ... on AttackPattern {
                      name
                      x_mitre_id
                    }
                  }
                }
              }
            }
            """,
            {"search": indicator},
        )
        edges = result.get("data", {}).get("stixCoreObjects", {}).get("edges", [])
        mapped = {
            "threat_actor": None,
            "malware_family": None,
            "campaign": None,
            "mitre_attack": [],
        }
        for edge in edges:
            node = edge.get("node", {})
            entity_type = node.get("entity_type")
            if entity_type == "Intrusion-Set" and not mapped["threat_actor"]:
                mapped["threat_actor"] = node.get("name")
            elif entity_type == "Malware" and not mapped["malware_family"]:
                mapped["malware_family"] = node.get("name")
            elif entity_type == "Campaign" and not mapped["campaign"]:
                mapped["campaign"] = node.get("name")
            elif entity_type == "Attack-Pattern":
                mapped["mitre_attack"].append(node.get("x_mitre_id") or node.get("name"))
        return mapped

    def _query_opencti(self, query: str, variables: dict) -> dict:
        payload = {"query": query, "variables": variables}
        try:
            response = httpx.post(
                f"{settings.opencti_url.rstrip('/')}/graphql",
                headers={
                    "Authorization": f"Bearer {settings.opencti_token}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=settings.opencti_timeout_seconds,
                verify=settings.opencti_verify_ssl,
            )
            response.raise_for_status()
            return response.json()
        except Exception as exc:
            # This local Windows runtime ships with a stubbed ssl module, so
            # fall back to PowerShell's TLS stack for live OpenCTI queries.
            if "ssl" not in str(exc).lower() and "SSL" not in exc.__class__.__name__:
                raise
            return self._query_opencti_via_powershell(payload)

    def _query_opencti_via_powershell(self, payload: dict) -> dict:
        payload_b64 = b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        ps_command = (
            "$headers = @{ "
            f"'Authorization' = 'Bearer {settings.opencti_token}'; "
            "'Content-Type' = 'application/json' }; "
            f"$body = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{payload_b64}')); "
            f"Invoke-RestMethod -Method Post -Uri '{settings.opencti_url.rstrip('/')}/graphql' "
            "-Headers $headers -Body $body | ConvertTo-Json -Depth 20"
        )
        encoded_command = b64encode(ps_command.encode("utf-16le")).decode("ascii")
        command = [
            "powershell.exe",
            "-NoProfile",
            "-EncodedCommand",
            encoded_command,
        ]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"PowerShell OpenCTI fallback failed: rc={result.returncode}; "
                f"stdout={result.stdout!r}; stderr={result.stderr!r}"
            )
        return json.loads(result.stdout)

    def _lookup_cached(self, indicator: str) -> dict | None:
        if not self._cache_path.exists():
            return None
        try:
            cache = json.loads(self._cache_path.read_text(encoding="utf-8"))
        except Exception:
            return None
        return cache.get(indicator)

    def _store_cached(self, indicator: str, result: dict) -> None:
        self._cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache = {}
        if self._cache_path.exists():
            try:
                cache = json.loads(self._cache_path.read_text(encoding="utf-8"))
            except Exception:
                cache = {}
        cache[indicator] = result
        self._cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")
