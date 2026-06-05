import json
from pathlib import Path
from typing import Any

from app.core.config import settings


def _matches(document: dict[str, Any], query: dict[str, Any]) -> bool:
    return all(document.get(key) == value for key, value in query.items())


def _apply_projection(document: dict[str, Any], projection: dict[str, int] | None) -> dict[str, Any]:
    if not projection:
        return dict(document)
    result = dict(document)
    if projection.get("_id") == 0:
        result.pop("_id", None)
    return result


class LocalCursor:
    def __init__(self, items: list[dict[str, Any]]) -> None:
        self.items = items
        self.index = 0

    def sort(self, field: str, direction: int):
        reverse = direction == -1
        self.items.sort(key=lambda item: item.get(field, ""), reverse=reverse)
        return self

    def limit(self, count: int):
        if count >= 0:
            self.items = self.items[:count]
        return self

    def __aiter__(self):
        self.index = 0
        return self

    async def __anext__(self):
        if self.index >= len(self.items):
            raise StopAsyncIteration
        item = self.items[self.index]
        self.index += 1
        return item


class LocalCollection:
    def __init__(self, base_path: Path, name: str) -> None:
        self.file_path = base_path / f"{name}.json"
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.file_path.exists():
            self.file_path.write_text("[]", encoding="utf-8")

    def _read(self) -> list[dict[str, Any]]:
        return json.loads(self.file_path.read_text(encoding="utf-8"))

    def _write(self, items: list[dict[str, Any]]) -> None:
        self.file_path.write_text(json.dumps(items, indent=2, default=str), encoding="utf-8")

    async def insert_one(self, document: dict[str, Any]) -> None:
        items = self._read()
        items.append(document)
        self._write(items)

    async def update_one(self, query: dict[str, Any], update: dict[str, Any], upsert: bool = False) -> None:
        items = self._read()
        updated = False
        for index, item in enumerate(items):
            if _matches(item, query):
                if "$set" in update:
                    item.update(update["$set"])
                else:
                    item.update(update)
                items[index] = item
                updated = True
                break
        if not updated and upsert:
            items.append(update.get("$set", update))
        self._write(items)

    def find(self, query: dict[str, Any], projection: dict[str, int] | None = None) -> LocalCursor:
        items = [_apply_projection(item, projection) for item in self._read() if _matches(item, query)]
        return LocalCursor(items)

    async def count_documents(self, query: dict[str, Any]) -> int:
        return sum(1 for item in self._read() if _matches(item, query))


class LocalDocumentDB:
    def __init__(self, base_path: str) -> None:
        path = Path(base_path)
        self.enriched_alerts = LocalCollection(path, "enriched_alerts")
        self.audit_logs = LocalCollection(path, "audit_logs")
        self.incident_queue = LocalCollection(path, "incident_queue")
        self.notification_logs = LocalCollection(path, "notification_logs")
        self.soar_actions = LocalCollection(path, "soar_actions")


if settings.embedded_mode or settings.mongodb_url.startswith("embedded://"):
    mongo_db = LocalDocumentDB(settings.document_store_path)
else:
    from motor.motor_asyncio import AsyncIOMotorClient

    mongo_client = AsyncIOMotorClient(settings.mongodb_url)
    mongo_db = mongo_client[settings.mongodb_db]


def get_mongo_db():
    return mongo_db
