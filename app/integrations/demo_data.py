from pathlib import Path
import json

BASE_DIR = Path("/sample-data")
if not BASE_DIR.exists():
    BASE_DIR = Path(__file__).resolve().parents[3] / "sample-data"


def load_json(relative_path: str):
    with (BASE_DIR / relative_path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


IOC_FIXTURES = load_json("iocs/demo_iocs.json")
ALERT_FIXTURES = load_json("alerts/demo_alerts.json")
