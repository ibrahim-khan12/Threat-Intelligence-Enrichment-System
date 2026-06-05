from datetime import datetime

from app.core.security import hash_password
from app.db.postgres import Base, SessionLocal, engine
from app.integrations.demo_data import ALERT_FIXTURES, IOC_FIXTURES
from app.models.alert import Alert
from app.models.api_key import APIKey
from app.models.ioc import IOC
from app.models.user import User
from app.services.indicator_extractor import extract_iocs


def run() -> None:
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        if not session.query(User).filter(User.username == "admin").first():
            session.add(
                User(
                    username="admin",
                    email="admin@example.local",
                    hashed_password=hash_password("admin123!"),
                    role="admin",
                )
            )
        if not session.query(User).filter(User.username == "analyst").first():
            session.add(
                User(
                    username="analyst",
                    email="analyst@example.local",
                    hashed_password=hash_password("analyst123!"),
                    role="analyst",
                )
            )
        for item in IOC_FIXTURES:
            exists = session.query(IOC).filter(IOC.value == item["value"]).first()
            if not exists:
                session.add(
                    IOC(
                        ioc_type=item["ioc_type"],
                        value=item["value"],
                        threat_level=item["threat_level"],
                        source=item["source"],
                        tags=item["tags"],
                        description=item.get("description"),
                    )
                )
        for alert in ALERT_FIXTURES:
            exists = session.query(Alert).filter(Alert.alert_id == alert["alert_id"]).first()
            if not exists:
                session.add(
                    Alert(
                        alert_id=alert["alert_id"],
                        source=alert["source"],
                        timestamp=datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00")),
                        raw_payload=alert,
                        extracted_iocs=extract_iocs(alert),
                        summary=f"{alert['source']} demo alert",
                    )
                )
        session.commit()
    finally:
        session.close()


if __name__ == "__main__":
    run()
