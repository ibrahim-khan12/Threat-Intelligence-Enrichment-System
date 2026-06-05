from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "threat_intel",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.task_always_eager = settings.celery_task_always_eager
celery_app.conf.task_store_eager_result = True
