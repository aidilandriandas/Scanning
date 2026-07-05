from celery import Celery
from datetime import datetime
import config

# Initialize Celery with Redis as broker and backend
celery_app = Celery(
    'scanner_tasks',
    broker=config.REDIS_URL,
    backend=config.REDIS_URL,
    include=['tasks']
)

# Celery configuration
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=config.MAX_SCAN_TIMEOUT,
    worker_prefetch_multiplier=1,
)
