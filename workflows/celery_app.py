"""
Celery Application for Workflow Automation

This module defines the Celery app and automated workflows for
continuous security operations.
"""

import os
from celery import Celery
from celery.schedules import crontab

# Initialize Celery
app = Celery(
    'security_workflows',
    broker=os.getenv('REDIS_URL', 'redis://localhost:6379'),
    backend=os.getenv('REDIS_URL', 'redis://localhost:6379')
)

# Celery configuration
app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour
    task_soft_time_limit=3000,  # 50 minutes
)

# Periodic task schedule
app.conf.beat_schedule = {
    # Threat detection every hour
    'threat-detection-hourly': {
        'task': 'workflows.tasks.run_threat_detection',
        'schedule': crontab(minute=0),  # Every hour
    },
    # Threat intelligence every 4 hours
    'threat-intel-4hourly': {
        'task': 'workflows.tasks.run_threat_intelligence',
        'schedule': crontab(minute=0, hour='*/4'),
    },
    # Vulnerability scan daily at 2 AM
    'vulnerability-scan-daily': {
        'task': 'workflows.tasks.run_vulnerability_scan',
        'schedule': crontab(minute=0, hour=2),
    },
    # Generate daily SOC report
    'daily-soc-report': {
        'task': 'workflows.tasks.generate_daily_report',
        'schedule': crontab(minute=0, hour=8),
    },
    # Health check every 15 minutes
    'health-check': {
        'task': 'workflows.tasks.health_check',
        'schedule': crontab(minute='*/15'),
    },
}

if __name__ == '__main__':
    app.start()
