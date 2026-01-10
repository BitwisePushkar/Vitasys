import os
from celery import Celery
from celery.schedules import crontab

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Vitasys.settings')

CELERY_BEAT_SCHEDULE = {
    'auto-complete-appointments': {
        'task': 'appointments.tasks.auto_complete_appointments',
        'schedule': crontab(minute='*/5'),
    },
}

app = Celery('Vitasys')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
