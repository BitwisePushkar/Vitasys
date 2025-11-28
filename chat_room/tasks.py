from django.utils import timezone
from datetime import datetime, timedelta
from celery import shared_task
from .models import ChatRoom
from django.utils.timezone import is_aware


@shared_task
def disable_expired_chats():
    now = timezone.now()

    rooms = ChatRoom.objects.filter(
        room_type='patient_doctor',
        is_active=True,
        appointment__isnull=False
    )

    disabled_count = 0

    for room in rooms:
        appt = room.appointment
        appt_datetime = datetime.combine(appt.appointment_date, appt.appointment_time)
        if not is_aware(appt_datetime):
            appt_datetime = timezone.make_aware(appt_datetime)

        if appt_datetime < now:
            room.is_active = False
            room.save()
            disabled_count += 1

    return f"Disabled {disabled_count} expired chats"


@shared_task
def delete_old_chats():
    now = timezone.now()
    cutoff = now - timedelta(days=1)

    rooms = ChatRoom.objects.filter(
        room_type='patient_doctor',
        is_active=False,
        appointment__isnull=False
    )

    deleted_count = 0

    for room in rooms:
        appt = room.appointment
        appt_datetime = datetime.combine(appt.appointment_date, appt.appointment_time)
        if not is_aware(appt_datetime):
            appt_datetime = timezone.make_aware(appt_datetime)

        if appt_datetime < cutoff:
            room.delete()
            deleted_count += 1

    return f"Deleted {deleted_count} old chats"
