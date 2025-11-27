from django.utils import timezone
from .models import Appointment
from datetime import datetime, timedelta
from django.utils import timezone
from datetime import datetime, timedelta

def get_doctor_queue_info(doctor):
    now = timezone.localtime()
    today = now.date()

    appointments = Appointment.objects.filter(
        doctor=doctor,
        appointment_date=today,
        status__in=['confirmed', 'completed']
    ).order_by('appointment_time')

    current_session = None
    ongoing = appointments.filter(
        appointment_time__lte=now.time(),
        appointment_time__gte=(now - timedelta(minutes=30)).time()
    ).first()

    if ongoing:
        session_start = ongoing.appointment_time
        session_end = (datetime.combine(today, session_start) + timedelta(minutes=30)).time()
        current_session = f"{session_start.strftime('%H:%M')} - {session_end.strftime('%H:%M')}"

    total_confirmed = appointments.count()
    estimated_wait = total_confirmed * 30  

    return {
        "current_queue_count": total_confirmed,
        "estimated_wait_time": estimated_wait,
        "current_session": current_session
    }

def get_available_slots(doctor, appointment_date):

    start_hour = 9
    end_hour = 17
    slot_duration_minutes = 30
    all_slots = []
    current_time = datetime.strptime(f"{start_hour}:00", "%H:%M")
    end_time = datetime.strptime(f"{end_hour}:00", "%H:%M")
    
    while current_time < end_time:
        all_slots.append(current_time.strftime("%H:%M"))
        current_time += timedelta(minutes=slot_duration_minutes)

    booked_appointments = Appointment.objects.filter(
        doctor=doctor,
        appointment_date=appointment_date,
        status__in=['pending', 'confirmed']
    ).values_list('appointment_time', flat=True)

    booked_slots = set()
    for time_obj in booked_appointments:
        if time_obj:
            booked_slots.add(time_obj.strftime("%H:%M"))
    available_slots = [slot for slot in all_slots if slot not in booked_slots]
    today = timezone.now().date()
    if appointment_date == today:
        current_datetime = timezone.now()
        current_time_str = current_datetime.strftime("%H:%M")
        future_threshold = (current_datetime + timedelta(minutes=30)).strftime("%H:%M")
        available_slots = [slot for slot in available_slots if slot >= future_threshold]
    
    return available_slots