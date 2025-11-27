from django.utils import timezone
from datetime import timedelta
from django.core.mail import send_mail
from django.conf import settings
from .models import Appointment
import logging
from celery import shared_task
logger = logging.getLogger(__name__)

@shared_task
def send_appointment_reminders():
    now = timezone.now()
    reminder_time = now + timedelta(minutes=30)

    upcoming_appointments = Appointment.objects.filter(
            appointment_date= reminder_time.date(),
            appointment_time__hour=reminder_time.hour,
            appointment_time__minute=reminder_time.minute,
            status='confirmed'
        ).select_related('doctor', 'patient')
    
    sent_count = 0
    
    for appointment in upcoming_appointments:
        try:

            send_patient_reminder(appointment.id)

            send_doctor_reminder(appointment.id)
            sent_count += 1
            
        except Exception as e:
            logger.error(f"Failed to send reminder for appointment {appointment.id}: {str(e)}")
    
    logger.info(f"Sent {sent_count} appointment reminders")
    return f"Sent {sent_count} reminders"

@shared_task
def send_patient_reminder(appointment_id):

    try:
        appointment = Appointment.objects.select_related('doctor', 'patient').get(id=appointment_id)
        patient = appointment.patient
        doctor = appointment.doctor

        patient_email = patient.user.email if hasattr(patient, 'user') else None
        
        if not patient_email:
            logger.warning(f"No email found for patient in appointment {appointment_id}")
            return False
        
        subject = f"Appointment Reminder - Dr. {doctor.user.get_full_name()}"
        
        message = f"""
Dear {patient.user.get_full_name()},

This is a reminder for your upcoming appointment:

Doctor: Dr. {doctor.user.get_full_name()}
Specialization: {doctor.specialization if hasattr(doctor, 'specialization') else 'N/A'}
Date: {appointment.appointment_date.strftime('%B %d, %Y')}
Time: {appointment.appointment_time.strftime('%I:%M %p')}
Reason: {appointment.reason if appointment.reason else 'General Consultation'}

Please arrive 10 minutes early to complete any necessary paperwork.

If you need to reschedule or cancel, please contact us as soon as possible.

Best regards,
Medtrax Hospital Management Team
        """
        
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[patient_email],
            fail_silently=False,
        )
        
        logger.info(f"Reminder sent to patient {patient.user.email} for appointment {appointment_id}")
        return True
        
    except Appointment.DoesNotExist:
        logger.error(f"Appointment {appointment_id} not found")
        return False
    except Exception as e:
        logger.error(f"Error sending patient reminder for appointment {appointment_id}: {str(e)}")
        return False

@shared_task
def send_doctor_reminder(appointment_id):

    try:
        appointment = Appointment.objects.select_related('doctor', 'patient').get(id=appointment_id)
        doctor = appointment.doctor
        patient = appointment.patient

        doctor_email = doctor.user.email if hasattr(doctor, 'user') else None
        
        if not doctor_email:
            logger.warning(f"No email found for doctor in appointment {appointment_id}")
            return False
        
        subject = f"Appointment Reminder - Patient: {patient.user.get_full_name()}"
        
        message = f"""
Dear Dr. {doctor.user.get_full_name()},

You have an upcoming appointment scheduled:

Patient: {patient.user.get_full_name()}
Date: {appointment.appointment_date.strftime('%B %d, %Y')}
Time: {appointment.appointment_time.strftime('%I:%M %p')}
Reason: {appointment.reason if appointment.reason else 'General Consultation'}
Status: {appointment.get_status_display()}

{f"Previous Notes: {appointment.notes}" if appointment.notes else ""}

Please review the patient's medical history before the appointment.

Best regards,
Medtrax Hospital Management Team
        """
        
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[doctor_email],
            fail_silently=False,
        )
        
        logger.info(f"Reminder sent to doctor {doctor.user.email} for appointment {appointment_id}")
        return True
        
    except Appointment.DoesNotExist:
        logger.error(f"Appointment {appointment_id} not found")
        return False
    except Exception as e:
        logger.error(f"Error sending doctor reminder for appointment {appointment_id}: {str(e)}")
        return False

@shared_task
def send_immediate_appointment_notification(appointment_id, notification_type='created'):
    """
    Send immediate notification when appointment is created/updated/cancelled
    
    Args:
        appointment_id: ID of the appointment
        notification_type: 'created', 'confirmed', 'cancelled', 'updated'
    """
    try:
        appointment = Appointment.objects.select_related('doctor', 'patient').get(id=appointment_id)
        

        if notification_type == 'created':
            send_appointment_created_notification(appointment)
        elif notification_type == 'confirmed':
            send_appointment_confirmed_notification(appointment)
        elif notification_type == 'cancelled':
            send_appointment_cancelled_notification(appointment)
            
        return True
        
    except Exception as e:
        logger.error(f"Error sending {notification_type} notification: {str(e)}")
        return False

def send_appointment_created_notification(appointment):

    patient_email = appointment.patient.user.email
    doctor_email = appointment.doctor.user.email

    send_mail(
        subject=f"Appointment Booked with Dr. {appointment.doctor.user.get_full_name()}",
        message=f"""
Dear {appointment.patient.user.get_full_name()},

Your appointment has been successfully booked!

Doctor: Dr. {appointment.doctor.user.get_full_name()}
Date: {appointment.appointment_date.strftime('%B %d, %Y')}
Time: {appointment.appointment_time.strftime('%I:%M %p')}
Status: {appointment.get_status_display()}

You will receive a reminder 24 hours before your appointment.

Best regards,
Medtrax Team
        """,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[patient_email],
        fail_silently=True,
    )

    send_mail(
        subject=f"New Appointment Request from {appointment.patient.user.get_full_name()}",
        message=f"""
Dear Dr. {appointment.doctor.user.get_full_name()},

A new appointment has been scheduled:

Patient: {appointment.patient.user.get_full_name()}
Date: {appointment.appointment_date.strftime('%B %d, %Y')}
Time: {appointment.appointment_time.strftime('%I:%M %p')}
Reason: {appointment.reason if appointment.reason else 'General Consultation'}

Please confirm or reschedule if needed.

Best regards,
Medtrax Team
        """,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[doctor_email],
        fail_silently=True,
    )

@shared_task
def send_appointment_confirmed_notification(appointment):

    send_mail(
        subject=f"Appointment Confirmed - Dr. {appointment.doctor.user.get_full_name()}",
        message=f"""
Dear {appointment.patient.user.get_full_name()},

Your appointment has been CONFIRMED!

Doctor: Dr. {appointment.doctor.user.get_full_name()}
Date: {appointment.appointment_date.strftime('%B %d, %Y')}
Time: {appointment.appointment_time.strftime('%I:%M %p')}

Please arrive 10 minutes early.

Best regards,
Medtrax Team
        """,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[appointment.patient.user.email],
        fail_silently=True,
    )

@shared_task
def send_appointment_cancelled_notification(appointment):

    message_base = f"""
Your appointment has been CANCELLED.

Doctor: Dr. {appointment.doctor.user.get_full_name()}
Patient: {appointment.patient.user.get_full_name()}
Date: {appointment.appointment_date.strftime('%B %d, %Y')}
Time: {appointment.appointment_time.strftime('%I:%M %p')}

If you need to reschedule, please book a new appointment.

Best regards,
Medtrax Team
    """

    send_mail(
        subject="Appointment Cancelled",
        message=f"Dear {appointment.patient.user.get_full_name()},\n\n{message_base}",
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[appointment.patient.user.email],
        fail_silently=True,
    )

    send_mail(
        subject="Appointment Cancelled",
        message=f"Dear Dr. {appointment.doctor.user.get_full_name()},\n\n{message_base}",
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[appointment.doctor.user.email],
        fail_silently=True,
    )

@shared_task
def auto_complete_appointments():
    from django.utils import timezone
    from datetime import timedelta
    
    now = timezone.now()
    cutoff_time = now - timedelta(minutes=30)
    
    expired_appointments = Appointment.objects.filter(
        appointment_date__lte=now.date(), 
        status='confirmed'
    )

    completed_count = 0
    for appointment in expired_appointments:
        appointment_datetime = timezone.make_aware(
            timezone.datetime.combine(appointment.appointment_date, appointment.appointment_time)
        )
        if appointment_datetime + timedelta(minutes=30) <= now:
            appointment.status = 'completed'
            appointment.save()
            completed_count += 1
            logger.info(f"Auto-completed appointment {appointment.id}")
    
    logger.info(f"Auto-completed {completed_count} appointments")
    return f"Completed {completed_count} appointments"