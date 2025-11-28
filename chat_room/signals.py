from django.db.models.signals import post_save
from django.dispatch import receiver
from appointments.models import Appointment
from chat_room.models import ChatRoom
import logging

logger = logging.getLogger(__name__)


@receiver(post_save, sender=Appointment)
def manage_patient_doctor_chat(sender, instance, created, **kwargs):
    """
    Creates chat room when appointment is confirmed.
    Deactivates chat room when appointment is cancelled.
    """
    logger.info(f"🔔 Signal fired: Appointment {instance.id}, Status: '{instance.status}', Created: {created}")
    
    # ✅ Create chat room when status is 'confirmed'
    if instance.status == 'confirmed':
        logger.info(f"✅ Status is 'confirmed', creating/checking chat room...")
        
        # Check if chat room already exists
        existing_room = ChatRoom.objects.filter(appointment=instance).first()
        
        if existing_room:
            if not existing_room.is_active:
                existing_room.is_active = True
                existing_room.save()
                logger.info(f"♻️ Existing chat room reactivated: ID={existing_room.id}")
            else:
                logger.info(f"✅ Chat room already exists and is active: ID={existing_room.id}")
            return
        
        # Create new chat room
        try:
            room = ChatRoom.objects.create(
                appointment=instance,
                room_type='patient_doctor',
                is_active=True,
            )
            room.participants.add(instance.patient.user, instance.doctor.user)
            logger.info(f"🆕 NEW chat room created: ID={room.id}")
            logger.info(f"👥 Participants added: Patient={instance.patient.user.id}, Doctor={instance.doctor.user.id}")
        except Exception as e:
            logger.error(f"❌ Failed to create chat room: {e}")
        
        return
    
    # ✅ Deactivate chat room when cancelled
    elif instance.status == 'cancelled':
        logger.info(f"🚫 Status is 'cancelled', deactivating chat room...")
        try:
            room = ChatRoom.objects.get(appointment=instance)
            room.is_active = False
            room.save()
            logger.info(f"🔒 Chat room deactivated: ID={room.id}")
        except ChatRoom.DoesNotExist:
            logger.warning(f"⚠️ No chat room found for cancelled appointment {instance.id}")
    else:
        logger.info(f"ℹ️ Status is '{instance.status}', no chat action taken")