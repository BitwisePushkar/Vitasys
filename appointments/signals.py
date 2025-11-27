from django.db.models.signals import post_save
from django.dispatch import receiver
from appointments.models import Appointment
from chat_room.models import ChatRoom

@receiver(post_save, sender=Appointment)
def create_chat_room_for_appointment(sender, instance, created, **kwargs):
    if instance.status != 'confirmed':
        return
    existing_room = ChatRoom.objects.filter(
        room_type='patient_doctor',
        participants=instance.patient.user,
        is_active=True
    ).filter(
        participants=instance.doctor.user
    ).first()

    if existing_room:
        instance.chat_room = existing_room
        instance.save(update_fields=['chat_room'])
        print(f"Reusing existing chat room {existing_room.id} for appointment {instance.id}")
        return

    chat_room = ChatRoom.objects.create(
        room_type='patient_doctor',
        is_active=True,
        appointment=instance
    )

    chat_room.participants.add(
        instance.patient.user,
        instance.doctor.user
    )

    print(f"Created new chat room {chat_room.id} for appointment {instance.id}")