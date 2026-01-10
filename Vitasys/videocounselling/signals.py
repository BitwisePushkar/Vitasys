from django.db.models.signals import post_save
from django.dispatch import receiver
from appointments.models import Appointment
from .models import VideoCall
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.utils import timezone

@receiver(post_save, sender=Appointment)
def handle_appointment_status_change(sender, instance, **kwargs):
    """
    Automatically end video calls when an appointment is completed or cancelled.
    """
    if instance.status in ['completed', 'cancelled']:
        try:
            video_call = VideoCall.objects.get(appointment=instance)
            if video_call.status != 'ended':
                video_call.status = 'ended'
                video_call.ended_at = timezone.now()
                video_call.save()
                
                # Broadcast termination to WebSockets
                channel_layer = get_channel_layer()
                async_to_sync(channel_layer.group_send)(
                    f'video_{instance.id}',
                    {
                        'type': 'call_ended',
                        'sender_id': None
                    }
                )
        except VideoCall.DoesNotExist:
            pass
