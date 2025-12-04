from django.db import models
from appointments.models import Appointment
from Authapi.models import CustomUser

class VideoCall(models.Model):
    STATUS_CHOICES = [
        ('waiting', 'Waiting'),
        ('active', 'Active'),
        ('ended', 'Ended'),
    ]

    appointment = models.OneToOneField(Appointment, on_delete=models.CASCADE, related_name='video_call')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='waiting')
    initiated_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, related_name='initiated_calls')
    started_at = models.DateTimeField(null=True, blank=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Video Call'
        verbose_name_plural = 'Video Calls'

    def __str__(self):
        return f"Call for {self.appointment} - {self.status}"