from django.db import models
from django.conf import settings
from Authapi.models import Doctor, Patient 
from appointments.models import Appointment


class ChatRoom(models.Model):
    ROOM_TYPES = [
        ('patient_doctor', 'Patient-Doctor Chat'),
        ('doctor_doctor', 'Doctor-Doctor Chat'),
    ]

    room_type = models.CharField(max_length=20, choices=ROOM_TYPES, db_index=True)
    name = models.CharField(max_length=200, blank=True, null=True)

    is_active = models.BooleanField(default=True)

    participants = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name='chat_rooms'
    )

    appointment = models.OneToOneField(
        Appointment,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='chat_room'
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']
        indexes = [
            models.Index(fields=['room_type', 'is_active']),
            models.Index(fields=['updated_at']),
        ]

    def __str__(self):
        return f"{self.get_room_type_display()} - Room #{self.id}"
    

class Message(models.Model):
    room = models.ForeignKey(
        ChatRoom,
        on_delete=models.CASCADE,
        related_name='messages'
    )
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE
    )
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    class Meta:
        ordering = ['timestamp']
        indexes = [
            models.Index(fields=['room', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.sender.username}: {self.content[:50]}"


class DoctorConnection(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
    ]

    from_doctor = models.ForeignKey(
        Doctor,
        on_delete=models.CASCADE,
        related_name='sent_requests'
    )
    to_doctor = models.ForeignKey(
        Doctor,
        on_delete=models.CASCADE,
        related_name='received_requests'
    )

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'
    )

    chat_room = models.OneToOneField(
        ChatRoom,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='doctor_connection'
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['from_doctor', 'to_doctor']
        indexes = [
            models.Index(fields=['to_doctor', 'status']),
        ]

    def __str__(self):
        return (
            f"Dr. {self.from_doctor.get_full_name()} → "
            f"Dr. {self.to_doctor.get_full_name()} ({self.status})"
        )
