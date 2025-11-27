from django.db import models
from Authapi.models import Doctor, Patient

class Appointment(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('confirmed', 'Confirmed'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]
    
    doctor = models.ForeignKey(
        Doctor, 
        on_delete=models.CASCADE, 
        related_name='appointments'
    )
    patient = models.ForeignKey(
        Patient, 
        on_delete=models.CASCADE, 
        related_name='appointments'
    )
    appointment_date = models.DateField()
    appointment_time = models.TimeField()
    reason = models.TextField(blank=True, null=True)
    status = models.CharField(
        max_length=20, 
        choices=STATUS_CHOICES, 
        default='pending'
    )
    notes = models.TextField(
        blank=True, 
        null=True, 
        help_text="Doctor's notes about the appointment"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-appointment_date', '-appointment_time']
        indexes = [
            models.Index(fields=['doctor', 'appointment_date']),
            models.Index(fields=['patient', 'appointment_date']),
            models.Index(fields=['status']),
            models.Index(fields=['doctor', 'status', 'appointment_date']),
        ]
        verbose_name = 'Appointment'
        verbose_name_plural = 'Appointments'
    
    def __str__(self):
        return f"{self.patient.get_full_name()} with Dr. {self.doctor.get_full_name()} on {self.appointment_date}"