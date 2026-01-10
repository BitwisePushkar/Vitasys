from django.db import models
from Authapi.models import Doctor, Patient

class DoctorReview(models.Model):
    RATING_CHOICES = [(i, f'{i} Star{"s" if i > 1 else ""}') for i in range(1, 6)]
    
    doctor = models.ForeignKey(
        Doctor, 
        on_delete=models.CASCADE, 
        related_name='reviews'
    )
    patient = models.ForeignKey(
        Patient, 
        on_delete=models.CASCADE, 
        related_name='given_reviews'
    )
    rating = models.IntegerField(choices=RATING_CHOICES)
    comment = models.TextField()
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        unique_together = ['doctor', 'patient'] 
        indexes = [
            models.Index(fields=['doctor', '-created_at']),
            models.Index(fields=['rating']),
        ]
        verbose_name = 'Doctor Review'
        verbose_name_plural = 'Doctor Reviews'
    
    def __str__(self):
        return f"{self.patient.get_full_name()} rated Dr. {self.doctor.get_full_name()} - {self.rating}★"



    