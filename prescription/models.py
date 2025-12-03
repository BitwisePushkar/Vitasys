from django.db import models
from Authapi.models import Doctor, Patient
from appointments.models import Appointment


class Prescription(models.Model):
    doctor = models.ForeignKey(
        Doctor,
        on_delete=models.CASCADE,
        related_name='prescriptions'
    )
    patient = models.ForeignKey(
        Patient,
        on_delete=models.CASCADE,
        related_name='prescriptions'
    )
    appointment = models.ForeignKey(
        Appointment,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='prescriptions',
        help_text="Associated appointment if any"
    )
    chief_complaint = models.TextField(
        help_text="Patient's main complaint"
    )
    diagnosis = models.TextField(
        help_text="Doctor's diagnosis"
    )
    blood_pressure = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        help_text="e.g., 120/80"
    )
    temperature = models.DecimalField(
        max_digits=4,
        decimal_places=1,
        blank=True,
        null=True,
        help_text="Temperature in Fahrenheit"
    )
    pulse_rate = models.IntegerField(
        blank=True,
        null=True,
        help_text="Pulse rate per minute"
    )
    weight = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        blank=True,
        null=True,
        help_text="Weight in kg"
    )
    additional_notes = models.TextField(
        blank=True,
        null=True,
        help_text="Any additional instructions or notes"
    )
    follow_up_date = models.DateField(
        blank=True,
        null=True,
        help_text="Recommended follow-up date"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['doctor', '-created_at']),
            models.Index(fields=['patient', '-created_at']),
            models.Index(fields=['appointment']),
        ]
        verbose_name = 'Prescription'
        verbose_name_plural = 'Prescriptions'
    
    def __str__(self):
        return f"Prescription for {self.patient.get_full_name()} by Dr. {self.doctor.get_full_name()} on {self.created_at.date()}"


class Medication(models.Model):
    DOSAGE_FREQUENCY = [
        ('once_daily', 'Once Daily'),
        ('twice_daily', 'Twice Daily'),
        ('thrice_daily', 'Three Times Daily'),
        ('four_times_daily', 'Four Times Daily'),
        ('as_needed', 'As Needed'),
        ('before_meals', 'Before Meals'),
        ('after_meals', 'After Meals'),
        ('at_bedtime', 'At Bedtime'),
    ]
    
    DURATION_UNIT = [
        ('days', 'Days'),
        ('weeks', 'Weeks'),
        ('months', 'Months'),
    ]
    
    prescription = models.ForeignKey(
        Prescription,
        on_delete=models.CASCADE,
        related_name='medications'
    )
    
    medicine_name = models.CharField(
        max_length=200,
        help_text="Name of the medicine"
    )
    dosage = models.CharField(
        max_length=100,
        help_text="e.g., 500mg, 10ml, 1 tablet"
    )
    frequency = models.CharField(
        max_length=50,
        choices=DOSAGE_FREQUENCY,
        help_text="How often to take the medicine"
    )
    duration = models.IntegerField(
        help_text="Duration number"
    )
    duration_unit = models.CharField(
        max_length=10,
        choices=DURATION_UNIT,
        default='days'
    )
    instructions = models.TextField(
        blank=True,
        null=True,
        help_text="Special instructions for this medication"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['id']
        verbose_name = 'Medication'
        verbose_name_plural = 'Medications'
    
    def __str__(self):
        return f"{self.medicine_name} - {self.dosage} {self.get_frequency_display()}"


class LabTest(models.Model):
    prescription = models.ForeignKey(
        Prescription,
        on_delete=models.CASCADE,
        related_name='lab_tests'
    )
    
    test_name = models.CharField(
        max_length=200,
        help_text="Name of the lab test"
    )
    instructions = models.TextField(
        blank=True,
        null=True,
        help_text="Special instructions for the test"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['id']
        verbose_name = 'Lab Test'
        verbose_name_plural = 'Lab Tests'
    
    def __str__(self):
        return f"{self.test_name} for {self.prescription.patient.get_full_name()}"