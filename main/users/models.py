from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import timedelta

OTP_SEND_LIMIT = 5

GENDER_CHOICES = [('M', 'Male'), ('F', 'Female'), ('O', 'Other')]

BLOOD_GROUP_CHOICES = [('A+', 'A+'), ('A-', 'A-'),('B+', 'B+'), ('B-', 'B-'),('AB+', 'AB+'), ('AB-', 'AB-'),
                       ('O+', 'O+'), ('O-', 'O-'),]

class CustomUser(AbstractUser):
    ROLE_CHOICES = [('doctor','Doctor'),('patient','Patient'),('nurse','Nurse'),('pharmacist','Pharmacist'),('superadmin','Super Admin'),]

    role  = models.CharField(max_length=15, choices=ROLE_CHOICES, null=True, blank=True)
    email  = models.EmailField(unique=True, db_index=True)
    is_verified = models.BooleanField(default=False)
    is_profile_complete = models.BooleanField(default=False)
    otp = models.CharField(max_length=6, null=True, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    otp_attempts = models.IntegerField(default=0)
    otp_locked_until = models.DateTimeField(null=True, blank=True)
    otp_type = models.CharField(max_length=15, null=True, blank=True,help_text=("'verification' during signup | "
                                                                                "'reset' after forgot-password | "))
    otp_send_count = models.IntegerField(default=0,help_text=f"OTP emails sent this session. Hard cap: {OTP_SEND_LIMIT}.")
    login_attempts = models.IntegerField(default=0)
    login_locked_until = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['username']),
            models.Index(fields=['role']),
            models.Index(fields=['is_verified']),
            models.Index(fields=['is_profile_complete']),
        ]
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self):
        return f"{self.username or self.email} ({self.role or 'unassigned'})"

    def is_otp_locked(self):
        if self.otp_locked_until and timezone.now() < self.otp_locked_until:
            return True
        if self.otp_locked_until and timezone.now() >= self.otp_locked_until:
            self.otp_locked_until = None
            self.otp_attempts = 0
            self.save(update_fields=['otp_locked_until', 'otp_attempts'])
        return False

    def is_otp_expired(self):
        if not self.otp_created_at:
            return True
        return timezone.now() - self.otp_created_at > timedelta(minutes=3)

    def is_otp_send_limit_reached(self):
        return self.otp_send_count >= OTP_SEND_LIMIT

    def reset_otp_attempts(self):
        self.otp_attempts = 0
        self.otp_locked_until = None
        self.save(update_fields=['otp_attempts', 'otp_locked_until'])

    def clear_otp(self):
        self.otp = None
        self.otp_created_at = None
        self.otp_attempts = 0
        self.otp_locked_until= None
        self.otp_type = None
        self.otp_send_count = 0
        self.save(update_fields=['otp', 'otp_created_at', 'otp_attempts','otp_locked_until', 'otp_type', 'otp_send_count',])

    def is_login_locked(self):
        if self.login_locked_until and timezone.now() < self.login_locked_until:
            return True
        if self.login_locked_until and timezone.now() >= self.login_locked_until:
            self.login_locked_until = None
            self.login_attempts = 0
            self.save(update_fields=['login_locked_until', 'login_attempts'])
        return False

    def reset_login_attempts(self):
        self.login_attempts = 0
        self.login_locked_until = None
        self.save(update_fields=['login_attempts', 'login_locked_until'])

class Doctor(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='doctor_profile')
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    date_of_birth = models.DateField()
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    blood_group = models.CharField(max_length=5, choices=BLOOD_GROUP_CHOICES)
    marital_status = models.CharField(max_length=20, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100, blank=True, null=True)
    pincode = models.CharField(max_length=10, blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    registration_number = models.CharField(max_length=50, blank=True, null=True, help_text="Medical Council Registration Number")
    specialization = models.CharField(max_length=100, blank=True, null=True)
    qualification = models.CharField(max_length=200, blank=True, null=True)
    years_of_experience = models.IntegerField(blank=True, null=True)
    department = models.CharField(max_length=100, blank=True, null=True)
    clinic_name = models.CharField(max_length=200, blank=True, null=True)
    phone_number = models.CharField(max_length=15, unique=True)
    alternate_phone_number = models.CharField(max_length=15, blank=True, null=True)
    alternate_email = models.EmailField(blank=True, null=True)
    emergency_contact_person = models.CharField(max_length=100, blank=True, null=True)
    emergency_contact_number = models.CharField(max_length=15, blank=True, null=True)
    is_approved = models.BooleanField(default=False, help_text="Admin must approve before doctor can access clinical features")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        constraints = [models.UniqueConstraint(fields=['phone_number'], name='unique_doctor_phone')]
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['phone_number']),
            models.Index(fields=['is_approved']),
            models.Index(fields=['city']),
            models.Index(fields=['specialization']),
        ]
        verbose_name = 'Doctor'
        verbose_name_plural = 'Doctors'

    def __str__(self):
        return f"Dr. {self.first_name} {self.last_name} — {self.specialization or 'General'}"

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"

class Patient(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='patient_profile')
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    date_of_birth = models.DateField()
    blood_group = models.CharField(max_length=5, choices=BLOOD_GROUP_CHOICES)
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    city = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=15, unique=True)
    emergency_contact = models.CharField(max_length=15, blank=True, null=True)
    emergency_email = models.EmailField(blank=True, null=True)
    is_insurance = models.BooleanField(default=False)
    ins_company_name = models.CharField(max_length=100, blank=True, null=True)
    ins_policy_number = models.CharField(max_length=50, blank=True, null=True)
    known_allergies = models.TextField(blank=True, null=True, help_text="Comma-separated list")
    chronic_diseases = models.TextField(blank=True, null=True, help_text="Comma-separated list")
    previous_surgeries = models.TextField(blank=True, null=True)
    family_medical_history = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        constraints = [models.UniqueConstraint(fields=['phone_number'], name='unique_patient_phone')]
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['phone_number']),
            models.Index(fields=['city']),
        ]
        verbose_name = 'Patient'
        verbose_name_plural = 'Patients'

    def __str__(self):
        return f"{self.first_name} {self.last_name} — Patient"

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"

class Nurse(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='nurse_profile')
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    date_of_birth = models.DateField()
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    blood_group = models.CharField(max_length=5, choices=BLOOD_GROUP_CHOICES)
    phone_number = models.CharField(max_length=15, unique=True)
    department = models.CharField(max_length=100)
    qualification = models.CharField(max_length=200, blank=True, null=True,help_text="e.g. B.Sc Nursing, GNM, Post Basic B.Sc")
    years_of_experience = models.IntegerField(blank=True, null=True)
    employee_id = models.CharField(max_length=50, unique=True, blank=True, null=True)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100, blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    is_approved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        constraints = [models.UniqueConstraint(fields=['phone_number'], name='unique_nurse_phone')]
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['phone_number']),
            models.Index(fields=['department']),
            models.Index(fields=['is_approved']),
        ]
        verbose_name        = 'Nurse'
        verbose_name_plural = 'Nurses'

    def __str__(self):
        return f"{self.first_name} {self.last_name} — Nurse ({self.department})"

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"

class Pharmacist(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='pharmacist_profile')
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    date_of_birth = models.DateField()
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    blood_group = models.CharField(max_length=5, choices=BLOOD_GROUP_CHOICES)
    phone_number = models.CharField(max_length=15, unique=True)
    license_number = models.CharField(max_length=50, unique=True, blank=True, null=True,help_text="Pharmacy Council Registration / License Number")
    qualification = models.CharField(max_length=200, blank=True, null=True,help_text="e.g. B.Pharm, M.Pharm, D.Pharm")
    years_of_experience = models.IntegerField(blank=True, null=True)
    employee_id = models.CharField(max_length=50, unique=True, blank=True, null=True)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100, blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    is_approved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        constraints = [models.UniqueConstraint(fields=['phone_number'], name='unique_pharmacist_phone')]
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['phone_number']),
            models.Index(fields=['license_number']),
            models.Index(fields=['is_approved']),
        ]
        verbose_name        = 'Pharmacist'
        verbose_name_plural = 'Pharmacists'

    def __str__(self):
        return f"{self.first_name} {self.last_name} — Pharmacist"

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"