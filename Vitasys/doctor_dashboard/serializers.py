from rest_framework import serializers
from Authapi.models import Doctor
from appointments.models import Appointment
from .models import DoctorReview
from django.utils import timezone
class DoctorDashboardProfileSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()
    email = serializers.CharField(source='user.email', read_only=True)
    class Meta:
        model = Doctor
        fields = [
            'id',
            'full_name',
            'email',
            'specialization',
            'phone_number',
            'years_of_experience',
            'registration_number'
        ]
    def get_full_name(self, obj):
        return f"Dr. {obj.get_full_name()}"
class DashboardAppointmentSerializer(serializers.ModelSerializer):
    patient_name = serializers.SerializerMethodField()
    patient_age = serializers.SerializerMethodField()
    patient_gender = serializers.CharField(source='patient.get_gender_display', read_only=True)
    patient_phone = serializers.CharField(source='patient.phone_number', read_only=True)
    patient_blood_group = serializers.CharField(source='patient.blood_group', read_only=True)
    appointment_time_formatted = serializers.SerializerMethodField()
    
    class Meta:
        model = Appointment
        fields = [
            'id',
            'patient_name',
            'patient_age',
            'patient_gender',
            'patient_phone',
            'patient_blood_group',
            'appointment_date',
            'appointment_time',
            'appointment_time_formatted',
            'reason',
            'status'
        ]
    
    def get_patient_name(self, obj):
        return obj.patient.get_full_name()
    
    def get_patient_age(self, obj):
        if obj.patient.date_of_birth:
            today = timezone.now().date()
            age = today.year - obj.patient.date_of_birth.year
            if today.month < obj.patient.date_of_birth.month or \
               (today.month == obj.patient.date_of_birth.month and today.day < obj.patient.date_of_birth.day):
                age -= 1
            return age
        return None
    
    def get_appointment_time_formatted(self, obj):
        if obj.appointment_time:
            return obj.appointment_time.strftime('%I:%M %p')
        return None



class DoctorCompleteProfileSerializer(serializers.ModelSerializer):
    email = serializers.CharField(source='user.email', read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    is_verified = serializers.BooleanField(source='user.is_verified', read_only=True)
    
    class Meta:
        model = Doctor
        fields = [
            'email',
            'username',
            'is_verified',
            'first_name',
            'last_name',
            'date_of_birth',
            'gender',
            'blood_group',
            'marital_status',
            'address',
            'city',
            'state',
            'pincode',
            'country',
            'registration_number',
            'specialization',
            'qualification',
            'years_of_experience',
            'department',
            'clinic_name',
            'phone_number',
            'alternate_phone_number',
            'alternate_email',
            'emergency_contact_person',
            'emergency_contact_number',
            'is_approved',
            'created_at',
            'updated_at'
        ]
class DoctorReviewSerializer(serializers.ModelSerializer):
    patient_name = serializers.SerializerMethodField()
    time_ago = serializers.SerializerMethodField()
    date_formatted = serializers.SerializerMethodField()
    
    class Meta:
        model = DoctorReview
        fields = [
            'id',
            'patient_name',
            'rating',
            'comment',
            'created_at',
            'date_formatted',
            'time_ago'
        ]
    
    def get_patient_name(self, obj):
        return obj.patient.get_full_name()
    
    def get_date_formatted(self, obj):
        return obj.created_at.strftime('%B %d, %Y')
    
    def get_time_ago(self, obj):
        now = timezone.now()
        diff = now - obj.created_at
        
        if diff.days > 365:
            years = diff.days // 365
            return f"{years} year{'s' if years > 1 else ''} ago"
        elif diff.days > 30:
            months = diff.days // 30
            return f"{months} month{'s' if months > 1 else ''} ago"
        elif diff.days > 0:
            return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours > 1 else ''} ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
        else:
            return "Just now"