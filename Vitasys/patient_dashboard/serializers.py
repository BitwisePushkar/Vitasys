from rest_framework import serializers
from Authapi.models  import Patient
from appointments.models import Appointment

class PatientDashboardSerializer(serializers.ModelSerializer):
    class Meta:
        model = Patient
        fields = [
            'first_name',
            'last_name', 
            'date_of_birth',
            'blood_group',
            'known_allergies',
            'chronic_diseases'
        ]


class PatientCompleteProfileSerializer(serializers.ModelSerializer):
    email = serializers.CharField(source='user.email', read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    is_verified = serializers.BooleanField(source='user.is_verified', read_only=True)
    
    class Meta:
        model = Patient
        fields = [
            'email',
            'username',
            'is_verified',
            'first_name',
            'last_name',
            'date_of_birth',
            'blood_group',
            'gender',
            'city',
            'phone_number',
            'emergency_contact',
            'emergency_email',
            'is_insurance',
            'ins_company_name',
            'ins_policy_number',
            'known_allergies',
            'chronic_diseases',
            'previous_surgeries',
            'family_medical_history',
            'created_at',
            'updated_at'
        ]
class DashboardAppointmentSerializer(serializers.ModelSerializer):
    doctor_name = serializers.SerializerMethodField()

    class Meta:
        model = Appointment
        fields = [
            'id',
            'doctor_name',
            'appointment_date',
            'appointment_time',
            'reason',
            'status'
        ]
    def get_doctor_name(self, obj):
        return f"Dr. {obj.doctor.get_full_name()}"

