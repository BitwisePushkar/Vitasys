from rest_framework import serializers
from .models import Prescription, Medication, LabTest
from Authapi.models import Patient


class MedicationSerializer(serializers.ModelSerializer):
    frequency_display = serializers.CharField(
        source='get_frequency_display',
        read_only=True
    )
    duration_unit_display = serializers.CharField(
        source='get_duration_unit_display',
        read_only=True
    )
    
    class Meta:
        model = Medication
        fields = [
            'id',
            'medicine_name',
            'dosage',
            'frequency',
            'frequency_display',
            'duration',
            'duration_unit',
            'duration_unit_display',
            'instructions'
        ]


class LabTestSerializer(serializers.ModelSerializer):
    class Meta:
        model = LabTest
        fields = ['id', 'test_name', 'instructions']


class CreatePrescriptionSerializer(serializers.ModelSerializer):
    medications = MedicationSerializer(many=True)
    lab_tests = LabTestSerializer(many=True, required=False)
    
    class Meta:
        model = Prescription
        fields = [
            'patient',
            'appointment',
            'chief_complaint',
            'diagnosis',
            'blood_pressure',
            'temperature',
            'pulse_rate',
            'weight',
            'additional_notes',
            'follow_up_date',
            'medications',
            'lab_tests'
        ]
    
    def validate_patient(self, value):
        """Ensure doctor has had appointment with this patient"""
        request = self.context.get('request')
        if request and hasattr(request.user, 'doctor_profile'):
            doctor = request.user.doctor_profile
            from appointments.models import Appointment
            
            # Check if doctor has had any appointment with this patient
            has_appointment = Appointment.objects.filter(
                doctor=doctor,
                patient=value,
                status__in=['confirmed', 'completed']
            ).exists()
            
            if not has_appointment:
                raise serializers.ValidationError(
                    "You can only create prescriptions for patients you've had appointments with."
                )
        return value
    
    def validate_medications(self, value):
        if not value or len(value) == 0:
            raise serializers.ValidationError(
                "At least one medication is required."
            )
        return value
    
    def validate(self, data):
        # If appointment is provided, ensure it's between the doctor and patient
        appointment = data.get('appointment')
        patient = data.get('patient')
        
        if appointment:
            request = self.context.get('request')
            if request and hasattr(request.user, 'doctor_profile'):
                doctor = request.user.doctor_profile
                
                if appointment.doctor != doctor:
                    raise serializers.ValidationError(
                        "This appointment does not belong to you."
                    )
                
                if appointment.patient != patient:
                    raise serializers.ValidationError(
                        "The appointment does not match the selected patient."
                    )
        
        return data
    
    def create(self, validated_data):
        medications_data = validated_data.pop('medications')
        lab_tests_data = validated_data.pop('lab_tests', [])
        prescription = Prescription.objects.create(**validated_data)
        
        for med_data in medications_data:
            Medication.objects.create(prescription=prescription, **med_data)
        
        for test_data in lab_tests_data:
            LabTest.objects.create(prescription=prescription, **test_data)
        
        return prescription


class PrescriptionDetailSerializer(serializers.ModelSerializer):
    doctor_name = serializers.SerializerMethodField()
    doctor_specialization = serializers.CharField(
        source='doctor.specialization',
        read_only=True
    )
    doctor_registration_number = serializers.CharField(
        source='doctor.registration_number',
        read_only=True
    )
    doctor_phone = serializers.CharField(
        source='doctor.phone_number',
        read_only=True
    )
    
    patient_name = serializers.SerializerMethodField()
    patient_age = serializers.SerializerMethodField()
    patient_gender = serializers.CharField(
        source='patient.get_gender_display',
        read_only=True
    )
    patient_phone = serializers.CharField(
        source='patient.phone_number',
        read_only=True
    )
    
    medications = MedicationSerializer(many=True, read_only=True)
    lab_tests = LabTestSerializer(many=True, read_only=True)
    
    class Meta:
        model = Prescription
        fields = [
            'id',
            'doctor_name',
            'doctor_specialization',
            'doctor_registration_number',
            'doctor_phone',
            'patient_name',
            'patient_age',
            'patient_gender',
            'patient_phone',
            'chief_complaint',
            'diagnosis',
            'blood_pressure',
            'temperature',
            'pulse_rate',
            'weight',
            'medications',
            'lab_tests',
            'additional_notes',
            'follow_up_date',
            'created_at'
        ]
    
    def get_doctor_name(self, obj):
        return f"Dr. {obj.doctor.get_full_name()}"
    
    def get_patient_name(self, obj):
        return obj.patient.get_full_name()
    
    def get_patient_age(self, obj):
        from django.utils import timezone
        if obj.patient.date_of_birth:
            today = timezone.now().date()
            age = today.year - obj.patient.date_of_birth.year
            if today.month < obj.patient.date_of_birth.month or \
               (today.month == obj.patient.date_of_birth.month and today.day < obj.patient.date_of_birth.day):
                age -= 1
            return age
        return None


class PrescriptionListSerializer(serializers.ModelSerializer):
    doctor_name = serializers.SerializerMethodField()
    patient_name = serializers.SerializerMethodField()
    medication_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Prescription
        fields = [
            'id',
            'doctor_name',
            'patient_name',
            'diagnosis',
            'medication_count',
            'created_at'
        ]
    
    def get_doctor_name(self, obj):
        return f"Dr. {obj.doctor.get_full_name()}"
    
    def get_patient_name(self, obj):
        return obj.patient.get_full_name()
    
    def get_medication_count(self, obj):
        return obj.medications.count()


class DoctorPatientListSerializer(serializers.ModelSerializer):
    patient_name = serializers.SerializerMethodField()
    patient_age = serializers.SerializerMethodField()
    patient_gender = serializers.CharField(
        source='get_gender_display',
        read_only=True
    )
    last_appointment = serializers.SerializerMethodField()
    total_appointments = serializers.SerializerMethodField()
    prescription_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Patient
        fields = [
            'id',
            'patient_name',
            'patient_age',
            'patient_gender',
            'phone_number',
            'blood_group',
            'last_appointment',
            'total_appointments',
            'prescription_count'
        ]
    
    def get_patient_name(self, obj):
        return obj.get_full_name()
    
    def get_patient_age(self, obj):
        from django.utils import timezone
        if obj.date_of_birth:
            today = timezone.now().date()
            age = today.year - obj.date_of_birth.year
            if today.month < obj.date_of_birth.month or \
               (today.month == obj.date_of_birth.month and today.day < obj.date_of_birth.day):
                age -= 1
            return age
        return None
    
    def get_last_appointment(self, obj):
        from appointments.models import Appointment
        doctor = self.context.get('doctor')
        if doctor:
            last_apt = Appointment.objects.filter(
                doctor=doctor,
                patient=obj,
                status__in=['confirmed', 'completed']
            ).order_by('-appointment_date', '-appointment_time').first()
            
            if last_apt:
                return {
                    'date': last_apt.appointment_date,
                    'time': last_apt.appointment_time
                }
        return None
    
    def get_total_appointments(self, obj):
        from appointments.models import Appointment
        doctor = self.context.get('doctor')
        if doctor:
            return Appointment.objects.filter(
                doctor=doctor,
                patient=obj,
                status__in=['confirmed', 'completed']
            ).count()
        return 0
    
    def get_prescription_count(self, obj):
        doctor = self.context.get('doctor')
        if doctor:
            return Prescription.objects.filter(
                doctor=doctor,
                patient=obj
            ).count()
        return 0