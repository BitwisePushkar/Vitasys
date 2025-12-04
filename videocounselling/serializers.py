from rest_framework import serializers
from .models import VideoCall


class VideoCallSerializer(serializers.ModelSerializer):
    appointment_id = serializers.IntegerField(source='appointment.id', read_only=True)
    doctor_name = serializers.SerializerMethodField()
    patient_name = serializers.SerializerMethodField()

    class Meta:
        model = VideoCall
        fields = [
            'id',
            'appointment_id',
            'status',
            'initiated_by',
            'doctor_name',
            'patient_name',
            'started_at',
            'ended_at',
            'created_at',
        ]
        read_only_fields = fields

    def get_doctor_name(self, obj):
        return obj.appointment.doctor.get_full_name()

    def get_patient_name(self, obj):
        return obj.appointment.patient.get_full_name()