from rest_framework.permissions import BasePermission
from appointments.models import Appointment

class IsAppointmentParticipant(BasePermission):
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        return True

    def has_object_permission(self, request, view, obj):
        user = request.user
        appointment = obj.appointment
        is_doctor = hasattr(user, 'doctor_profile') and appointment.doctor == user.doctor_profile
        is_patient = hasattr(user, 'patient_profile') and appointment.patient == user.patient_profile
        return is_doctor or is_patient