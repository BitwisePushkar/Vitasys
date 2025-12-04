from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from appointments.models import Appointment
from .models import VideoCall
from .serializers import VideoCallSerializer


class InitiateVideoCall(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, appointment_id):
        try:
            appointment = Appointment.objects.get(id=appointment_id)
        except Appointment.DoesNotExist:
            return Response({'error': 'Appointment not found'}, status=status.HTTP_404_NOT_FOUND)

        user = request.user
        if not hasattr(user, 'doctor_profile') or appointment.doctor != user.doctor_profile:
            return Response({'error': 'Only the doctor can initiate a call'}, status=status.HTTP_403_FORBIDDEN)

        if appointment.status != 'confirmed':
            return Response({'error': 'Appointment must be confirmed to start a call'}, status=status.HTTP_400_BAD_REQUEST)

        video_call, created = VideoCall.objects.get_or_create(
            appointment=appointment,
            defaults={'initiated_by': user, 'status': 'waiting'}
        )

        if not created and video_call.status == 'ended':
            video_call.status = 'waiting'
            video_call.started_at = None
            video_call.ended_at = None
            video_call.save()

        serializer = VideoCallSerializer(video_call)
        return Response(serializer.data, status=status.HTTP_200_OK)


class JoinVideoCall(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, appointment_id):
        try:
            appointment = Appointment.objects.get(id=appointment_id)
        except Appointment.DoesNotExist:
            return Response({'error': 'Appointment not found'}, status=status.HTTP_404_NOT_FOUND)

        user = request.user
        is_doctor = hasattr(user, 'doctor_profile') and appointment.doctor == user.doctor_profile
        is_patient = hasattr(user, 'patient_profile') and appointment.patient == user.patient_profile

        if not is_doctor and not is_patient:
            return Response({'error': 'You are not a participant of this appointment'}, status=status.HTTP_403_FORBIDDEN)

        try:
            video_call = VideoCall.objects.get(appointment=appointment)
        except VideoCall.DoesNotExist:
            return Response({'error': 'No active call for this appointment'}, status=status.HTTP_404_NOT_FOUND)

        if video_call.status == 'ended':
            return Response({'error': 'This call has already ended'}, status=status.HTTP_400_BAD_REQUEST)

        if video_call.status == 'waiting':
            video_call.status = 'active'
            video_call.started_at = timezone.now()
            video_call.save()

        serializer = VideoCallSerializer(video_call)
        return Response(serializer.data, status=status.HTTP_200_OK)


class EndVideoCall(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, appointment_id):
        try:
            appointment = Appointment.objects.get(id=appointment_id)
        except Appointment.DoesNotExist:
            return Response({'error': 'Appointment not found'}, status=status.HTTP_404_NOT_FOUND)

        user = request.user
        is_doctor = hasattr(user, 'doctor_profile') and appointment.doctor == user.doctor_profile
        is_patient = hasattr(user, 'patient_profile') and appointment.patient == user.patient_profile

        if not is_doctor and not is_patient:
            return Response({'error': 'You are not a participant of this appointment'}, status=status.HTTP_403_FORBIDDEN)

        try:
            video_call = VideoCall.objects.get(appointment=appointment)
        except VideoCall.DoesNotExist:
            return Response({'error': 'No call found'}, status=status.HTTP_404_NOT_FOUND)

        video_call.status = 'ended'
        video_call.ended_at = timezone.now()
        video_call.save()

        serializer = VideoCallSerializer(video_call)
        return Response(serializer.data, status=status.HTTP_200_OK)


class VideoCallStatus(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, appointment_id):
        try:
            appointment = Appointment.objects.get(id=appointment_id)
        except Appointment.DoesNotExist:
            return Response({'error': 'Appointment not found'}, status=status.HTTP_404_NOT_FOUND)

        user = request.user
        is_doctor = hasattr(user, 'doctor_profile') and appointment.doctor == user.doctor_profile
        is_patient = hasattr(user, 'patient_profile') and appointment.patient == user.patient_profile

        if not is_doctor and not is_patient:
            return Response({'error': 'You are not a participant of this appointment'}, status=status.HTTP_403_FORBIDDEN)

        try:
            video_call = VideoCall.objects.get(appointment=appointment)
        except VideoCall.DoesNotExist:
            return Response({'error': 'No call found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = VideoCallSerializer(video_call)
        return Response(serializer.data, status=status.HTTP_200_OK)