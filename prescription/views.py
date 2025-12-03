from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.db.models import Q
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import Prescription
from .serializers import (
    CreatePrescriptionSerializer,
    PrescriptionDetailSerializer,
    PrescriptionListSerializer,
    DoctorPatientListSerializer
)
from Authapi.models import Patient
from appointments.models import Appointment


class DoctorPatientsListView(APIView):
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_summary="Get doctor's patients list",
        operation_description="Retrieve all patients the authenticated doctor has had confirmed/completed appointments with",
        responses={
            200: openapi.Response(
                description="List of patients",
                schema=DoctorPatientListSerializer(many=True)
            ),
            403: openapi.Response(description="Only doctors can access this endpoint")
        },
        tags=['Doctor Prescriptions']
    )

    def get(self, request):
        try:
            doctor = request.user.doctor_profile
            patient_ids = Appointment.objects.filter(
                doctor=doctor,
                status__in=['confirmed', 'completed']
            ).values_list('patient_id', flat=True).distinct()
            patients = Patient.objects.filter(
                id__in=patient_ids
            ).prefetch_related('appointments')
            patients_with_last_apt = []
            for patient in patients:
                last_apt = Appointment.objects.filter(
                    doctor=doctor,
                    patient=patient,
                    status__in=['confirmed', 'completed']
                ).order_by('-appointment_date', '-appointment_time').first()
                
                if last_apt:
                    patients_with_last_apt.append((patient, last_apt.appointment_date, last_apt.appointment_time))
            patients_with_last_apt.sort(key=lambda x: (x[1], x[2]), reverse=True)
            sorted_patients = [item[0] for item in patients_with_last_apt]
            
            serializer = DoctorPatientListSerializer(
                sorted_patients,
                many=True,
                context={'doctor': doctor}
            )
            return Response(serializer.data, status=status.HTTP_200_OK)
            
        except AttributeError:
            return Response(
                {"error": "Only doctors can access this endpoint"},
                status=status.HTTP_403_FORBIDDEN
            )


class CreatePrescriptionView(APIView):

    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
    operation_summary="Create prescription",
    operation_description="Doctor creates a new prescription for a patient they've had appointments with",
    request_body=CreatePrescriptionSerializer,
    responses={
        201: openapi.Response(
            description="Prescription created successfully",
            schema=PrescriptionDetailSerializer()
        ),
        400: openapi.Response(description="Validation error"),
        403: openapi.Response(description="Only doctors can create prescriptions")
    },
    tags=['Doctor Prescriptions']
)

    def post(self, request):
        try:
            doctor = request.user.doctor_profile
            
            serializer = CreatePrescriptionSerializer(
                data=request.data,
                context={'request': request}
            )
            
            if serializer.is_valid():
                prescription = serializer.save(doctor=doctor)
                
                return Response(
                    {
                        "message": "Prescription created successfully",
                        "prescription": PrescriptionDetailSerializer(prescription).data
                    },
                    status=status.HTTP_201_CREATED
                )
            
            return Response(
                {"errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        except AttributeError:
            return Response(
                {"error": "Only doctors can create prescriptions"},
                status=status.HTTP_403_FORBIDDEN
            )


class DoctorPrescriptionsListView(APIView):
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
    operation_summary="Get doctor's prescriptions",
    operation_description="Retrieve all prescriptions created by the authenticated doctor",
    manual_parameters=[
        openapi.Parameter(
            'patient_id',
            openapi.IN_QUERY,
            description="Filter by patient ID (optional)",
            type=openapi.TYPE_INTEGER
        )
    ],
    responses={
        200: openapi.Response(
            description="List of prescriptions",
            schema=PrescriptionListSerializer(many=True)
        ),
        403: openapi.Response(description="Only doctors can access this endpoint")
    },
    tags=['Doctor Prescriptions']
)

    def get(self, request):
        try:
            doctor = request.user.doctor_profile
            patient_id = request.query_params.get('patient_id')
            
            prescriptions = Prescription.objects.filter(
                doctor=doctor
            ).select_related('patient', 'doctor').prefetch_related('medications', 'lab_tests')
            
            if patient_id:
                prescriptions = prescriptions.filter(patient_id=patient_id)
            
            prescriptions = prescriptions.order_by('-created_at')
            
            serializer = PrescriptionListSerializer(prescriptions, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
            
        except AttributeError:
            return Response(
                {"error": "Only doctors can access this endpoint"},
                status=status.HTTP_403_FORBIDDEN
            )


class PatientPrescriptionsListView(APIView):
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
    operation_summary="Get patient's prescriptions",
    operation_description="Retrieve all prescriptions for the authenticated patient",
    responses={
        200: openapi.Response(
            description="List of prescriptions",
            schema=PrescriptionListSerializer(many=True)
        ),
        403: openapi.Response(description="Only patients can access this endpoint")
    },
    tags=['Patient Prescriptions']
)

    def get(self, request):
        try:
            patient = request.user.patient_profile
            
            prescriptions = Prescription.objects.filter(
                patient=patient
            ).select_related('doctor', 'patient').prefetch_related('medications', 'lab_tests').order_by('-created_at')
            
            serializer = PrescriptionListSerializer(prescriptions, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
            
        except AttributeError:
            return Response(
                {"error": "Only patients can access this endpoint"},
                status=status.HTTP_403_FORBIDDEN
            )

class PatientPrescriptionsByDoctorView(APIView):

    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
    operation_summary="Get prescriptions by doctor",
    operation_description="Patient can view all prescriptions from a specific doctor",
    responses={
        200: openapi.Response(
            description="List of prescriptions",
            schema=PrescriptionListSerializer(many=True)
        ),
        403: openapi.Response(description="Only patients can access this endpoint")
    },
    tags=['Patient Prescriptions']
)

    def get(self, request, doctor_id):
        try:
            patient = request.user.patient_profile
            
            prescriptions = Prescription.objects.filter(
                patient=patient,
                doctor_id=doctor_id
            ).select_related('doctor', 'patient').prefetch_related('medications', 'lab_tests').order_by('-created_at')
            
            serializer = PrescriptionListSerializer(prescriptions, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
            
        except AttributeError:
            return Response(
                {"error": "Only patients can access this endpoint"},
                status=status.HTTP_403_FORBIDDEN
            )