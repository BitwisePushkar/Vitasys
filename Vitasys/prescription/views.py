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
from django.shortcuts import get_object_or_404
from django.db.models import Max, Count, OuterRef, Subquery


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
            
            # Subquery to get last appointment date/time for each patient
            last_apt = Appointment.objects.filter(
                doctor=doctor,
                patient=OuterRef('pk'),
                status__in=['confirmed', 'completed']
            ).order_by('-appointment_date', '-appointment_time')

            patients = Patient.objects.filter(
                appointments__doctor=doctor,
                appointments__status__in=['confirmed', 'completed']
            ).annotate(
                last_apt_date=Subquery(last_apt.values('appointment_date')[:1]),
                last_apt_time=Subquery(last_apt.values('appointment_time')[:1]),
                total_apts=Count('appointments', filter=Q(appointments__doctor=doctor, appointments__status__in=['confirmed', 'completed']), distinct=True),
                pres_count=Count('prescriptions', filter=Q(prescriptions__doctor=doctor), distinct=True)
            ).filter(last_apt_date__isnull=False).order_by('-last_apt_date', '-last_apt_time').distinct()

            serializer = DoctorPatientListSerializer(
                patients,
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


class PrescriptionDetailView(APIView):
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_summary="Get prescription details",
        operation_description="Retrieve full details of a specific prescription. Access restricted to the involved doctor and patient.",
        responses={
            200: PrescriptionDetailSerializer(),
            404: openapi.Response(description="Prescription not found"),
            403: openapi.Response(description="Permission denied")
        },
        tags=['Prescriptions']
    )
    def get(self, request, prescription_id):
        user = request.user
        prescription = get_object_or_404(Prescription, id=prescription_id)
        
        # Check permissions
        is_doctor = hasattr(user, 'doctor_profile') and prescription.doctor == user.doctor_profile
        is_patient = hasattr(user, 'patient_profile') and prescription.patient == user.patient_profile
        
        if not (is_doctor or is_patient):
            return Response(
                {"error": "You do not have permission to view this prescription"},
                status=status.HTTP_403_FORBIDDEN
            )
            
        serializer = PrescriptionDetailSerializer(prescription)
        return Response(serializer.data, status=status.HTTP_200_OK)

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