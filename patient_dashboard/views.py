from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .serializers import PatientDashboardSerializer, DashboardAppointmentSerializer, PatientCompleteProfileSerializer
from django.utils import timezone
from datetime import datetime, date


class PatientDashboardView(APIView):
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Retrieve patient's dashboard profile information including name, date of birth, blood group, known allergies, and chronic diseases",
        operation_summary="Get Patient Dashboard Profile",
        responses={
            200: PatientDashboardSerializer,
            403: openapi.Response(
                description="Access denied - User is not a patient",
                examples={
                    "application/json": {
                        "error": "Only patients can access this endpoint"
                    }
                }
            ),
            401: openapi.Response(
                description="Unauthorized - Authentication required",
                examples={
                    "application/json": {
                        "detail": "Authentication credentials were not provided."
                    }
                }
            ),
            500: openapi.Response(
                description="Server error",
                examples={
                    "application/json": {
                        "error": "Something went wrong",
                        "detail": "Error message"
                    }
                }
            )
        },
        tags=['Patient Profile']
    )
    def get(self, request):
        try:
            patient = request.user.patient_profile
            serializer = PatientDashboardSerializer(patient)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except AttributeError:
            return Response(
                {"error": "Only patients can access this endpoint"},
                status=status.HTTP_403_FORBIDDEN
            )
        except Exception as e:
            return Response(
                {"error": "Something went wrong", "detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PatientUpcomingAppointmentsView(APIView):
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Get patient's upcoming appointments with pending or confirmed status. Returns up to 4 appointments ordered by date and time with doctor name, appointment details, reason, and status",
        operation_summary="List Upcoming Appointments",
        responses={
            200: DashboardAppointmentSerializer(many=True),
            403: openapi.Response(
                description="Access denied - User is not a patient",
                examples={
                    "application/json": {
                        "error": "Only patients can access this endpoint"
                    }
                }
            ),
            401: openapi.Response(
                description="Unauthorized - Authentication required",
                examples={
                    "application/json": {
                        "detail": "Authentication credentials were not provided."
                    }
                }
            ),
            500: openapi.Response(
                description="Server error",
                examples={
                    "application/json": {
                        "error": "Something went wrong",
                        "detail": "Error message"
                    }
                }
            )
        },
        tags=['Patient Appointments']
    )
    def get(self, request):
        try:
            patient = request.user.patient_profile
            appointments = patient.appointments.filter(
                appointment_date__gte=date.today(),
                status__in=['pending', 'confirmed']
            ).order_by('appointment_date', 'appointment_time')[:4]
            serializer = DashboardAppointmentSerializer(appointments, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except AttributeError:
            return Response(
                {"error": "Only patients can access this endpoint"},
                status=status.HTTP_403_FORBIDDEN
            )
        except Exception as e:
            return Response(
                {"error": "Something went wrong", "detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PatientRecentAppointmentsView(APIView):
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Get patient's recent completed appointments. Returns up to 4 past appointments with completed status ordered by most recent date and time with doctor name, appointment details, reason, and status",
        operation_summary="List Recent Appointments",
        responses={
            200: DashboardAppointmentSerializer(many=True),
            403: openapi.Response(
                description="Access denied - User is not a patient",
                examples={
                    "application/json": {
                        "error": "Only patients can access this endpoint"
                    }
                }
            ),
            401: openapi.Response(
                description="Unauthorized - Authentication required",
                examples={
                    "application/json": {
                        "detail": "Authentication credentials were not provided."
                    }
                }
            ),
            500: openapi.Response(
                description="Server error",
                examples={
                    "application/json": {
                        "error": "Something went wrong",
                        "detail": "Error message"
                    }
                }
            )
        },
        tags=['Patient Appointments']
    )
    def get(self, request):
        try:
            patient = request.user.patient_profile
            appointments = patient.appointments.filter(
                appointment_date__lt=date.today(),
                status='completed'
            ).order_by('-appointment_date', '-appointment_time')[:4]
            serializer = DashboardAppointmentSerializer(appointments, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except AttributeError:
            return Response(
                {"error": "Only patients can access this endpoint"},
                status=status.HTTP_403_FORBIDDEN
            )
        except Exception as e:
            return Response(
                {"error": "Something went wrong", "detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PatientCompleteProfileView(APIView):
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Retrieve complete patient profile with all fields including personal information, contact details, insurance information, and medical history",
        operation_summary="Get Complete Patient Profile",
        responses={
            200: PatientCompleteProfileSerializer,
            403: openapi.Response(
                description="Access denied - User is not a patient",
                examples={
                    "application/json": {
                        "error": "Only patients can access this endpoint"
                    }
                }
            ),
            401: openapi.Response(
                description="Unauthorized - Authentication required",
                examples={
                    "application/json": {
                        "detail": "Authentication credentials were not provided."
                    }
                }
            ),
            500: openapi.Response(
                description="Server error",
                examples={
                    "application/json": {
                        "error": "Something went wrong",
                        "detail": "Error message"
                    }
                }
            )
        },
        tags=['Patient Profile']
    )
    def get(self, request):
        try:
            patient = request.user.patient_profile
            serializer = PatientCompleteProfileSerializer(patient)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except AttributeError:
            return Response(
                {"error": "Only patients can access this endpoint"},
                status=status.HTTP_403_FORBIDDEN
            )
        except Exception as e:
            return Response(
                {"error": "Something went wrong", "detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @swagger_auto_schema(
        operation_description="Update patient profile with editable fields. Allowed fields: first_name, last_name, phone_number, emergency_contact, emergency_email, city, is_insurance, ins_company_name, ins_policy_number, known_allergies, chronic_diseases, previous_surgeries, family_medical_history. Non-editable fields like email, username, date_of_birth, blood_group, and gender cannot be modified",
        operation_summary="Update Patient Profile",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'first_name': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='First name',
                    example='John'
                ),
                'last_name': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Last name',
                    example='Doe'
                ),
                'phone_number': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Primary phone number',
                    example='+11234567890'
                ),
                'emergency_contact': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Emergency contact number',
                    example='+19876543210'
                ),
                'emergency_email': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    format=openapi.FORMAT_EMAIL,
                    description='Emergency contact email',
                    example='jane.doe@example.com'
                ),
                'city': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='City',
                    example='New York'
                ),
                'is_insurance': openapi.Schema(
                    type=openapi.TYPE_BOOLEAN,
                    description='Has insurance coverage',
                    example=True
                ),
                'ins_company_name': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Insurance company name',
                    example='HealthCare Plus'
                ),
                'ins_policy_number': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Insurance policy number',
                    example='HCP123456789'
                ),
                'known_allergies': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Known allergies',
                    example='Penicillin, Peanuts, Latex'
                ),
                'chronic_diseases': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Chronic diseases',
                    example='Diabetes Type 2, Hypertension'
                ),
                'previous_surgeries': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Previous surgeries',
                    example='Appendectomy (2015), Hernia repair (2018)'
                ),
                'family_medical_history': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Family medical history',
                    example='Father: Hypertension, Mother: Diabetes, Sister: Asthma'
                )
            }
        ),
        responses={
            200: openapi.Response(
                description="Profile updated successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Profile updated successfully'
                        ),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            description='Updated patient profile data'
                        )
                    }
                ),
                examples={
                    "application/json": {
                        "message": "Profile updated successfully",
                        "data": {
                            "email": "john.doe@example.com",
                            "username": "johndoe",
                            "is_verified": True,
                            "first_name": "John",
                            "last_name": "Doe",
                            "date_of_birth": "1990-05-15",
                            "blood_group": "O+",
                            "gender": "M",
                            "city": "Los Angeles",
                            "phone_number": "+11234567890",
                            "emergency_contact": "+19999888877",
                            "emergency_email": "jane.new@example.com",
                            "is_insurance": True,
                            "ins_company_name": "HealthCare Premium",
                            "ins_policy_number": "HCP987654321",
                            "known_allergies": "Penicillin, Peanuts, Latex",
                            "chronic_diseases": "Diabetes Type 2, Hypertension",
                            "previous_surgeries": "Appendectomy (2015), Hernia repair (2018)",
                            "family_medical_history": "Father: Hypertension, Mother: Diabetes, Sister: Asthma",
                            "created_at": "2024-01-15T10:30:00Z",
                            "updated_at": "2024-11-03T16:45:00Z"
                        }
                    }
                }
            ),
            400: openapi.Response(
                description="Invalid data",
                examples={
                    "application/json": {
                        "error": "Invalid data",
                        "details": {
                            "phone_number": ["This field is required."],
                            "is_insurance": ["Must be a valid boolean."]
                        }
                    }
                }
            ),
            403: openapi.Response(
                description="Access denied - User is not a patient",
                examples={
                    "application/json": {
                        "error": "Only patients can access this endpoint"
                    }
                }
            ),
            401: openapi.Response(
                description="Unauthorized - Authentication required",
                examples={
                    "application/json": {
                        "detail": "Authentication credentials were not provided."
                    }
                }
            ),
            500: openapi.Response(
                description="Server error",
                examples={
                    "application/json": {
                        "error": "Something went wrong",
                        "detail": "Error message"
                    }
                }
            )
        },
        tags=['Patient Profile']
    )
    def patch(self, request):
        try:
            patient = request.user.patient_profile
            editable_fields = [
                'first_name', 'last_name',
                'phone_number', 'emergency_contact', 'emergency_email',
                'city', 'is_insurance', 'ins_company_name', 'ins_policy_number',
                'known_allergies', 'chronic_diseases', 'previous_surgeries',
                'family_medical_history'
            ]
            filtered_data = {
                key: value for key, value in request.data.items() 
                if key in editable_fields
            }
            serializer = PatientCompleteProfileSerializer(
                patient, 
                data=filtered_data, 
                partial=True
            )
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {
                        "message": "Profile updated successfully",
                        "data": serializer.data
                    },
                    status=status.HTTP_200_OK
                )
            return Response(
                {"error": "Invalid data", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        except AttributeError:
            return Response(
                {"error": "Only patients can access this endpoint"},
                status=status.HTTP_403_FORBIDDEN
            )
        except Exception as e:
            return Response(
                {"error": "Something went wrong", "detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PatientDashboardStatsView(APIView):
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Get comprehensive dashboard statistics for patient including total appointments count, upcoming appointments, completed appointments, and pending appointments",
        operation_summary="Get Patient Dashboard Stats",
        responses={
            200: openapi.Response(
                description="Statistics retrieved successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'total_appointments': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description='Total number of appointments',
                            example=45
                        ),
                        'upcoming': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description='Number of upcoming appointments',
                            example=3
                        ),
                        'completed': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description='Number of completed appointments',
                            example=38
                        ),
                        'pending': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description='Number of pending appointments',
                            example=4
                        )
                    }
                ),
                examples={
                    "application/json": {
                        "total_appointments": 45,
                        "upcoming": 3,
                        "completed": 38,
                        "pending": 4
                    }
                }
            ),
            403: openapi.Response(
                description="Access denied - User is not a patient",
                examples={
                    "application/json": {
                        "error": "Only patients can access this endpoint"
                    }
                }
            ),
            401: openapi.Response(
                description="Unauthorized - Authentication required",
                examples={
                    "application/json": {
                        "detail": "Authentication credentials were not provided."
                    }
                }
            ),
            500: openapi.Response(
                description="Server error",
                examples={
                    "application/json": {
                        "error": "Something went wrong",
                        "detail": "Error message"
                    }
                }
            )
        },
        tags=['Patient Dashboard']
    )
    def get(self, request):
        try:
            patient = request.user.patient_profile
            total_appointments = patient.appointments.count()
            upcoming = patient.appointments.filter(
                appointment_date__gte=date.today(),
                status__in=['pending', 'confirmed']
            ).count()
            completed = patient.appointments.filter(
                status='completed'
            ).count()
            pending = patient.appointments.filter(
                status='pending'
            ).count()
            stats = {
                "total_appointments": total_appointments,
                "upcoming": upcoming,
                "completed": completed,
                "pending": pending
            }
            return Response(stats, status=status.HTTP_200_OK)
        except AttributeError:
            return Response(
                {"error": "Only patients can access this endpoint"},
                status=status.HTTP_403_FORBIDDEN
            )
        except Exception as e:
            return Response(
                {"error": "Something went wrong", "detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )