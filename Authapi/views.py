from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.db import transaction, IntegrityError
from django.db import transaction
from django.utils import timezone
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import logging
from django.core.mail import send_mail
from django.conf import settings
import random
from datetime import timedelta
from dateutil import parser
from rest_framework.permissions import IsAuthenticated
from Authapi.tasks import send_otp_email_task
from Authapi.throttles import AuthAnonRateThrottle, OTPRateThrottle, LoginRateThrottle

from Authapi.models import CustomUser, Doctor, Patient
from .serializers import (
    SignupSerializer, VerifySignupOTPSerializer, ResendSignupOTPSerializer,
    DoctorDetailsSerializer, PatientDetailsSerializer,
    LoginSerializer,
    ForgotPasswordSerializer, VerifyPasswordResetOTPSerializer,
    ResetPasswordSerializer, ResendPasswordResetOTPSerializer
)

logger = logging.getLogger(__name__)

class SignupView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AuthAnonRateThrottle]
    @swagger_auto_schema(
        operation_description="Register a new user account (Doctor or Patient). Role must be provided in the request body.",
        operation_summary="User Signup",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email', 'password1', 'password2', 'role'],
            properties={
                'email': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    format=openapi.FORMAT_EMAIL,
                    description='User email address',
                    example='user@example.com'
                ),
                'password1': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Password (8-20 characters, must include uppercase, lowercase, digit, and special character)',
                    example='SecurePass@123'
                ),
                'password2': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Confirm password',
                    example='SecurePass@123'
                ),
                'role': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='User role selection',
                    enum=['doctor', 'patient'],
                    example='doctor'
                )
            }
        ),
        responses={
            201: openapi.Response(
                description="Account created successfully",
                examples={
                    "application/json": {
                        "success": True,
                        "message": "Account created! OTP sent to your email. Valid for 3 minutes.",
                        "email": "user@example.com",
                        # "role": "doctor",
                        "next_step": "verify_otp"
                    }
                }
            ),
            400: openapi.Response(
                description="Validation error",
                examples={
                    "application/json": {
                        "success": False,
                        "errors": {
                            "email": ["This email is already registered."],
                            "non_field_errors": ["No role selected. Please select a role first from the landing page."]
                        }
                    }
                }
            ),
            500: openapi.Response(
                description="Server error",
                examples={
                    "application/json": {
                        "success": False,
                        "error": "Signup failed. Please try again."
                    }
                }
            )
        },
        tags=['Authentication']
    )
    @transaction.atomic
    def post(self, request):
            try:
                serializer = SignupSerializer(data=request.data)
                
                if not serializer.is_valid():
                    return Response(
                        {'success': False, 'errors': serializer.errors},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                email = serializer.validated_data['email']
                password = serializer.validated_data['password1']
                role = serializer.validated_data['role']

                otp = str(random.randint(100000, 999999))

                user, created = CustomUser.objects.get_or_create(
                    email=email,
                    defaults={
                        'username': email,
                        'role': role,
                        'is_verified': False,
                        'is_profile_complete': False
                    }
                )

                if not created and user.is_verified:
                    return Response(
                        {'success': False, 'error': 'This email is already registered.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                user.set_password(password)
                user.role = role
                user.otp = otp
                user.otp_created_at = timezone.now()
                user.otp_attempts = 0
                user.otp_locked_until = None
                user.save()

                try:
                    send_otp_email_task.delay(email, otp, "Verification")
                    logger.info(f"OTP email queued via Celery for {email}")
                except Exception as e:
                    logger.error(f"Failed to queue email task: {e}")
                    raise

                logger.info(f"Signup OTP sent for: {email} as {role}")

                return Response({
                    'success': True,
                    'message': 'OTP sent to your email. Valid for 3 minutes.',
                    'email': email,
                    # 'role': role,
                    
                }, status=status.HTTP_201_CREATED)

            except Exception as e:
                logger.error(f"Signup error: {str(e)}")
                return Response(
                    {'success': False, 'error': 'Signup failed. Please try again.'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            

class VerifySignupOTPView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]
    @swagger_auto_schema(
        operation_description="Verify email using OTP sent during signup",
        operation_summary="Verify Signup OTP",
        request_body=VerifySignupOTPSerializer,
        responses={
            200: openapi.Response(
                description="Email verified successfully",
                examples={
                    "application/json": {
                        "success": True,
                        "message": "Email verified successfully! Please complete your profile.",
                        "email": "user@example.com",

                        "next_step": "complete_profile"
                    }
                }
            ),
            400: openapi.Response(
                description="Invalid or expired OTP",
                examples={
                    "application/json": {
                        "success": False,
                        "errors": {
                            "otp": ["Invalid OTP"],
                            "non_field_errors": ["OTP has expired"]
                        }
                    }
                }
            ),
            500: "Server error"
        },
        tags=['Authentication']
    )
    @transaction.atomic
    def post(self, request):
        try:
            serializer = VerifySignupOTPSerializer(data=request.data)

            if not serializer.is_valid():
                return Response(
                    {'success': False, 'errors': serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )

            email = request.data.get('email')
            otp = request.data.get('otp')

            try:
                user = CustomUser.objects.get(email=email, is_verified=False)
            except CustomUser.DoesNotExist:
                return Response(
                    {'success': False, 'error': 'No pending signup found for this email.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            if user.otp_locked_until and timezone.now() < user.otp_locked_until:
                remaining = max(0, (user.otp_locked_until - timezone.now()).total_seconds() // 60)
                return Response(
                    {'success': False, 'error': f'Too many attempts. Try again in {int(remaining) + 1} minutes.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            if not user.otp_created_at or timezone.now() - user.otp_created_at > timedelta(minutes=3):
                return Response(
                    {'success': False, 'error': 'OTP expired. Request a new one.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if user.otp != otp:
                user.otp_attempts += 1
                if user.otp_attempts >= 3:
                    user.otp_locked_until = timezone.now() + timedelta(minutes=10)
                user.save()
                
                attempts_left = max(0, 3 - user.otp_attempts)
                return Response(
                    {'success': False, 'error': f'Invalid OTP. {attempts_left} attempts remaining.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            role = user.role

            user.is_verified = True
            user.otp = None
            user.otp_created_at = None
            user.otp_attempts = 0
            user.otp_locked_until = None
            user.save()

            logger.info(f"User created and verified: {email} as {role}")

            return Response({
                'success': True,
                'message': 'Email verified successfully! Please complete your profile.',
                'email': user.email,
                'role': user.role,
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"OTP verification error: {str(e)}")
            return Response(
                {'success': False, 'error': 'Verification failed. Please try again.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ResendSignupOTPView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle] 
    @swagger_auto_schema(
        operation_description="Request a new OTP for email verification",
        operation_summary="Resend Signup OTP",
        request_body=ResendSignupOTPSerializer,
        responses={
            200: openapi.Response(
                description="New OTP sent successfully",
                examples={
                    "application/json": {
                        "success": True,
                        "message": "New OTP sent to your email. Valid for 3 minutes.",
                        "email": "user@example.com"
                    }
                }
            ),
            400: "Invalid request or user not found",
            500: "Failed to send OTP"
        },
        tags=['Authentication']
    )
    def post(self, request):
        try:
            serializer = ResendSignupOTPSerializer(data=request.data)
            
            if not serializer.is_valid():
                return Response(
                    {'success': False, 'errors': serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )

            email = request.data.get('email')

            try:
                user = CustomUser.objects.get(email=email, is_verified=False)
            except CustomUser.DoesNotExist:
                return Response(
                    {'success': False, 'error': 'No pending signup found for this email.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if user.otp_locked_until and timezone.now() < user.otp_locked_until:
                remaining = max(0, (user.otp_locked_until - timezone.now()).total_seconds() // 60)
                return Response(
                    {'success': False, 'error': f'Too many attempts. Try again in {int(remaining) + 1} minutes.'},
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                ) 
            
          
            if user.otp_created_at and (timezone.now() - user.otp_created_at) < timedelta(seconds=30):
                return Response(
                    {'success': False, 'error': 'Please wait at least 30 seconds before requesting a new OTP.'},
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )

            otp = str(random.randint(100000, 999999))
            user.otp = otp
            user.otp_created_at = timezone.now()
            user.otp_attempts = 0
            user.otp_locked_until = None
            user.save()

            try:
                send_otp_email_task.delay(email, otp, 'verification')
            except Exception as e:
                logger.error(f"Failed to resend OTP email: {str(e)}")
                return Response(
                    {'success': False, 'error': 'Failed to resend OTP. Please try again.'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            return Response({
                'success': True,
                'message': 'New OTP sent to your email. Valid for 3 minutes.',
                'email': email
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Resend OTP error: {str(e)}")
            return Response(
                {'success': False, 'error': 'Failed to resend OTP. Please try again.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class DoctorDetailsView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [LoginRateThrottle]
    @swagger_auto_schema(
        operation_description="Create complete doctor profile with medical credentials",
        operation_summary="Complete Doctor Profile",
        request_body=DoctorDetailsSerializer,
        responses={
            201: openapi.Response(
                description="Doctor profile created successfully",
                examples={
                    "application/json": {
                        "success": True,
                        "message": "Doctor profile created successfully! You can now login.",
                        "doctor_id": 123,
                        "specialization": "Cardiology",
                        "department": "Cardiology",
                        "username": "Dr. Smith",
                        "email": "doctor@example.com",
                        "next_step": "login"
                    }
                }
            ),
            400: "Validation error or profile already exists",
            404: "User account not found",
            500: "Profile creation failed"
        },
        tags=['Profile Management']
    )
    @transaction.atomic
    def post(self, request):
        try:
            serializer = DoctorDetailsSerializer(data=request.data)

            if not serializer.is_valid():
                return Response(
                    {'success': False, 'errors': serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )

            email = serializer.validated_data['email']

            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                return Response(
                    {'success': False, 'error': 'No account found. Please sign up first.'},
                    status=status.HTTP_404_NOT_FOUND
                )

            if not user.is_verified:
                return Response(
                    {'success': False, 'error': 'Please verify your email first.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if user.role != 'doctor':
                return Response(
                    {'success': False, 'error': 'This account is not registered as a doctor.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if Doctor.objects.filter(user=user).exists():
                return Response(
                    {'success': False, 'error': 'Doctor profile already exists for this account.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            try:
                doctor = Doctor.objects.create(
                    user=user,
                    first_name=serializer.validated_data['first_name'],
                    last_name=serializer.validated_data['last_name'],
                    date_of_birth=serializer.validated_data['date_of_birth'],
                    gender=serializer.validated_data['gender'],
                    blood_group=serializer.validated_data['blood_group'],
                    marital_status=serializer.validated_data.get('marital_status', ''),
                    address=serializer.validated_data.get('address', ''),
                    city=serializer.validated_data['city'],
                    state=serializer.validated_data.get('state', ''),
                    pincode=serializer.validated_data.get('pincode', ''),
                    country=serializer.validated_data.get('country', ''),
                    registration_number=serializer.validated_data.get('registration_number', ''),
                    specialization=serializer.validated_data.get('specialization', ''),
                    qualification=serializer.validated_data.get('qualification', ''),
                    years_of_experience=serializer.validated_data.get('years_of_experience'),
                    department=serializer.validated_data.get('department', ''),
                    clinic_name=serializer.validated_data.get('clinic_name', ''),
                    phone_number=serializer.validated_data['phone_number'],
                    alternate_phone_number=serializer.validated_data.get('alternate_phone_number', ''),
                    alternate_email=serializer.validated_data.get('alternate_email', ''),
                    emergency_contact_person=serializer.validated_data.get('emergency_contact_person', ''),
                    emergency_contact_number=serializer.validated_data.get('emergency_contact_number', '')
                )
            except IntegrityError:
                return Response({'success':False, 'error':'Phone number alreadyregistered. Please use a different number.'},status = status.HTTP_400_BAD_REQUEST)
                
            username = f"{serializer.validated_data['first_name'].lower()}{serializer.validated_data['last_name'].lower()}"
            base_username = username
            counter = 1
            while CustomUser.objects.filter(username=username).exists():
                username = f"{base_username}{counter}"
                counter += 1

            user.username = username
            user.is_profile_complete = True
            user.save()
    
            response = Response({
                'success': True,
                'message': 'Doctor profile created successfully!',
                'user': {
                    'user_id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': 'doctor',
                    'profile_id': doctor.id,
                    'specialization': doctor.specialization,
                    'department': doctor.department,
                    'is_approved': doctor.is_approved
                }
            }, status=status.HTTP_201_CREATED)

            refresh = RefreshToken.for_user(user)
            response.set_cookie(
                key='access_token',
                value=str(refresh.access_token),
                httponly=True,
                secure=True,
                samesite='None',
                max_age=3600,
                path='/'
            )

            response.set_cookie(
                key='refresh_token',
                value=str(refresh),
                httponly=True,
                secure=True,
                samesite='None',
                max_age=604800,
                path='/' 
            )

            return response


        except Exception as e:
            logger.error(f"Doctor profile creation error: {str(e)}")
            return Response(
                {'success': False, 'error': 'Profile creation failed. Please try again.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PatientDetailsView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Create complete patient profile with medical history",
        operation_summary="Complete Patient Profile",
        request_body=PatientDetailsSerializer,
        responses={
            201: openapi.Response(
                description="Patient profile created successfully",
                examples={
                    "application/json": {
                        "success": True,
                        "message": "Patient profile created successfully! You can now login.",
                        "patient_id": 456,
                        "username": "johndoe",
                        "email": "patient@example.com",
                        "next_step": "login"
                    }
                }
            ),
            400: "Validation error or profile already exists",
            404: "User account not found",
            500: "Profile creation failed"
        },
        tags=['Profile Management']
    )
    @transaction.atomic
    def post(self, request):
        try:
            serializer = PatientDetailsSerializer(data=request.data)

            if not serializer.is_valid():
                return Response(
                    {'success': False, 'errors': serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )

            email = serializer.validated_data['email']

            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                return Response(
                    {'success': False, 'error': 'No account found. Please sign up first.'},
                    status=status.HTTP_404_NOT_FOUND
                )

            if not user.is_verified:
                return Response(
                    {'success': False, 'error': 'Please verify your email first.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if user.role != 'patient':
                return Response(
                    {'success': False, 'error': 'This account is not registered as a patient.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if Patient.objects.filter(user=user).exists():
                return Response(
                    {'success': False, 'error': 'Patient profile already exists for this account.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            try:
                patient = Patient.objects.create(
                    user=user,
                    first_name=serializer.validated_data['first_name'],
                    last_name=serializer.validated_data['last_name'],
                    date_of_birth=serializer.validated_data['date_of_birth'],
                    blood_group=serializer.validated_data['blood_group'],
                    gender=serializer.validated_data['gender'],
                    city=serializer.validated_data['city'],
                    phone_number=serializer.validated_data['phone_number'],
                    emergency_contact=serializer.validated_data.get('emergency_contact', ''),
                    emergency_email=serializer.validated_data.get('emergency_email', ''),
                    is_insurance=serializer.validated_data.get('is_insurance', False),
                    ins_company_name=serializer.validated_data.get('ins_company_name', ''),
                    ins_policy_number=serializer.validated_data.get('ins_policy_number', ''),
                    known_allergies=serializer.validated_data.get('known_allergies', ''),
                    chronic_diseases=serializer.validated_data.get('chronic_diseases', ''),
                    previous_surgeries=serializer.validated_data.get('previous_surgeries', ''),
                    family_medical_history=serializer.validated_data.get('family_medical_history', '')
                )
            except IntegrityError:
                return Response({'success':False,'error':'Phone number already registered. Please use a different number.'}, status = status.HTTP_400_BAD_REQUEST)

            username = f"{serializer.validated_data['first_name'].lower()}{serializer.validated_data['last_name'].lower()}"
            base_username = username
            counter = 1
            while CustomUser.objects.filter(username=username).exists():
                username = f"{base_username}{counter}"
                counter += 1

            user.username = username
            user.is_profile_complete = True
            user.save()
            response = Response({
            'success': True,
            'message': 'Patient profile created successfully!',
            'user': {
                'user_id': user.id,
                'username': user.username,
                'email': user.email,
                'role': 'patient',
                'profile_id': patient.id,
                'gender': patient.gender,
                'phone_number': patient.phone_number
            }
        }, status=status.HTTP_201_CREATED)
            refresh = RefreshToken.for_user(user)
            response.set_cookie(
                key='access_token',
                value=str(refresh.access_token),
                httponly=True,
                secure=True,
                samesite='None',
                max_age=3600,
                domain=None,
                path='/'
            )

            response.set_cookie(
                key='refresh_token',
                value=str(refresh),
                httponly=True,
                secure=True,
                samesite='None',
                domain=None,
                max_age=604800,
                path='/'  
            )
            return response

        except Exception as e:
            logger.error(f"Patient profile creation error: {str(e)}")
            return Response(
                {'success': False, 'error': 'Profile creation failed. Please try again.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LoginView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]
    @swagger_auto_schema(
        operation_description="Unified login endpoint for both doctors and patients. System validates credentials and returns user profile based on registered role.",
        operation_summary="User Login",
        request_body=LoginSerializer,
        responses={
            200: openapi.Response(
                description="Login successful",
                examples={
                    "application/json": {
                        "success": True,
                        "message": "Login successful!",
                        "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
                        "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
                        "user": {
                            "user_id": 1,
                            "username": "johndoe",
                            "email": "user@example.com",
                            "role": "doctor",
                            "profile_id": 123
                        }
                    }
                }
            ),
            400: openapi.Response(
                description="Invalid credentials or role not selected",
                examples={
                    "application/json": {
                        "success": False,
                        "errors": {
                            "non_field_errors": ["No role selected. Please select a role first from the landing page."]
                        }
                    }
                }
            ),
            404: "Profile not found",
            500: "Login failed"
        },
        tags=['Authentication']
    )
    def post(self, request):
        try:
            serializer = LoginSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(
                    {'success': False, 'errors': serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )

            user = serializer.validated_data['user']
            is_profile_complete = serializer.validated_data['is_profile_complete']
            role = user.role

            if not is_profile_complete:
                return Response({
                    'success': False,
                    'is_profile_complete': False,
                    'message': 'Please complete your profile first.',
                    'email': user.email,
                    'role': role,
                }, status=status.HTTP_400_BAD_REQUEST)

            profile_data = {}
            
            if role == 'doctor':
                try:
                    doctor = Doctor.objects.get(user=user)
                    profile_data = {
                        'profile_id': doctor.id,
                        'specialization': doctor.specialization,
                        'department': doctor.department,
                        'is_approved': doctor.is_approved
                    }
                except Doctor.DoesNotExist:
                    logger.error(f"Doctor profile not found for user: {user.email}")
                    return Response(
                        {'success': False, 'error': 'Profile not found. Please complete your profile.'},
                        status=status.HTTP_404_NOT_FOUND
                    )
            else:
                try:
                    patient = Patient.objects.get(user=user)
                    profile_data = {
                        'profile_id': patient.id,
                        'gender': patient.gender,
                        'phone_number': patient.phone_number
                    }
                except Patient.DoesNotExist:
                    logger.error(f"Patient profile not found for user: {user.email}")
                    return Response(
                        {'success': False, 'error': 'Profile not found. Please complete your profile.'},
                        status=status.HTTP_404_NOT_FOUND
                    )

            refresh = RefreshToken.for_user(user)

            response = Response({
                'success': True,
                'message': 'Login successful!',
                'user': {
                    'user_id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': role,
                    **profile_data
                }
            }, status=status.HTTP_200_OK)

            response.set_cookie(
                key='access_token',
                value=str(refresh.access_token),
                httponly=True,
                secure=True,
                samesite='None',
                max_age=3600,
                domain=None,
                path='/' 
            )

            response.set_cookie(
                key='refresh_token',
                value=str(refresh),
                httponly=True,
                secure=True,
                samesite='None',
                domain=None,
                max_age=604800,
                path='/'  
            )

            return response
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return Response(
                {'success': False, 'error': 'Login failed. Please try again.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]
    @swagger_auto_schema(
        operation_description="Request password reset OTP via email",
        operation_summary="Forgot Password",
        request_body=ForgotPasswordSerializer,
        responses={
            200: openapi.Response(
                description="OTP sent successfully",
                examples={
                    "application/json": {
                        "success": True,
                        "message": "OTP sent to your email. Valid for 3 minutes.",
                        "email": "user@example.com",
                        "next_step": "verify_reset_otp"
                    }
                }
            ),
            400: "Invalid email or user not found",
            500: "Failed to send OTP"
        },
        tags=['Password Management']
    )
    def post(self, request):
        try:
            serializer = ForgotPasswordSerializer(data=request.data)

            if not serializer.is_valid():
                return Response(
                    {'success': False, 'errors': serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )

            return Response({
                'success': True,
                'message': 'OTP sent to your email. Valid for 3 minutes.',
                'email': request.data.get('email'),
                
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Forgot password error: {str(e)}")
            return Response(
                {'success': False, 'error': 'Failed to send OTP. Please try again.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class VerifyPasswordResetOTPView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]
    @swagger_auto_schema(
        operation_description="Verify OTP for password reset",
        operation_summary="Verify Password Reset OTP",
        request_body=VerifyPasswordResetOTPSerializer,
        responses={
            200: openapi.Response(
                description="OTP verified successfully",
                examples={
                    "application/json": {
                        "success": True,
                        "message": "OTP verified successfully! You can now reset your password.",
                        "email": "user@example.com",
                    }
                }
            ),
            400: "Invalid or expired OTP",
            500: "Verification failed"
        },
        tags=['Password Management']
    )
    def post(self, request):
        try:
            serializer = VerifyPasswordResetOTPSerializer(data=request.data)

            if not serializer.is_valid():
                return Response(
                    {'success': False, 'errors': serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )

            return Response({
                'success': True,
                'message': 'OTP verified successfully! You can now reset your password.',
                'email': request.data.get('email'),
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Password reset OTP verification error: {str(e)}")
            return Response(
                {'success': False, 'error': 'Verification failed. Please try again.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ResetPasswordView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]
    @swagger_auto_schema(
        operation_description="Set new password after OTP verification",
        operation_summary="Reset Password",
        request_body=ResetPasswordSerializer,
        responses={
            200: openapi.Response(
                description="Password reset successfully",
                examples={
                    "application/json": {
                        "success": True,
                        "message": "Password reset successfully! Please login with your new password.",

                    }
                }
            ),
            400: "Validation error or passwords don't match",
            500: "Password reset failed"
        },
        tags=['Password Management']
    )
    @transaction.atomic
    def post(self, request):
        try:
            serializer = ResetPasswordSerializer(data=request.data)

            if not serializer.is_valid():
                return Response(
                    {'success': False, 'errors': serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )

            serializer.save()

            return Response({
                'success': True,
                'message': 'Password reset successfully! Please login with your new password.',

            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Password reset error: {str(e)}")
            return Response(
                {'success': False, 'error': 'Password reset failed. Please try again.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
class ResendPasswordResetOTPView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]
    @swagger_auto_schema(
        operation_description="Request a new OTP for password reset",
        operation_summary="Resend Password Reset OTP",
        request_body=ResendPasswordResetOTPSerializer,
        responses={
            200: openapi.Response(
                description="New OTP sent successfully",
                examples={
                    "application/json": {
                        "success": True,
                        "message": "New OTP sent to your email. Valid for 3 minutes.",
                        "email": "user@example.com"
                    }
                }
            ),
            400: "Invalid request or user not found",
            500: "Failed to resend OTP"
        },
        tags=['Password Management']
    )
    def post(self, request):
        try:
            serializer = ResendPasswordResetOTPSerializer(data=request.data)

            if not serializer.is_valid():
                return Response(
                    {'success': False, 'errors': serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )

            user = serializer.validated_data['user']
            if user.otp_created_at and (timezone.now() - user.otp_created_at) < timedelta(seconds=30):
                return Response(
                    {'success': False, 'error': 'Please wait at least 30 seconds before requesting a new OTP.'},
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )
            email = user.email
            otp = str(random.randint(100000, 999999))

            user.otp = otp
            user.otp_created_at = timezone.now()
            user.otp_attempts = 0
            user.otp_locked_until = None
            user.save()

            try:
                send_otp_email_task.delay(email, otp, 'reset')
            except Exception as e:
                logger.error(f"Failed to resend password reset OTP email: {str(e)}")
                return Response(
                    {'success': False, 'error': 'Failed to resend OTP. Please try again.'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            return Response({
                'success': True,
                'message': 'New OTP sent to your email. Valid for 3 minutes.',
                'email': email
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Resend password reset OTP error: {str(e)}")
            return Response(
                {'success': False, 'error': 'Failed to resend OTP. Please try again.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

class RefreshTokenView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:

            refresh_token = request.COOKIES.get('refresh_token')
            
            if not refresh_token:
                return Response(
                    {'success': False, 'error': 'Refresh token not found'},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            refresh = RefreshToken(refresh_token)
            new_access_token = str(refresh.access_token)

            response = Response({
                'success': True,
                'message': 'Token refreshed successfully'
            }, status=status.HTTP_200_OK)

            response.set_cookie(
                key='access_token',
                value=new_access_token,
                httponly=True,
                secure=True,
                samesite='Strict',
                max_age=3600  # 1 hour
            )

            return response

        except Exception as e:
            logger.error(f"Token refresh error: {str(e)}")
            return Response(
                {'success': False, 'error': 'Token refresh failed'},
                status=status.HTTP_401_UNAUTHORIZED
            )

class VerifyTokenView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = request.user

            profile_data = {}
            if user.role == 'doctor':
                try:
                    doctor = Doctor.objects.get(user=user)
                    profile_data = {
                        'profile_id': doctor.id,
                        'specialization': doctor.specialization,
                        'department': doctor.department,
                        'is_approved': doctor.is_approved
                    }
                except Doctor.DoesNotExist:
                    pass
            else:
                try:
                    patient = Patient.objects.get(user=user)
                    profile_data = {
                        'profile_id': patient.id,
                        'gender': patient.gender,
                        'phone_number': patient.phone_number
                    }
                except Patient.DoesNotExist:
                    pass

            return Response({
                'success': True,
                'user': {
                    'user_id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'is_profile_complete': user.is_profile_complete,
                    **profile_data
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Token verification error: {str(e)}")
            return Response(
                {'success': False, 'error': 'Token verification failed'},
                status=status.HTTP_401_UNAUTHORIZED
            )
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            response = Response({
                'success': True,
                'message': 'Logged out successfully'
            }, status=status.HTTP_200_OK)
            response.delete_cookie('access_token')
            response.delete_cookie('refresh_token')
            
            return response

        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
            return Response(
                {'success': False, 'error': 'Logout failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )