import random
import logging
from datetime import timedelta
from django.db import transaction, IntegrityError
from django.utils import timezone
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from drf_spectacular.utils import extend_schema, OpenApiExample, OpenApiResponse
from users.models import CustomUser, Doctor, Patient, OTP_SEND_LIMIT
from users.utils import send_otp_email
from users.serializers import (SignupSerializer,VerifySignupOTPSerializer,ResendSignupOTPSerializer,DoctorDetailsSerializer,
                               PatientDetailsSerializer,LoginSerializer,ForgotPasswordSerializer,VerifyPasswordResetOTPSerializer,
                               ResetPasswordSerializer,ResendPasswordResetOTPSerializer,DeleteAccountSerializer,
                               DeactivateAccountSerializer,ReactivateAccountSerializer,)

logger = logging.getLogger(__name__)

def get_tokens_for_user(user) -> dict:
    refresh = RefreshToken.for_user(user)
    return {'access_token': str(refresh.access_token),'refresh_token': str(refresh),}

def _check_otp_send_allowed(user):
    if user.is_otp_send_limit_reached():
        logger.warning(f"OTP send limit reached for {user.email}")
        return Response({'success': False,'error': (f"Maximum of {OTP_SEND_LIMIT} OTP emails reached for this session. "),},
                        status=status.HTTP_429_TOO_MANY_REQUESTS,)
    if user.otp_created_at:
        elapsed = (timezone.now() - user.otp_created_at).total_seconds()
        if elapsed < 30:
            wait = int(30 - elapsed) + 1
            return Response({'success': False,'error': f"Please wait {wait} second(s) before requesting a new OTP.",},status=status.HTTP_429_TOO_MANY_REQUESTS,)
    return None 

class SignupView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        tags=['Authentication'],
        summary='Register a new user account',
        description=(
            'Creates an unverified account and sends a 6-digit OTP to the email. '
            'Unverified accounts can be overwritten (re-registration before OTP confirmed). '
            'Verified accounts cannot reuse the same email or username.'
        ),
        request=SignupSerializer,
        responses={
            201: OpenApiResponse(description='Account created, OTP sent'),
            400: OpenApiResponse(description='Validation error'),
            429: OpenApiResponse(description='Send limit or cooldown active'),
            500: OpenApiResponse(description='Server error'),
        },
        examples=[
            OpenApiExample('Doctor signup', request_only=True, value={
                'email': 'doctor@example.com',
                'username': 'dr_smith',
                'password1': 'SecurePass@123',
                'password2': 'SecurePass@123',
                'role': 'doctor',
            }),
        ],
    )
    @transaction.atomic
    def post(self, request):
        try:
            serializer = SignupSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors},status=status.HTTP_400_BAD_REQUEST)
            email = serializer.validated_data['email']
            username = serializer.validated_data['username']
            password = serializer.validated_data['password1']
            role = serializer.validated_data['role']
            existing = CustomUser.objects.select_for_update().filter(email=email).first()
            if existing:
                if existing.is_verified:
                    return Response({'success': False, 'errors': {'email': ['An account with this email already exists.']}},status=status.HTTP_400_BAD_REQUEST)
                if CustomUser.objects.filter(username=username).exclude(pk=existing.pk).exists():
                    return Response({'success': False, 'errors': {'username': ['This username is currently unavailable.']}},status=status.HTTP_400_BAD_REQUEST)
                limit_response = _check_otp_send_allowed(existing)
                if limit_response:
                    return limit_response
                user = existing
                user.otp_send_count = 0
            else:
                user = CustomUser(email=email)
            otp = str(random.randint(100000, 999999))
            user.username = username
            user.role = role
            user.is_verified = False
            user.is_profile_complete = False
            user.otp = otp
            user.otp_created_at = timezone.now()
            user.otp_type = 'verification'
            user.otp_attempts = 0
            user.otp_locked_until = None
            user.otp_send_count += 1 
            user.set_password(password)
            user.save()
            send_otp_email(email, otp, 'verification')
            logger.info(f"Signup OTP dispatched for {email} (role={role}, send_count={user.otp_send_count})")
            return Response({'success': True,'message': 'OTP sent to your email. It is valid for 3 minutes.',
                             'email': email,}, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"Signup error: {e}")
            return Response({'success': False, 'error': 'Signup failed. Please try again.'},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class VerifySignupOTPView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        tags=['Authentication'],
        summary='Verify signup OTP',
        request=VerifySignupOTPSerializer,
        responses={
            200: OpenApiResponse(description='Email verified successfully'),
            400: OpenApiResponse(description='Invalid or expired OTP'),
            429: OpenApiResponse(description='Too many wrong attempts — account locked'),
        },
    )
    @transaction.atomic
    def post(self, request):
        try:
            serializer = VerifySignupOTPSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors},status=status.HTTP_400_BAD_REQUEST)
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            try:
                user = CustomUser.objects.get(email=email, is_verified=False)
            except CustomUser.DoesNotExist:
                if CustomUser.objects.filter(email=email, is_verified=True).exists():
                    return Response({'success': False, 'error': 'This email is already verified. Please login.'},status=status.HTTP_400_BAD_REQUEST)
                return Response({'success': False, 'error': 'No pending signup found for this email.'},status=status.HTTP_400_BAD_REQUEST)
            if user.is_otp_locked():
                remaining = 1
                if user.otp_locked_until:
                    remaining = int(max(0, (user.otp_locked_until - timezone.now()).total_seconds() // 60)) + 1
                return Response({'success': False, 'error': f'Too many attempts. Try again in {remaining} minute(s).'},
                                status=status.HTTP_429_TOO_MANY_REQUESTS)
            if user.is_otp_expired():
                return Response({'success': False, 'error': 'OTP has expired. Please request a new one.'},
                                status=status.HTTP_400_BAD_REQUEST)
            if user.otp_type != 'verification':
                return Response({'success': False, 'error': 'Invalid OTP type. Please request a new verification OTP.'},
                                status=status.HTTP_400_BAD_REQUEST)
            if user.otp != otp:
                user.otp_attempts += 1
                if user.otp_attempts >= 3:
                    user.otp_locked_until = timezone.now() + timedelta(minutes=10)
                user.save(update_fields=['otp_attempts', 'otp_locked_until'])
                attempts_left = max(0, 3 - user.otp_attempts)
                return Response({'success': False, 'error': f'Invalid OTP. {attempts_left} attempt(s) remaining.'},
                                status=status.HTTP_400_BAD_REQUEST)
            user.is_verified = True
            user.save(update_fields=['is_verified'])
            user.clear_otp()
            logger.info(f"User verified: {email} (role={user.role})")
            return Response({'success': True,'message': 'Email verified successfully! Please complete your profile to continue.',
                             'email': user.email,'role': user.role,}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"OTP verification error: {e}")
            return Response({'success': False, 'error': 'Verification failed. Please try again.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ResendSignupOTPView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        tags=['Authentication'],
        summary='Resend signup OTP',
        request=ResendSignupOTPSerializer,
        responses={
            200: OpenApiResponse(description='New OTP sent'),
            400: OpenApiResponse(description='Invalid request or already verified'),
            429: OpenApiResponse(description='Cooldown, lockout, or send limit reached'),
        },
    )
    def post(self, request):
        try:
            serializer = ResendSignupOTPSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors},status=status.HTTP_400_BAD_REQUEST)
            email = serializer.validated_data['email']
            try:
                user = CustomUser.objects.get(email=email, is_verified=False)
            except CustomUser.DoesNotExist:
                if CustomUser.objects.filter(email=email, is_verified=True).exists():
                    return Response({'success': False, 'error': 'This email is already verified. Please login.'},status=status.HTTP_400_BAD_REQUEST)
                return Response({'success': False, 'error': 'No pending signup found for this email.'},status=status.HTTP_400_BAD_REQUEST)
            if user.is_otp_locked():
                remaining = 1
                if user.otp_locked_until:
                    remaining = int(max(0, (user.otp_locked_until - timezone.now()).total_seconds() // 60)) + 1
                return Response({'success': False, 'error': f'Too many attempts. Try again in {remaining} minute(s).'},status=status.HTTP_429_TOO_MANY_REQUESTS)
            limit_response = _check_otp_send_allowed(user)
            if limit_response:
                return limit_response
            otp = str(random.randint(100000, 999999))
            user.otp = otp
            user.otp_created_at = timezone.now()
            user.otp_type = 'verification'
            user.otp_attempts = 0
            user.otp_locked_until = None
            user.otp_send_count += 1  
            user.save(update_fields=['otp', 'otp_created_at', 'otp_type','otp_attempts', 'otp_locked_until', 'otp_send_count',])
            send_otp_email(email, otp, 'verification')
            logger.info(f"Signup OTP resent to {email} (send_count={user.otp_send_count})")
            return Response({'success': True,'message': 'New OTP sent to your email. Valid for 3 minutes.',
                             'email': email,}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Resend signup OTP error: {e}")
            return Response({'success': False, 'error': 'Failed to resend OTP. Please try again.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DoctorDetailsView(APIView):
    permission_classes = [IsAuthenticated]
    @extend_schema(
        tags=['Profile Completion'],
        summary='Complete doctor profile',
        description=(
            'Saves doctor details for the authenticated user. '
            'Requires Authorization: Bearer <access_token> from /login/. '
        ),
        request=DoctorDetailsSerializer,
        responses={
            201: OpenApiResponse(description='Profile created — no tokens returned'),
            400: OpenApiResponse(description='Validation error or profile already exists'),
            401: OpenApiResponse(description='No valid token — call /login/ first'),
        },
    )
    @transaction.atomic
    def post(self, request):
        try:
            user = request.user  
            if user.role != 'doctor':
                return Response({'success': False, 'error': 'This account is registered as a patient, not a doctor.'},
                                status=status.HTTP_400_BAD_REQUEST)
            if Doctor.objects.filter(user=user).exists() or user.is_profile_complete:
                return Response({'success': False, 'error': 'Doctor profile already exists.'},status=status.HTTP_400_BAD_REQUEST)
            serializer = DoctorDetailsSerializer(data=request.data,context={'exclude_user': user})
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors},status=status.HTTP_400_BAD_REQUEST)
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
                    emergency_contact_number=serializer.validated_data.get('emergency_contact_number', ''),
                )
            except IntegrityError:
                return Response({'success': False, 'error': 'Phone number already registered. Please use a different number.'},
                                status=status.HTTP_400_BAD_REQUEST)
            user.is_profile_complete = True
            user.save(update_fields=['is_profile_complete'])
            logger.info(f"Doctor profile created: {user.email}")
            return Response({
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
                    'is_approved': doctor.is_approved,
                    'is_profile_complete': True,
                },
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"Doctor profile creation error: {e}")
            return Response({'success': False, 'error': 'Profile creation failed. Please try again.'},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class PatientDetailsView(APIView):
    permission_classes = [IsAuthenticated]
    @extend_schema(
        tags=['Profile Completion'],
        summary='Complete patient profile',
        description=(
            'Saves patient details for the authenticated user. '
            'Requires Authorization: Bearer <access_token> from /login/. '
        ),
        request=PatientDetailsSerializer,
        responses={
            201: OpenApiResponse(description='Profile created — no tokens returned'),
            400: OpenApiResponse(description='Validation error or profile already exists'),
            401: OpenApiResponse(description='No valid token — call /login/ first'),
        },
    )
    @transaction.atomic
    def post(self, request):
        try:
            user = request.user 
            if user.role != 'patient':
                return Response({'success': False, 'error': 'This account is registered as a doctor, not a patient.'},
                                status=status.HTTP_400_BAD_REQUEST)
            if Patient.objects.filter(user=user).exists() or user.is_profile_complete:
                return Response({'success': False, 'error': 'Patient profile already exists.'},status=status.HTTP_400_BAD_REQUEST)
            serializer = PatientDetailsSerializer(data=request.data,context={'exclude_user': user})
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors},status=status.HTTP_400_BAD_REQUEST)
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
                    family_medical_history=serializer.validated_data.get('family_medical_history', ''),
                )
            except IntegrityError:
                return Response({'success': False, 'error': 'Phone number already registered. Please use a different number.'},
                                status=status.HTTP_400_BAD_REQUEST)
            user.is_profile_complete = True
            user.save(update_fields=['is_profile_complete'])
            logger.info(f"Patient profile created: {user.email}")
            return Response({
                'success': True,
                'message': 'Patient profile created successfully!',
                'user': {
                    'user_id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': 'patient',
                    'profile_id': patient.id,
                    'gender': patient.gender,
                    'phone_number': patient.phone_number,
                    'is_profile_complete': True,
                },
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"Patient profile creation error: {e}")
            return Response({'success': False, 'error': 'Profile creation failed. Please try again.'},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
class LoginView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        tags=['Authentication'],
        summary='Login with email or username',
        request=LoginSerializer,
        responses={
            200: OpenApiResponse(description='Login successful, tokens returned'),
            400: OpenApiResponse(description='Invalid credentials, incomplete profile, or locked'),
        },
        examples=[
            OpenApiExample('Email login',    request_only=True, value={'identifier': 'doctor@example.com', 'password': 'SecurePass@123'}),
            OpenApiExample('Username login', request_only=True, value={'identifier': 'dr_smith',           'password': 'SecurePass@123'}),
        ],
    )
    def post(self, request):
        try:
            serializer = LoginSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors},status=status.HTTP_400_BAD_REQUEST)
            user = serializer.validated_data['user']
            is_profile_complete = serializer.validated_data['is_profile_complete']
            role = user.role
            tokens = get_tokens_for_user(user)
            if not is_profile_complete:
                logger.info(f"Login (profile incomplete): {user.email} (role={role})")
                return Response({
                    'success': True,
                    'message': 'Login successful. Please complete your profile to continue.',
                    **tokens,
                    'username': user.username,
                    'user': {
                        'user_id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'role': role,
                        'is_profile_complete': False,
                    },
                }, status=status.HTTP_200_OK)
            profile_data = {}
            if role == 'doctor':
                try:
                    doctor = Doctor.objects.get(user=user)
                    profile_data = {'profile_id': doctor.id,'specialization': doctor.specialization,'department': doctor.department,'is_approved': doctor.is_approved,}
                except Doctor.DoesNotExist:
                    logger.error(f"Doctor profile missing for verified user: {user.email}")
                    return Response({'success': False, 'error': 'Doctor profile not found. Please contact support.'},status=status.HTTP_404_NOT_FOUND)
            elif role == 'patient':
                try:
                    patient = Patient.objects.get(user=user)
                    profile_data = {'profile_id': patient.id,'gender': patient.gender,'phone_number': patient.phone_number,}
                except Patient.DoesNotExist:
                    logger.error(f"Patient profile missing for verified user: {user.email}")
                    return Response({'success': False, 'error': 'Patient profile not found. Please contact support.'},status=status.HTTP_404_NOT_FOUND)
            else:
                return Response({'success': False, 'error': 'Unknown role. Please contact support.'},status=status.HTTP_400_BAD_REQUEST)
            logger.info(f"Login successful: {user.email} (role={role})")
            return Response({
                'success': True,
                'message': 'Login successful!',
                **tokens,
                'username': user.username,
                'user': {
                    'user_id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': role,
                    'is_profile_complete': True,
                    **profile_data,
                },
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Login error: {e}")
            return Response({'success': False, 'error': 'Login failed. Please try again.'},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class RefreshTokenView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        tags=['Authentication'],
        summary='Refresh access token',
        request={'application/json': {
            'type': 'object',
            'properties': {'refresh_token': {'type': 'string'}},
            'required': ['refresh_token'],
        }},
        responses={
            200: OpenApiResponse(description='New access token returned'),
            401: OpenApiResponse(description='Invalid or expired refresh token'),
        },
    )
    def post(self, request):
        refresh_token = request.data.get('refresh_token')
        if not refresh_token:
            return Response({'success': False, 'error': 'Refresh token is required.'},status=status.HTTP_400_BAD_REQUEST)
        try:
            refresh = RefreshToken(refresh_token)
            new_access_token = str(refresh.access_token)
            return Response({'success': True,'access_token': new_access_token,}, status=status.HTTP_200_OK)
        except TokenError:
            return Response({'success': False, 'error': 'Invalid or expired refresh token. Please login again.'},status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            return Response({'success': False, 'error': 'Token refresh failed.'},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MeView(APIView):
    permission_classes = [IsAuthenticated]
    @extend_schema(
        tags=['Authentication'],
        summary='Get current user info',
        responses={
            200: OpenApiResponse(description='User info returned'),
            401: OpenApiResponse(description='Unauthenticated or token invalid'),
        },
    )
    def get(self, request):
        try:
            user = request.user
            profile_data = {}
            if user.role == 'doctor':
                try:
                    doctor = Doctor.objects.get(user=user)
                    profile_data = {'profile_id': doctor.id,'specialization': doctor.specialization,
                                    'department': doctor.department,'is_approved': doctor.is_approved,}
                except Doctor.DoesNotExist:
                    pass
            elif user.role == 'patient':
                try:
                    patient = Patient.objects.get(user=user)
                    profile_data = {'profile_id': patient.id,'gender': patient.gender,'phone_number': patient.phone_number,}
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
                    **profile_data,
                },
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Me view error: {e}")
            return Response({'success': False, 'error': 'Failed to fetch user info.'},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    @extend_schema(
        tags=['Authentication'],
        summary='Logout — blacklist refresh token',
        request={'application/json': {
            'type': 'object',
            'properties': {'refresh_token': {'type': 'string'}},
            'required': ['refresh_token'],
        }},
        responses={
            200: OpenApiResponse(description='Logged out successfully'),
            400: OpenApiResponse(description='Refresh token missing'),
            401: OpenApiResponse(description='Unauthenticated'),
        },
    )
    def post(self, request):
        refresh_token = request.data.get('refresh_token')
        if not refresh_token:
            return Response({'success': False, 'error': 'Refresh token is required to logout.'},status=status.HTTP_400_BAD_REQUEST)
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            logger.info(f"User logged out: {request.user.email}")
            return Response({'success': True,'message': 'Logged out successfully. Please discard your tokens.',}, status=status.HTTP_200_OK)
        except TokenError:
            return Response({'success': True,'message': 'Logged out successfully.',}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return Response({'success': False, 'error': 'Logout failed. Please try again.'},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        tags=['Authentication'],
        summary='Request password reset OTP',
        request=ForgotPasswordSerializer,
        responses={
            200: OpenApiResponse(description='Generic response — OTP sent if email is registered'),
            400: OpenApiResponse(description='Invalid email format'),
        },
    )
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({'success': False, 'errors': serializer.errors},status=status.HTTP_400_BAD_REQUEST)
        email = serializer.validated_data['email']
        generic_response = Response({'success': True,'message': ('If this email is registered and verified, an OTP has been sent. '
                                                                 'Valid for 3 minutes.'),}, status=status.HTTP_200_OK)
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return generic_response   
        if not user.is_verified:
            return generic_response 
        if user.is_otp_locked():
            return generic_response 
        limit_response = _check_otp_send_allowed(user)
        if limit_response:
            return generic_response
        otp = str(random.randint(100000, 999999))
        user.otp = otp
        user.otp_created_at = timezone.now()
        user.otp_type = 'reset'
        user.otp_attempts = 0
        user.otp_locked_until = None
        user.otp_send_count += 1  
        user.save(update_fields=['otp', 'otp_created_at', 'otp_type','otp_attempts', 'otp_locked_until', 'otp_send_count',])
        send_otp_email(email, otp, 'reset')
        logger.info(f"Password reset OTP dispatched for {email} (send_count={user.otp_send_count})")
        return generic_response

class VerifyPasswordResetOTPView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        tags=['Authentication'],
        summary='Verify password reset OTP',
        request=VerifyPasswordResetOTPSerializer,
        responses={
            200: OpenApiResponse(description='OTP verified — proceed to /reset-password/'),
            400: OpenApiResponse(description='Invalid, expired, or wrong-type OTP'),
        },
    )
    def post(self, request):
        try:
            serializer = VerifyPasswordResetOTPSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors},status=status.HTTP_400_BAD_REQUEST)
            return Response({'success': True,'message': 'OTP verified. You may now reset your password.',
                             'email': serializer.validated_data['email'],}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Password reset OTP verification error: {e}")
            return Response({'success': False, 'error': 'Verification failed. Please try again.'},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ResetPasswordView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        tags=['Authentication'],
        summary='Reset password',
        request=ResetPasswordSerializer,
        responses={
            200: OpenApiResponse(description='Password reset — login with new password'),
            400: OpenApiResponse(description='OTP not verified first, mismatch, or same password'),
        },
    )
    @transaction.atomic
    def post(self, request):
        try:
            serializer = ResetPasswordSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors},status=status.HTTP_400_BAD_REQUEST)
            serializer.save()
            logger.info(f"Password reset for: {serializer.validated_data['email']}")
            return Response({'success': True,'message': 'Password reset successfully! Please login with your new password.',}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Password reset error: {e}")
            return Response({'success': False, 'error': 'Password reset failed. Please try again.'},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ResendPasswordResetOTPView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        tags=['Authentication'],
        summary='Resend password reset OTP',
        request=ResendPasswordResetOTPSerializer,
        responses={
            200: OpenApiResponse(description='New OTP sent'),
            400: OpenApiResponse(description='No active reset request — call /forgot-password/ first'),
            429: OpenApiResponse(description='Cooldown, lockout, or send limit reached'),
        },
    )
    def post(self, request):
        try:
            serializer = ResendPasswordResetOTPSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors},status=status.HTTP_400_BAD_REQUEST)
            user = serializer.validated_data['user']
            limit_response = _check_otp_send_allowed(user)
            if limit_response:
                return limit_response
            otp = str(random.randint(100000, 999999))
            user.otp = otp
            user.otp_created_at = timezone.now()
            user.otp_type = 'reset'
            user.otp_attempts = 0
            user.otp_locked_until = None
            user.otp_send_count += 1  
            user.save(update_fields=['otp', 'otp_created_at', 'otp_type','otp_attempts', 'otp_locked_until', 'otp_send_count',])
            send_otp_email(user.email, otp, 'reset')
            logger.info(f"Password reset OTP resent to {user.email} (send_count={user.otp_send_count})")
            return Response({'success': True,'message': 'New OTP sent to your email. Valid for 3 minutes.',
                             'email': user.email,}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Resend password reset OTP error: {e}")
            return Response({'success': False, 'error': 'Failed to resend OTP. Please try again.'},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class DeactivateAccountView(APIView):
    permission_classes = [IsAuthenticated]
    @extend_schema(
        tags=['Authentication'],
        summary='Deactivate account (reversible)',
        request={'application/json': {
            'type': 'object',
            'properties': {
                'password':      {'type': 'string'},
                'refresh_token': {'type': 'string'},
            },
            'required': ['password', 'refresh_token'],
        }},
        responses={
            200: OpenApiResponse(description='Account deactivated'),
            400: OpenApiResponse(description='Wrong password or missing refresh_token'),
            401: OpenApiResponse(description='Unauthenticated'),
        },
    )
    @transaction.atomic
    def post(self, request):
        try:
            serializer = DeactivateAccountSerializer(data=request.data,context={'user': request.user})
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors},status=status.HTTP_400_BAD_REQUEST)
            refresh_token = request.data.get('refresh_token')
            if not refresh_token:
                return Response({'success': False, 'error': 'refresh_token is required.'},status=status.HTTP_400_BAD_REQUEST)
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except TokenError:
                pass  
            user = request.user
            user.is_active = False
            user.save(update_fields=['is_active'])
            logger.info(f"Account deactivated: {user.email}")
            return Response({'success': True,'message': 'Account deactivated. Reactivate anytime via /auth/reactivate-account/.',},
                            status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Account deactivation error: {e}")
            return Response({'success': False, 'error': 'Deactivation failed. Please try again.'},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ReactivateAccountView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        tags=['Authentication'],
        summary='Reactivate a deactivated account',
        request=ReactivateAccountSerializer,
        responses={
            200: OpenApiResponse(description='Account reactivated, tokens returned'),
            400: OpenApiResponse(description='Invalid credentials or account already active'),
        },
    )
    @transaction.atomic
    def post(self, request):
        try:
            serializer = ReactivateAccountSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors},status=status.HTTP_400_BAD_REQUEST)
            user = serializer.validated_data['user']
            user.is_active = True
            user.save(update_fields=['is_active'])
            tokens = get_tokens_for_user(user)
            logger.info(f"Account reactivated: {user.email}")
            return Response({
                'success': True,
                'message': 'Account reactivated successfully!',
                **tokens,
                'user': {
                    'user_id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'is_profile_complete': user.is_profile_complete,
                },
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Account reactivation error: {e}")
            return Response({'success': False, 'error': 'Reactivation failed. Please try again.'},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DeleteAccountView(APIView):
    permission_classes = [IsAuthenticated]
    @extend_schema(
        tags=['Authentication'],
        summary='Permanently delete account',
        request={'application/json': {
            'type': 'object',
            'properties': {
                'password':      {'type': 'string'},
                'refresh_token': {'type': 'string'},
            },
            'required': ['password', 'refresh_token'],
        }},
        responses={
            200: OpenApiResponse(description='Account permanently deleted'),
            400: OpenApiResponse(description='Wrong password or missing refresh_token'),
            401: OpenApiResponse(description='Unauthenticated'),
        },
    )
    @transaction.atomic
    def delete(self, request):
        try:
            serializer = DeleteAccountSerializer(data=request.data,context={'user': request.user})
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors},status=status.HTTP_400_BAD_REQUEST)
            refresh_token = request.data.get('refresh_token')
            if not refresh_token:
                return Response({'success': False, 'error': 'refresh_token is required.'},status=status.HTTP_400_BAD_REQUEST)
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except TokenError:
                pass
            user  = request.user
            email = user.email  
            user.delete()  
            logger.info(f"Account permanently deleted: {email}")
            return Response({'success': True,'message': 'Account and all associated data have been permanently deleted.',},
                             status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Account deletion error: {e}")
            return Response({'success': False, 'error': 'Account deletion failed. Please try again.'},status=status.HTTP_500_INTERNAL_SERVER_ERROR)