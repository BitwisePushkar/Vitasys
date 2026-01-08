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
from users.models import CustomUser, Doctor, Patient, Nurse, Pharmacist, OTP_SEND_LIMIT
from users.utils import send_otp_email
from users.serializers import (
    SignupSerializer, VerifySignupOTPSerializer, ResendSignupOTPSerializer,
    DoctorDetailsSerializer, PatientDetailsSerializer,
    NurseDetailsSerializer, PharmacistDetailsSerializer,
    LoginSerializer, ForgotPasswordSerializer,
    VerifyPasswordResetOTPSerializer, ResetPasswordSerializer,
    ResendPasswordResetOTPSerializer, DeleteAccountSerializer,
    DeactivateAccountSerializer, ReactivateAccountSerializer,
)

logger = logging.getLogger(__name__)

def get_tokens_for_user(user) -> dict:
    refresh = RefreshToken.for_user(user)
    return {'access_token' : str(refresh.access_token),'refresh_token': str(refresh),}

def _check_otp_send_allowed(user):
    if user.is_otp_send_limit_reached():
        return Response({'success': False, 'error': f"Maximum of {OTP_SEND_LIMIT} OTP emails reached for this session."},
                        status=status.HTTP_429_TOO_MANY_REQUESTS,)
    if user.otp_created_at:
        elapsed = (timezone.now() - user.otp_created_at).total_seconds()
        if elapsed < 30:
            wait = int(30 - elapsed) + 1
            return Response({'success': False, 'error': f"Please wait {wait} second(s) before requesting a new OTP."},
                            status=status.HTTP_429_TOO_MANY_REQUESTS,)
    return None

def _build_profile_data(user) -> dict:
    role = user.role
    if role == 'doctor':
        try:
            d = Doctor.objects.get(user=user)
            return {'profile_id' : d.id,'specialization': d.specialization,'department' : d.department,'is_approved' : d.is_approved,}
        except Doctor.DoesNotExist:
            return {}

    if role == 'patient':
        try:
            p = Patient.objects.get(user=user)
            return {'profile_id' : p.id,'gender' : p.gender,'phone_number': p.phone_number,}
        except Patient.DoesNotExist:
            return {}

    if role == 'nurse':
        try:
            n = Nurse.objects.get(user=user)
            return {'profile_id': n.id,'department' : n.department,'employee_id': n.employee_id,'is_approved': n.is_approved,}
        except Nurse.DoesNotExist:
            return {}

    if role == 'pharmacist':
        try:
            ph = Pharmacist.objects.get(user=user)
            return {'profile_id': ph.id,'license_number': ph.license_number,'employee_id': ph.employee_id,
                    'is_approved': ph.is_approved,}
        except Pharmacist.DoesNotExist:
            return {}
    return {}

class SignupView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        tags=['Authentication'],
        summary='Register a new user account',
        description=('Creates an unverified account and sends a 6-digit OTP to the email. '),
        request=SignupSerializer,
        responses={
            201: OpenApiResponse(description='Account created, OTP sent'),
            400: OpenApiResponse(description='Validation error'),
            429: OpenApiResponse(description='Send limit or cooldown active'),
        },
        examples=[
            OpenApiExample('Doctor signup', request_only=True, value={
                'email': 'doctor@example.com', 'username': 'dr_smith',
                'password1': 'SecurePass@123', 'password2': 'SecurePass@123', 'role': 'doctor',
            }),
            OpenApiExample('Nurse signup', request_only=True, value={
                'email': 'nurse@example.com', 'username': 'nurse_sarah',
                'password1': 'SecurePass@123', 'password2': 'SecurePass@123', 'role': 'nurse',
            }),
        ],
    )
    @transaction.atomic
    def post(self, request):
        try:
            serializer = SignupSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors}, status=400)
            email = serializer.validated_data['email']
            username = serializer.validated_data['username']
            password = serializer.validated_data['password1']
            role = serializer.validated_data['role']
            existing = CustomUser.objects.select_for_update().filter(email=email).first()
            if existing:
                if existing.is_verified:
                    return Response({'success': False, 'errors': {'email': ['An account with this email already exists.']}}, status=400)
                if CustomUser.objects.filter(username=username).exclude(pk=existing.pk).exists():
                    return Response({'success': False, 'errors': {'username': ['This username is currently unavailable.']}}, status=400)
                blocked = _check_otp_send_allowed(existing)
                if blocked:
                    return blocked
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
            user.otp_locked_until= None
            user.otp_send_count += 1
            user.set_password(password)
            user.save()
            send_otp_email(email, otp, 'verification')
            logger.info(f"Signup OTP sent: {email} (role={role})")
            return Response({'success': True, 'message': 'OTP sent to your email. Valid for 3 minutes.', 'email': email},
                            status=201)
        except Exception as e:
            logger.error(f"Signup error: {e}")
            return Response({'success': False, 'error': 'Signup failed. Please try again.'}, status=500)

class VerifySignupOTPView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        tags=['Authentication'], summary='Verify signup OTP',
        request=VerifySignupOTPSerializer,
        responses={200: OpenApiResponse(description='Email verified'), 400: OpenApiResponse(description='Invalid OTP')},
    )
    @transaction.atomic
    def post(self, request):
        try:
            serializer = VerifySignupOTPSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors}, status=400)
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            try:
                user = CustomUser.objects.get(email=email, is_verified=False)
            except CustomUser.DoesNotExist:
                if CustomUser.objects.filter(email=email, is_verified=True).exists():
                    return Response({'success': False, 'error': 'This email is already verified. Please login.'}, status=400)
                return Response({'success': False, 'error': 'No pending signup found for this email.'}, status=400)
            if user.is_otp_locked():
                remaining = int(max(0, (user.otp_locked_until - timezone.now()).total_seconds() // 60)) + 1 if user.otp_locked_until else 1
                return Response({'success': False, 'error': f'Too many attempts. Try again in {remaining} minute(s).'}, status=429)
            if user.is_otp_expired():
                return Response({'success': False, 'error': 'OTP has expired. Please request a new one.'}, status=400)
            if user.otp_type != 'verification':
                return Response({'success': False, 'error': 'Invalid OTP type.'}, status=400)
            if user.otp != otp:
                user.otp_attempts += 1
                if user.otp_attempts >= 3:
                    user.otp_locked_until = timezone.now() + timedelta(minutes=10)
                user.save(update_fields=['otp_attempts', 'otp_locked_until'])
                attempts_left = max(0, 3 - user.otp_attempts)
                return Response({'success': False, 'error': f'Invalid OTP. {attempts_left} attempt(s) remaining.'}, status=400)
            user.is_verified = True
            user.save(update_fields=['is_verified'])
            user.clear_otp()
            profile_url_map = {'doctor': '/auth/doctor-profile/','patient': '/auth/patient-profile/',
                               'nurse': '/auth/nurse-profile/','pharmacist': '/auth/pharmacist-profile/',}
            next_step = profile_url_map.get(user.role, '/auth/login/')
            logger.info(f"User verified: {email} (role={user.role})")
            return Response({'success' : True,'message' : f'Email verified successfully! Please complete your profile at {next_step}.',
                             'email': user.email,'role': user.role,'next': next_step,})
        except Exception as e:
            logger.error(f"OTP verification error: {e}")
            return Response({'success': False, 'error': 'Verification failed. Please try again.'}, status=500)

class ResendSignupOTPView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        tags=['Authentication'], summary='Resend signup OTP',
        request=ResendSignupOTPSerializer,
        responses={200: OpenApiResponse(description='New OTP sent'), 429: OpenApiResponse(description='Rate limited')},
    )
    def post(self, request):
        try:
            serializer = ResendSignupOTPSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors}, status=400)
            email = serializer.validated_data['email']
            try:
                user = CustomUser.objects.get(email=email, is_verified=False)
            except CustomUser.DoesNotExist:
                if CustomUser.objects.filter(email=email, is_verified=True).exists():
                    return Response({'success': False, 'error': 'This email is already verified. Please login.'}, status=400)
                return Response({'success': False, 'error': 'No pending signup found for this email.'}, status=400)
            if user.is_otp_locked():
                remaining = int(max(0, (user.otp_locked_until - timezone.now()).total_seconds() // 60)) + 1 if user.otp_locked_until else 1
                return Response({'success': False, 'error': f'Too many attempts. Try again in {remaining} minute(s).'}, status=429)
            blocked = _check_otp_send_allowed(user)
            if blocked:
                return blocked
            otp = str(random.randint(100000, 999999))
            user.otp = otp
            user.otp_created_at = timezone.now()
            user.otp_type = 'verification'
            user.otp_attempts = 0
            user.otp_locked_until= None
            user.otp_send_count += 1
            user.save(update_fields=['otp', 'otp_created_at', 'otp_type', 'otp_attempts', 'otp_locked_until', 'otp_send_count'])
            send_otp_email(email, otp, 'verification')
            return Response({'success': True, 'message': 'New OTP sent. Valid for 3 minutes.', 'email': email})
        except Exception as e:
            logger.error(f"Resend OTP error: {e}")
            return Response({'success': False, 'error': 'Failed to resend OTP.'}, status=500)

class DoctorDetailsView(APIView):
    permission_classes = [IsAuthenticated]
    @extend_schema(
        tags=['Profile Completion'], summary='Complete doctor profile',
        request=DoctorDetailsSerializer,
        responses={201: OpenApiResponse(description='Doctor profile created'), 400: OpenApiResponse(description='Validation error')},
    )
    @transaction.atomic
    def post(self, request):
        try:
            user = request.user
            if user.role != 'doctor':
                return Response({'success': False, 'error': 'This account is not registered as a doctor.'}, status=400)
            if Doctor.objects.filter(user=user).exists() or user.is_profile_complete:
                return Response({'success': False, 'error': 'Doctor profile already exists.'}, status=400)
            serializer = DoctorDetailsSerializer(data=request.data, context={'exclude_user': user})
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors}, status=400)
            d = serializer.validated_data
            try:
                doctor = Doctor.objects.create(
                    user=user,
                    first_name=d['first_name'], last_name=d['last_name'],
                    date_of_birth=d['date_of_birth'], gender=d['gender'],
                    blood_group=d['blood_group'],
                    marital_status=d.get('marital_status', ''),
                    address=d.get('address', ''), city=d['city'],
                    state=d.get('state', ''), pincode=d.get('pincode', ''),
                    country=d.get('country', ''),
                    registration_number=d.get('registration_number', ''),
                    specialization=d.get('specialization', ''),
                    qualification=d.get('qualification', ''),
                    years_of_experience=d.get('years_of_experience'),
                    department=d.get('department', ''),
                    clinic_name=d.get('clinic_name', ''),
                    phone_number=d['phone_number'],
                    alternate_phone_number=d.get('alternate_phone_number', ''),
                    alternate_email=d.get('alternate_email', ''),
                    emergency_contact_person=d.get('emergency_contact_person', ''),
                    emergency_contact_number=d.get('emergency_contact_number', ''),
                )
            except IntegrityError:
                return Response({'success': False, 'error': 'Phone number already registered.'}, status=400)
            user.is_profile_complete = True
            user.save(update_fields=['is_profile_complete'])
            logger.info(f"Doctor profile created: {user.email}")
            return Response({'success': True,'message': 'Doctor profile created successfully!',
                             'user': {'user_id': user.id, 'username': user.username,'email': user.email, 'role': 'doctor',
                                      'profile_id': doctor.id,'specialization': doctor.specialization,'department': doctor.department,
                                      'is_approved': doctor.is_approved,'is_profile_complete': True,},}, status=201)
        except Exception as e:
            logger.error(f"Doctor profile error: {e}")
            return Response({'success': False, 'error': 'Profile creation failed.'}, status=500)

class PatientDetailsView(APIView):
    permission_classes = [IsAuthenticated]
    @extend_schema(
        tags=['Profile Completion'], summary='Complete patient profile',
        request=PatientDetailsSerializer,
        responses={201: OpenApiResponse(description='Patient profile created'), 400: OpenApiResponse(description='Validation error')},
    )
    @transaction.atomic
    def post(self, request):
        try:
            user = request.user
            if user.role != 'patient':
                return Response({'success': False, 'error': 'This account is not registered as a patient.'}, status=400)
            if Patient.objects.filter(user=user).exists() or user.is_profile_complete:
                return Response({'success': False, 'error': 'Patient profile already exists.'}, status=400)
            serializer = PatientDetailsSerializer(data=request.data, context={'exclude_user': user})
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors}, status=400)
            d = serializer.validated_data
            try:
                patient = Patient.objects.create(
                    user=user,
                    first_name=d['first_name'], last_name=d['last_name'],
                    date_of_birth=d['date_of_birth'], blood_group=d['blood_group'],
                    gender=d['gender'], city=d['city'], phone_number=d['phone_number'],
                    emergency_contact=d.get('emergency_contact', ''),
                    emergency_email=d.get('emergency_email', ''),
                    is_insurance=d.get('is_insurance', False),
                    ins_company_name=d.get('ins_company_name', ''),
                    ins_policy_number=d.get('ins_policy_number', ''),
                    known_allergies=d.get('known_allergies', ''),
                    chronic_diseases=d.get('chronic_diseases', ''),
                    previous_surgeries=d.get('previous_surgeries', ''),
                    family_medical_history=d.get('family_medical_history', ''),
                )
            except IntegrityError:
                return Response({'success': False, 'error': 'Phone number already registered.'}, status=400)
            user.is_profile_complete = True
            user.save(update_fields=['is_profile_complete'])
            logger.info(f"Patient profile created: {user.email}")
            return Response({'success': True,'message': 'Patient profile created successfully!',
                             'user': {'user_id': user.id, 'username': user.username,'email': user.email, 'role': 'patient',
                                      'profile_id': patient.id,'gender': patient.gender,'phone_number': patient.phone_number,
                                      'is_profile_complete': True,},}, status=201)
        except Exception as e:
            logger.error(f"Patient profile error: {e}")
            return Response({'success': False, 'error': 'Profile creation failed.'}, status=500)

class NurseDetailsView(APIView):
    permission_classes = [IsAuthenticated]
    @extend_schema(
        tags=['Profile Completion'], summary='Complete nurse profile',
        request=NurseDetailsSerializer,
        responses={201: OpenApiResponse(description='Nurse profile created'), 400: OpenApiResponse(description='Validation error')},
    )
    @transaction.atomic
    def post(self, request):
        try:
            user = request.user
            if user.role != 'nurse':
                return Response({'success': False, 'error': 'This account is not registered as a nurse.'}, status=400)
            if Nurse.objects.filter(user=user).exists() or user.is_profile_complete:
                return Response({'success': False, 'error': 'Nurse profile already exists.'}, status=400)
            serializer = NurseDetailsSerializer(data=request.data, context={'exclude_user': user})
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors}, status=400)
            d = serializer.validated_data
            try:
                nurse = Nurse.objects.create(
                    user=user,
                    first_name=d['first_name'], last_name=d['last_name'],
                    date_of_birth=d['date_of_birth'], gender=d['gender'],
                    blood_group=d['blood_group'], phone_number=d['phone_number'],
                    department=d['department'],
                    qualification=d.get('qualification', ''),
                    years_of_experience=d.get('years_of_experience'),
                    employee_id=d.get('employee_id'),
                    city=d['city'],
                    state=d.get('state', ''),
                    country=d.get('country', ''),
                )
            except IntegrityError:
                return Response({'success': False, 'error': 'Phone number or employee ID already registered.'}, status=400)
            user.is_profile_complete = True
            user.save(update_fields=['is_profile_complete'])
            logger.info(f"Nurse profile created: {user.email}")
            return Response({'success': True,'message': 'Nurse profile created successfully!',
                             'user': {'user_id': user.id, 'username': user.username,'email': user.email, 'role': 'nurse','profile_id': nurse.id,
                                      'department': nurse.department,'employee_id': nurse.employee_id,'is_approved': nurse.is_approved,
                                      'is_profile_complete': True,},}, status=201)
        except Exception as e:
            logger.error(f"Nurse profile error: {e}")
            return Response({'success': False, 'error': 'Profile creation failed.'}, status=500)

class PharmacistDetailsView(APIView):
    permission_classes = [IsAuthenticated]
    @extend_schema(
        tags=['Profile Completion'], summary='Complete pharmacist profile',
        request=PharmacistDetailsSerializer,
        responses={201: OpenApiResponse(description='Pharmacist profile created'), 400: OpenApiResponse(description='Validation error')},
    )
    @transaction.atomic
    def post(self, request):
        try:
            user = request.user
            if user.role != 'pharmacist':
                return Response({'success': False, 'error': 'This account is not registered as a pharmacist.'}, status=400)
            if Pharmacist.objects.filter(user=user).exists() or user.is_profile_complete:
                return Response({'success': False, 'error': 'Pharmacist profile already exists.'}, status=400)
            serializer = PharmacistDetailsSerializer(data=request.data, context={'exclude_user': user})
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors}, status=400)
            d = serializer.validated_data
            try:
                pharmacist = Pharmacist.objects.create(
                    user=user,
                    first_name=d['first_name'], last_name=d['last_name'],
                    date_of_birth=d['date_of_birth'], gender=d['gender'],
                    blood_group=d['blood_group'], phone_number=d['phone_number'],
                    license_number=d.get('license_number'),
                    qualification=d.get('qualification', ''),
                    years_of_experience=d.get('years_of_experience'),
                    employee_id=d.get('employee_id'),
                    city=d['city'],
                    state=d.get('state', ''),
                    country=d.get('country', ''),
                )
            except IntegrityError:
                return Response({'success': False, 'error': 'Phone number, license number, or employee ID already registered.'}, status=400)
            user.is_profile_complete = True
            user.save(update_fields=['is_profile_complete'])
            logger.info(f"Pharmacist profile created: {user.email}")
            return Response({'success': True,'message': 'Pharmacist profile created successfully!',
                             'user': {'user_id': user.id, 'username': user.username,'email': user.email, 'role': 'pharmacist',
                                      'profile_id': pharmacist.id,'license_number': pharmacist.license_number,'employee_id': pharmacist.employee_id,
                                      'is_approved': pharmacist.is_approved,'is_profile_complete': True,},}, status=201)
        except Exception as e:
            logger.error(f"Pharmacist profile error: {e}")
            return Response({'success': False, 'error': 'Profile creation failed.'}, status=500)

class LoginView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        tags=['Authentication'], summary='Login with email or username',
        request=LoginSerializer,
        responses={200: OpenApiResponse(description='Login successful'), 400: OpenApiResponse(description='Invalid credentials')},
        examples=[
            OpenApiExample('Email login',    request_only=True, value={'identifier': 'doctor@example.com', 'password': 'SecurePass@123'}),
            OpenApiExample('Username login', request_only=True, value={'identifier': 'dr_smith',           'password': 'SecurePass@123'}),
        ],
    )
    def post(self, request):
        try:
            serializer = LoginSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors}, status=400)
            user = serializer.validated_data['user']
            is_profile_complete = serializer.validated_data['is_profile_complete']
            tokens = get_tokens_for_user(user)
            if not is_profile_complete:
                profile_url_map = {'doctor' : '/auth/doctor-profile/','patient' : '/auth/patient-profile/',
                                   'nurse' : '/auth/nurse-profile/','pharmacist' : '/auth/pharmacist-profile/',}
                next_step = profile_url_map.get(user.role, '')
                return Response({'success': True,'message': 'Login successful. Please complete your profile to continue.',**tokens,'username': user.username,
                                 'user': {'user_id': user.id, 'username': user.username,'email': user.email, 'role': user.role,
                                          'is_profile_complete': False,'next': next_step,},})
            profile_data = _build_profile_data(user)
            logger.info(f"Login: {user.email} (role={user.role})")
            return Response({'success': True,'message': 'Login successful!',**tokens,'username': user.username,
                             'user': {'user_id': user.id, 'username': user.username,'email': user.email, 'role': user.role,
                                      'is_profile_complete': True,**profile_data,},})
        except Exception as e:
            logger.error(f"Login error: {e}")
            return Response({'success': False, 'error': 'Login failed. Please try again.'}, status=500)

class RefreshTokenView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        tags=['Authentication'], summary='Refresh access token',
        responses={200: OpenApiResponse(description='New access token'), 401: OpenApiResponse(description='Invalid token')},
    )
    def post(self, request):
        refresh_token = request.data.get('refresh_token')
        if not refresh_token:
            return Response({'success': False, 'error': 'Refresh token is required.'}, status=400)
        try:
            refresh = RefreshToken(refresh_token)
            return Response({'success': True, 'access_token': str(refresh.access_token)})
        except TokenError:
            return Response({'success': False, 'error': 'Invalid or expired refresh token. Please login again.'}, status=401)
        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            return Response({'success': False, 'error': 'Token refresh failed.'}, status=500)

class MeView(APIView):
    permission_classes = [IsAuthenticated]
    @extend_schema(
        tags=['Authentication'], summary='Get current user info',
        responses={200: OpenApiResponse(description='User info returned')},
    )
    def get(self, request):
        try:
            user = request.user
            profile_data = _build_profile_data(user)
            return Response({'success': True,'user': {'user_id': user.id, 'username': user.username,'email': user.email, 'role': user.role,
                                                      'is_profile_complete': user.is_profile_complete,**profile_data,},})
        except Exception as e:
            logger.error(f"Me view error: {e}")
            return Response({'success': False, 'error': 'Failed to fetch user info.'}, status=500)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    @extend_schema(
        tags=['Authentication'], summary='Logout — blacklist refresh token',
        responses={200: OpenApiResponse(description='Logged out'), 400: OpenApiResponse(description='Token missing')},
    )
    def post(self, request):
        refresh_token = request.data.get('refresh_token')
        if not refresh_token:
            return Response({'success': False, 'error': 'Refresh token is required to logout.'}, status=400)
        try:
            RefreshToken(refresh_token).blacklist()
        except TokenError:
            pass
        except Exception as e:
            logger.error(f"Logout error: {e}")
        logger.info(f"Logout: {request.user.email}")
        return Response({'success': True, 'message': 'Logged out successfully.'})

class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        tags=['Authentication'], summary='Request password reset OTP',
        request=ForgotPasswordSerializer,
        responses={200: OpenApiResponse(description='Generic — OTP sent if email is registered')},
    )
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({'success': False, 'errors': serializer.errors}, status=400)
        email = serializer.validated_data['email']
        generic = Response({'success': True, 'message': 'If this email is registered and verified, an OTP has been sent. Valid for 3 minutes.'})
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return generic
        if not user.is_verified or user.is_otp_locked():
            return generic
        blocked = _check_otp_send_allowed(user)
        if blocked:
            return generic
        otp = str(random.randint(100000, 999999))
        user.otp = otp
        user.otp_created_at = timezone.now()
        user.otp_type = 'reset'
        user.otp_attempts = 0
        user.otp_locked_until= None
        user.otp_send_count += 1
        user.save(update_fields=['otp', 'otp_created_at', 'otp_type', 'otp_attempts', 'otp_locked_until', 'otp_send_count'])
        send_otp_email(email, otp, 'reset')
        return generic

class VerifyPasswordResetOTPView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        tags=['Authentication'], summary='Verify password reset OTP',
        request=VerifyPasswordResetOTPSerializer,
        responses={200: OpenApiResponse(description='OTP verified'), 400: OpenApiResponse(description='Invalid OTP')},
    )
    def post(self, request):
        try:
            serializer = VerifyPasswordResetOTPSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors}, status=400)
            return Response({'success': True,'message': 'OTP verified. You may now reset your password.',
                             'email'  : serializer.validated_data['email'],})
        except Exception as e:
            logger.error(f"OTP verify error: {e}")
            return Response({'success': False, 'error': 'Verification failed.'}, status=500)

class ResetPasswordView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        tags=['Authentication'], summary='Reset password',
        request=ResetPasswordSerializer,
        responses={200: OpenApiResponse(description='Password reset'), 400: OpenApiResponse(description='Validation error')},
    )
    @transaction.atomic
    def post(self, request):
        try:
            serializer = ResetPasswordSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors}, status=400)
            serializer.save()
            logger.info(f"Password reset: {serializer.validated_data['email']}")
            return Response({'success': True, 'message': 'Password reset successfully! Please login with your new password.'})
        except Exception as e:
            logger.error(f"Password reset error: {e}")
            return Response({'success': False, 'error': 'Password reset failed.'}, status=500)

class ResendPasswordResetOTPView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        tags=['Authentication'], summary='Resend password reset OTP',
        request=ResendPasswordResetOTPSerializer,
        responses={200: OpenApiResponse(description='New OTP sent'), 429: OpenApiResponse(description='Rate limited')},
    )
    def post(self, request):
        try:
            serializer = ResendPasswordResetOTPSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors}, status=400)
            user = serializer.validated_data['user']
            blocked = _check_otp_send_allowed(user)
            if blocked:
                return blocked
            otp = str(random.randint(100000, 999999))
            user.otp = otp
            user.otp_created_at = timezone.now()
            user.otp_type = 'reset'
            user.otp_attempts = 0
            user.otp_locked_until= None
            user.otp_send_count += 1
            user.save(update_fields=['otp', 'otp_created_at', 'otp_type', 'otp_attempts', 'otp_locked_until', 'otp_send_count'])
            send_otp_email(user.email, otp, 'reset')
            return Response({'success': True, 'message': 'New OTP sent. Valid for 3 minutes.', 'email': user.email})
        except Exception as e:
            logger.error(f"Resend reset OTP error: {e}")
            return Response({'success': False, 'error': 'Failed to resend OTP.'}, status=500)

class DeactivateAccountView(APIView):
    permission_classes = [IsAuthenticated]
    @extend_schema(
        tags=['Authentication'], summary='Deactivate account (reversible)',
        responses={200: OpenApiResponse(description='Account deactivated')},
    )
    @transaction.atomic
    def post(self, request):
        try:
            serializer = DeactivateAccountSerializer(data=request.data, context={'user': request.user})
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors}, status=400)
            refresh_token = request.data.get('refresh_token')
            if not refresh_token:
                return Response({'success': False, 'error': 'refresh_token is required.'}, status=400)
            try:
                RefreshToken(refresh_token).blacklist()
            except TokenError:
                pass
            request.user.is_active = False
            request.user.save(update_fields=['is_active'])
            logger.info(f"Account deactivated: {request.user.email}")
            return Response({'success': True, 'message': 'Account deactivated. Reactivate via /auth/reactivate-account/.'})
        except Exception as e:
            logger.error(f"Deactivate error: {e}")
            return Response({'success': False, 'error': 'Deactivation failed.'}, status=500)

class ReactivateAccountView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        tags=['Authentication'], summary='Reactivate a deactivated account',
        request=ReactivateAccountSerializer,
        responses={200: OpenApiResponse(description='Account reactivated, tokens returned')},
    )
    @transaction.atomic
    def post(self, request):
        try:
            serializer = ReactivateAccountSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors}, status=400)
            user = serializer.validated_data['user']
            user.is_active = True
            user.save(update_fields=['is_active'])
            tokens = get_tokens_for_user(user)
            logger.info(f"Account reactivated: {user.email}")
            return Response({'success': True,'message': 'Account reactivated successfully!',**tokens,
                             'user': {'user_id': user.id, 'username': user.username,'email': user.email, 'role': user.role,
                                      'is_profile_complete': user.is_profile_complete,},})
        except Exception as e:
            logger.error(f"Reactivate error: {e}")
            return Response({'success': False, 'error': 'Reactivation failed.'}, status=500)

class DeleteAccountView(APIView):
    permission_classes = [IsAuthenticated]
    @extend_schema(
        tags=['Authentication'], summary='Permanently delete account',
        responses={200: OpenApiResponse(description='Account deleted')},
    )
    @transaction.atomic
    def delete(self, request):
        try:
            serializer = DeleteAccountSerializer(data=request.data, context={'user': request.user})
            if not serializer.is_valid():
                return Response({'success': False, 'errors': serializer.errors}, status=400)
            refresh_token = request.data.get('refresh_token')
            if not refresh_token:
                return Response({'success': False, 'error': 'refresh_token is required.'}, status=400)
            try:
                RefreshToken(refresh_token).blacklist()
            except TokenError:
                pass
            email = request.user.email
            request.user.delete()
            logger.info(f"Account deleted: {email}")
            return Response({'success': True, 'message': 'Account and all associated data permanently deleted.'})
        except Exception as e:
            logger.error(f"Delete account error: {e}")
            return Response({'success': False, 'error': 'Account deletion failed.'}, status=500)