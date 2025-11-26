from rest_framework import serializers
from django.utils import timezone
from datetime import timedelta, date
from django.core.mail import send_mail
from django.conf import settings
import re
import logging
import random
from Authapi.tasks import send_otp_email_task 
from Authapi.models import CustomUser, Doctor, Patient

logger = logging.getLogger(__name__)
class PasswordValidator:
    @staticmethod
    def validate(password):
        if len(password) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        if not re.search(r'[A-Z]', password):
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")
        if len(password) > 20:
            raise serializers.ValidationError("Password must be only 20 characters long.")
        if ' ' in password:
            raise serializers.ValidationError("Password cannot contain spaces.")
        if not re.search(r'[a-z]', password):
            raise serializers.ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r'[0-9]', password):
            raise serializers.ValidationError("Password must contain at least one digit.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/`~;]', password):
            raise serializers.ValidationError("Password must contain at least one special character (!@#$%^&* etc.).")
        return True


class PhoneValidator:
    @staticmethod
    def validate(phone):
        if not re.match(r'^[0-9]{10,15}$', phone):
            raise serializers.ValidationError("Phone number must be 10-15 digits.")
        return True


class SignupSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password1 = serializers.CharField(required=True, min_length=8, max_length=20, trim_whitespace=False)
    password2 = serializers.CharField(required=True, min_length=8, max_length=20, trim_whitespace=False)
    role = serializers.ChoiceField(choices=['doctor', 'patient'], required=True)

    def validate_email(self, value):
        value = value.strip().lower()
        if CustomUser.objects.filter(email=value, is_verified=True).exists():
            raise serializers.ValidationError("This email is already registered.")
        return value

    def validate_password1(self, value):
        PasswordValidator.validate(value)
        return value
    
    def validate_role(self, value):
        value = value.strip().lower()
        if value not in ['doctor', 'patient']:
            raise serializers.ValidationError("Invalid role. Choose either 'doctor' or 'patient'.")
        return value
    
    def validate(self, data):
        if data['password1'] != data['password2']:
            raise serializers.ValidationError({"password2": "Passwords do not match."})
        return data


class VerifySignupOTPSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    otp = serializers.CharField(required=True, max_length=6, min_length=6)

    def validate_email(self, value):
        return value.strip().lower()

    def validate_otp(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("OTP must contain only digits.")
        return value

    def validate(self, data):
        return data


class ResendSignupOTPSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        return value.strip().lower()

    def validate(self, data):
        return data


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)

    def validate_email(self, value):
        return value.strip().lower()

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("Invalid email or password.")

        if user.is_login_locked():
            if user.login_locked_until:
                remaining = max(0, (user.login_locked_until - timezone.now()).total_seconds() // 60)
                raise serializers.ValidationError(f"Account locked due to multiple failed attempts. Try again in {int(remaining) + 1} minutes.")
            raise serializers.ValidationError("Account temporarily locked. Try again later.")

        if not user.check_password(password):
            user.login_attempts += 1
            if user.login_attempts >= 5:
                user.login_locked_until = timezone.now() + timedelta(minutes=15)
            user.save()
            raise serializers.ValidationError("Invalid email or password.")

        user.reset_login_attempts()

        if not user.is_verified:
            raise serializers.ValidationError("Your account is not verified. Please verify your email first.")
        
        data['user'] = user
        data['is_profile_complete'] = user.is_profile_complete
        return data


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        return value.strip().lower()

    def validate(self, data):
        email = data.get('email')

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("No account found with this email. Please sign up.")

        if not user.is_verified:
            raise serializers.ValidationError("Your account is not verified. Please complete registration first.")

        otp = str(random.randint(100000, 999999))
        user.otp = otp
        user.otp_created_at = timezone.now()
        user.otp_type = 'reset'
        user.otp_attempts = 0
        user.otp_locked_until = None
        user.save()

        try:
           send_otp_email_task.delay(email, otp, 'reset')
        except Exception as e:
            raise serializers.ValidationError(f"Failed to send OTP. {str(e)}")

        data['user'] = user
        return data


class VerifyPasswordResetOTPSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    otp = serializers.CharField(required=True, max_length=6, min_length=6)

    def validate_email(self, value):
        return value.strip().lower()

    def validate_otp(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("OTP must contain only digits.")
        return value

    def validate(self, data):
        email = data.get('email')
        otp = data.get('otp')

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("No account found with this email.")

        if user.is_otp_locked():
            if user.otp_locked_until:
                remaining = max(0, (user.otp_locked_until - timezone.now()).total_seconds() // 60)
                raise serializers.ValidationError(f"Too many attempts. Try again in {int(remaining) + 1} minutes.")
            raise serializers.ValidationError("Account temporarily locked. Try again later.")

        if not user.otp:
            raise serializers.ValidationError("No OTP generated. Request a new one.")

        if user.is_otp_expired():
            user.clear_otp()
            raise serializers.ValidationError("OTP expired. Request a new one.")

        if user.otp != otp:
            user.otp_attempts += 1
            if user.otp_attempts >= 3:
                user.otp_locked_until = timezone.now() + timedelta(minutes=10)
            user.save()
            attempts_left = max(0, 3 - user.otp_attempts)
            raise serializers.ValidationError(f"Invalid OTP. {attempts_left} attempts remaining.")

        data['user'] = user
        return data


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    new_password = serializers.CharField(required=True, min_length=8, max_length=20, trim_whitespace=False)
    confirm_password = serializers.CharField(required=True, min_length=8, max_length=20, trim_whitespace=False)

    def validate_email(self, value):
        return value.strip().lower()

    def validate_new_password(self, value):
        PasswordValidator.validate(value)
        return value

    def validate(self, data):
        email = data.get('email')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("No account found with this email.")

        if new_password != confirm_password:
            raise serializers.ValidationError("Passwords do not match.")

        if user.check_password(new_password):
            raise serializers.ValidationError("New password cannot be the same as your current password.")

        data['user'] = user
        return data

    def save(self):
        user = self.validated_data['user']
        user.set_password(self.validated_data['new_password'])
        user.clear_otp()
        user.save()
        return user


class ResendPasswordResetOTPSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        return value.strip().lower()

    def validate(self, data):
        email = data.get('email')

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("No account found with this email.")

        if not user.is_verified:
            raise serializers.ValidationError("Your account is not verified.")

        if user.is_otp_locked():
            if user.otp_locked_until:
                remaining = max(0, (user.otp_locked_until - timezone.now()).total_seconds() // 60)
                raise serializers.ValidationError(f"Too many attempts. Try again in {int(remaining) + 1} minutes.")
            raise serializers.ValidationError("Account temporarily locked. Try again later.")

        data['user'] = user
        return data


class DoctorDetailsSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    first_name = serializers.CharField(required=True, max_length=50)
    last_name = serializers.CharField(required=True, max_length=50)
    date_of_birth = serializers.DateField(required=True)
    gender = serializers.ChoiceField(choices=['M', 'F', 'O','PNTS'], required=True)
    blood_group = serializers.ChoiceField(choices=['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'], required=True)
    marital_status = serializers.CharField(required=False, allow_blank=True, max_length=20)
    address = serializers.CharField(required=False, allow_blank=True, max_length=500)
    city = serializers.CharField(required=True, max_length=100)
    state = serializers.CharField(required=False, allow_blank=True, max_length=100)
    pincode = serializers.CharField(required=False, allow_blank=True, max_length=10)
    country = serializers.CharField(required=False, allow_blank=True, max_length=100)
    registration_number = serializers.CharField(required=False, allow_blank=True, max_length=50)
    specialization = serializers.CharField(required=False, allow_blank=True, max_length=100)
    qualification = serializers.CharField(required=False, allow_blank=True, max_length=200)
    years_of_experience = serializers.IntegerField(required=False, allow_null=True)
    department = serializers.CharField(required=False, allow_blank=True, max_length=100)
    clinic_name = serializers.CharField(required=False, allow_blank=True, max_length=200)
    phone_number = serializers.CharField(required=True, max_length=15)
    alternate_phone_number = serializers.CharField(required=False, allow_blank=True, max_length=15)
    alternate_email = serializers.EmailField(required=False, allow_blank=True)
    emergency_contact_person = serializers.CharField(required=False, allow_blank=True, max_length=100)
    emergency_contact_number = serializers.CharField(required=False, allow_blank=True, max_length=15)

    def validate_email(self, value):
        return value.strip().lower()

    def validate_first_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("First name cannot be empty.")
        return value.strip()

    def validate_last_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("Last name cannot be empty.")
        return value.strip()

    def validate_date_of_birth(self, value):
        today = date.today()
        if value > today:
            raise serializers.ValidationError("Date of birth cannot be in the future.")
        age = (today - value).days // 365
        if age < 25:
            raise serializers.ValidationError("Doctor must be at least 25 years old.")
        if age > 70:
            raise serializers.ValidationError("Please enter a valid date of birth.")
        return value

    def validate_city(self, value):
        if not value.strip():
            raise serializers.ValidationError("City cannot be empty.")
        return value.strip()

    def validate_phone_number(self, value):
        value = value.strip()
        PhoneValidator.validate(value)
        if Doctor.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("This phone number is already registered.")
        return value

    def validate_alternate_phone_number(self, value):
        if value and value.strip():
            value = value.strip()
            PhoneValidator.validate(value)
        return value

    def validate_alternate_email(self, value):
        if value:
            return value.strip().lower()
        return value

    def validate_emergency_contact_number(self, value):
        if value and value.strip():
            value = value.strip()
            PhoneValidator.validate(value)
        return value

    def validate_marital_status(self, value):
        if value:
            return value.strip()
        return value

    def validate_address(self, value):
        if value:
            return value.strip()
        return value

    def validate_state(self, value):
        if value:
            return value.strip()
        return value

    def validate_pincode(self, value):
        if value:
            return value.strip()
        return value

    def validate_country(self, value):
        if value:
            return value.strip()
        return value

    def validate_registration_number(self, value):
        if value:
            return value.strip().upper()
        return value

    def validate_specialization(self, value):
        if value:
            return value.strip()
        return value

    def validate_qualification(self, value):
        if value:
            return value.strip()
        return value

    def validate_department(self, value):
        if value:
            return value.strip()
        return value

    def validate_clinic_name(self, value):
        if value:
            return value.strip()
        return value

    def validate_emergency_contact_person(self, value):
        if value:
            return value.strip()
        return value
    
    def validate(self, data):
        years_exp = data.get('years_of_experience')
        if years_exp is not None and years_exp < 0:
            raise serializers.ValidationError("Years of experience cannot be negative.")
        return data


class PatientDetailsSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    first_name = serializers.CharField(required=True, max_length=50)
    last_name = serializers.CharField(required=True, max_length=50)
    date_of_birth = serializers.DateField(required=True)
    blood_group = serializers.ChoiceField(choices=['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'], required=True)
    gender = serializers.ChoiceField(choices=['M', 'F', 'O'], required=True)
    city = serializers.CharField(required=True, max_length=100)
    phone_number = serializers.CharField(required=True, max_length=15)
    emergency_contact = serializers.CharField(required=False, allow_blank=True, max_length=15)
    emergency_email = serializers.EmailField(required=False, allow_blank=True)
    is_insurance = serializers.BooleanField(required=False, default=False)
    ins_company_name = serializers.CharField(required=False, allow_blank=True, max_length=100)
    ins_policy_number = serializers.CharField(required=False, allow_blank=True, max_length=50)
    known_allergies = serializers.CharField(required=False, allow_blank=True, max_length=500)
    chronic_diseases = serializers.CharField(required=False, allow_blank=True, max_length=500)
    previous_surgeries = serializers.CharField(required=False, allow_blank=True, max_length=500)
    family_medical_history = serializers.CharField(required=False, allow_blank=True, max_length=500)

    def validate_email(self, value):
        return value.strip().lower()

    def validate_first_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("First name cannot be empty.")
        return value.strip()

    def validate_last_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("Last name cannot be empty.")
        return value.strip()

    def validate_date_of_birth(self, value):
        today = date.today()
        if value > today:
            raise serializers.ValidationError("Date of birth cannot be in the future.")
        age = (today - value).days // 365
        if age < 0:
            raise serializers.ValidationError("Please enter a valid date of birth.")
        if age > 150:
            raise serializers.ValidationError("Please enter a valid date of birth.")
        return value

    def validate_city(self, value):
        if not value.strip():
            raise serializers.ValidationError("City cannot be empty.")
        return value.strip()

    def validate_phone_number(self, value):
        value = value.strip()
        PhoneValidator.validate(value)
        if Patient.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("This phone number is already registered.")
        return value

    def validate_emergency_contact(self, value):
        if value and value.strip():
            value = value.strip()
            PhoneValidator.validate(value)
        return value

    def validate_emergency_email(self, value):
        if value:
            return value.strip().lower()
        return value

    def validate_ins_company_name(self, value):
        if value:
            return value.strip()
        return value

    def validate_ins_policy_number(self, value):
        if value:
            return value.strip()
        return value

    def validate_known_allergies(self, value):
        if value:
            return value.strip()
        return value

    def validate_chronic_diseases(self, value):
        if value:
            return value.strip()
        return value

    def validate_previous_surgeries(self, value):
        if value:
            return value.strip()
        return value

    def validate_family_medical_history(self, value):
        if value:
            return value.strip()
        return value
    
    def validate(self, data):
        is_insurance = data.get('is_insurance', False)
        ins_company = data.get('ins_company_name', '').strip() if data.get('ins_company_name') else ''
        ins_policy = data.get('ins_policy_number', '').strip() if data.get('ins_policy_number') else ''

        if is_insurance:
            if not ins_company:
                raise serializers.ValidationError("Insurance company name is required when insurance is selected.")
            if not ins_policy:
                raise serializers.ValidationError("Insurance policy number is required when insurance is selected.")

        return data