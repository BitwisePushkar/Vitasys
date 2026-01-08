import re
import logging
from datetime import timedelta, date
from django.utils import timezone
from rest_framework import serializers
from users.models import CustomUser, Doctor, Patient, Nurse, Pharmacist

logger = logging.getLogger(__name__)

class PasswordValidator:
    @staticmethod
    def validate(password: str):
        if len(password) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        if len(password) > 20:
            raise serializers.ValidationError("Password must not exceed 20 characters.")
        if ' ' in password:
            raise serializers.ValidationError("Password cannot contain spaces.")
        if not re.search(r'[A-Z]', password):
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', password):
            raise serializers.ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r'[0-9]', password):
            raise serializers.ValidationError("Password must contain at least one digit.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/`~;]', password):
            raise serializers.ValidationError("Password must contain at least one special character.")

class PhoneValidator:
    @staticmethod
    def validate(phone: str):
        if not re.match(r'^[0-9]{10,15}$', phone):
            raise serializers.ValidationError("Phone number must be 10–15 digits, numbers only.")

class UsernameValidator:
    @staticmethod
    def validate(username: str):
        if len(username) < 3:
            raise serializers.ValidationError("Username must be at least 3 characters long.")
        if len(username) > 20:
            raise serializers.ValidationError("Username must not exceed 20 characters.")
        if not re.match(r'^[a-zA-Z0-9_\-]+$', username):
            raise serializers.ValidationError("Username can only contain letters, numbers, underscores, and hyphens.")
        if username.isdigit():
            raise serializers.ValidationError("Username cannot be purely numeric.")

def _validate_name(value: str, field: str) -> str:
    value = value.strip()
    if not value:
        raise serializers.ValidationError(f"{field} cannot be empty.")
    if not re.match(r'^[a-zA-Z\s\-]+$', value):
        raise serializers.ValidationError(f"{field} can only contain letters, spaces, and hyphens.")
    return value

class SignupSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    username = serializers.CharField(required=True, min_length=3, max_length=20, trim_whitespace=True)
    password1 = serializers.CharField(required=True, min_length=8, max_length=20, trim_whitespace=False)
    password2 = serializers.CharField(required=True, min_length=8, max_length=20, trim_whitespace=False)
    role = serializers.ChoiceField(choices=['doctor', 'patient', 'nurse', 'pharmacist'], required=True)

    def validate_email(self, value):
        value = value.strip().lower()
        if CustomUser.objects.filter(email=value, is_verified=True).exists():
            raise serializers.ValidationError("An account with this email already exists.")
        return value

    def validate_username(self, value):
        value = value.strip().lower()
        UsernameValidator.validate(value)
        reserved = ['admin', 'root', 'superuser', 'vitasys', 'support', 'help']
        if value in reserved:
            raise serializers.ValidationError("This username is reserved. Please choose another.")
        if CustomUser.objects.filter(username=value, is_verified=True).exists():
            raise serializers.ValidationError("This username is already taken.")
        return value

    def validate_password1(self, value):
        PasswordValidator.validate(value)
        return value

    def validate_role(self, value):
        return value.strip().lower()

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

class ResendSignupOTPSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    def validate_email(self, value):
        return value.strip().lower()

class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField(required=True, help_text="Your email address or username")
    password = serializers.CharField(required=True, trim_whitespace=False)

    def validate(self, data):
        identifier = data.get('identifier', '').strip()
        password = data.get('password', '')
        if not identifier:
            raise serializers.ValidationError("Email or username is required.")
        user = None
        if '@' in identifier:
            try:
                user = CustomUser.objects.get(email=identifier.lower())
            except CustomUser.DoesNotExist:
                pass
        else:
            try:
                user = CustomUser.objects.get(username=identifier.lower())
            except CustomUser.DoesNotExist:
                pass
        if user is None:
            raise serializers.ValidationError("Invalid credentials. Please check and try again.")
        if not user.is_active:
            raise serializers.ValidationError("This account has been deactivated. Use /auth/reactivate-account/ to restore it.")
        if user.is_login_locked():
            remaining = 1
            if user.login_locked_until:
                remaining = int(max(0, (user.login_locked_until - timezone.now()).total_seconds() // 60)) + 1
            raise serializers.ValidationError(f"Account locked due to multiple failed attempts. Try again in {remaining} minute(s).")
        if not user.check_password(password):
            user.login_attempts += 1
            if user.login_attempts >= 5:
                user.login_locked_until = timezone.now() + timedelta(minutes=15)
                user.save(update_fields=['login_attempts', 'login_locked_until'])
                raise serializers.ValidationError("Too many failed attempts. Account locked for 15 minutes.")
            user.save(update_fields=['login_attempts'])
            attempts_left = max(0, 5 - user.login_attempts)
            raise serializers.ValidationError(f"Invalid credentials. {attempts_left} attempt(s) remaining before lockout.")
        user.reset_login_attempts()
        if not user.is_verified:
            raise serializers.ValidationError("Your email is not verified. Please complete signup first.")
        data['user'] = user
        data['is_profile_complete'] = user.is_profile_complete
        return data

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    def validate_email(self, value): 
        return value.strip().lower()

class VerifyPasswordResetOTPSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    otp   = serializers.CharField(required=True, max_length=6, min_length=6)

    def validate_email(self, value):
        return value.strip().lower()
    def validate_otp(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("OTP must contain only digits.")
        return value

    def validate(self, data):
        try:
            user = CustomUser.objects.get(email=data.get('email'))
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("No account found with this email.")
        if user.is_otp_locked():
            remaining = int(max(0, (user.otp_locked_until - timezone.now()).total_seconds() // 60)) + 1 if user.otp_locked_until else 1
            raise serializers.ValidationError(f"Too many attempts. Try again in {remaining} minute(s).")
        if not user.otp:
            raise serializers.ValidationError("No OTP found. Please request a new one.")
        if user.is_otp_expired():
            user.clear_otp()
            raise serializers.ValidationError("OTP has expired. Please request a new one.")
        if user.otp_type != 'reset':
            raise serializers.ValidationError("Invalid OTP type. Please request a password reset OTP first.")
        if user.otp != data.get('otp'):
            user.otp_attempts += 1
            if user.otp_attempts >= 3:
                user.otp_locked_until = timezone.now() + timedelta(minutes=10)
            user.save(update_fields=['otp_attempts', 'otp_locked_until'])
            attempts_left = max(0, 3 - user.otp_attempts)
            raise serializers.ValidationError(f"Invalid OTP. {attempts_left} attempt(s) remaining.")
        user.otp_type = 'reset_verified'
        user.otp_attempts = 0
        user.save(update_fields=['otp_type', 'otp_attempts'])
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
        try:
            user = CustomUser.objects.get(email=data.get('email'))
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("No account found with this email.")
        if user.otp_type != 'reset_verified':
            raise serializers.ValidationError("OTP verification required before resetting password.")
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        if user.check_password(data['new_password']):
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
        try:
            user = CustomUser.objects.get(email=data.get('email'))
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("If this email is registered, a new OTP will be sent.")
        if not user.is_verified:
            raise serializers.ValidationError("This account is not verified.")
        if user.otp_type not in ('reset', 'reset_verified'):
            raise serializers.ValidationError("No active password reset request found. Please call /forgot-password/ first.")
        if user.is_otp_locked():
            remaining = int(max(0, (user.otp_locked_until - timezone.now()).total_seconds() // 60)) + 1 if user.otp_locked_until else 1
            raise serializers.ValidationError(f"Too many attempts. Try again in {remaining} minute(s).")
        data['user'] = user
        return data

class DeactivateAccountSerializer(serializers.Serializer):
    password = serializers.CharField(required=True, trim_whitespace=False)
    def validate_password(self, value):
        user = self.context.get('user')
        if user and not user.check_password(value):
            raise serializers.ValidationError("Incorrect password.")
        return value

class ReactivateAccountSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, trim_whitespace=False)

    def validate_email(self, value):
        return value.strip().lower()

    def validate(self, data):
        try:
            user = CustomUser.objects.get(email=data.get('email'))
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("Invalid credentials.")
        if user.is_active:
            raise serializers.ValidationError("This account is already active. Please login normally.")
        if not user.is_verified:
            raise serializers.ValidationError("This account has not completed email verification.")
        if not user.check_password(data.get('password')):
            raise serializers.ValidationError("Invalid credentials.")
        data['user'] = user
        return data

class DeleteAccountSerializer(serializers.Serializer):
    password = serializers.CharField(required=True, trim_whitespace=False)
    def validate_password(self, value):
        user = self.context.get('user')
        if user and not user.check_password(value):
            raise serializers.ValidationError("Incorrect password.")
        return value

class DoctorDetailsSerializer(serializers.Serializer):
    first_name = serializers.CharField(required=True, max_length=50)
    last_name = serializers.CharField(required=True, max_length=50)
    date_of_birth = serializers.DateField(required=True)
    gender = serializers.ChoiceField(choices=['M', 'F', 'O'], required=True)
    blood_group = serializers.ChoiceField(choices=['A+','A-','B+','B-','AB+','AB-','O+','O-'], required=True)
    marital_status = serializers.CharField(required=False, allow_blank=True, max_length=20)
    address = serializers.CharField(required=False, allow_blank=True, max_length=500)
    city = serializers.CharField(required=True, max_length=100)
    state = serializers.CharField(required=False, allow_blank=True, max_length=100)
    pincode = serializers.CharField(required=False, allow_blank=True, max_length=10)
    country = serializers.CharField(required=False, allow_blank=True, max_length=100)
    registration_number = serializers.CharField(required=False, allow_blank=True, max_length=50)
    specialization = serializers.CharField(required=False, allow_blank=True, max_length=100)
    qualification = serializers.CharField(required=False, allow_blank=True, max_length=200)
    years_of_experience = serializers.IntegerField(required=False, allow_null=True, min_value=0, max_value=50)
    department = serializers.CharField(required=False, allow_blank=True, max_length=100)
    clinic_name = serializers.CharField(required=False, allow_blank=True, max_length=200)
    phone_number = serializers.CharField(required=True, max_length=15)
    alternate_phone_number = serializers.CharField(required=False, allow_blank=True, max_length=15)
    alternate_email = serializers.EmailField(required=False, allow_blank=True)
    emergency_contact_person = serializers.CharField(required=False, allow_blank=True, max_length=100)
    emergency_contact_number = serializers.CharField(required=False, allow_blank=True, max_length=15)
    profile_image = serializers.ImageField(required=False, allow_null=True) 

    def validate_first_name(self, v):
        return _validate_name(v, 'First name')
    def validate_last_name(self, v): 
        return _validate_name(v, 'Last name')

    def validate_date_of_birth(self, value):
        today = date.today()
        if value > today:
            raise serializers.ValidationError("Date of birth cannot be in the future.")
        age = (today - value).days // 365
        if age < 25: raise serializers.ValidationError("Doctor must be at least 25 years old.")
        if age > 70: raise serializers.ValidationError("Age must be 70 or below for active registration.")
        return value

    def validate_phone_number(self, value):
        value = value.strip()
        PhoneValidator.validate(value)
        qs = Doctor.objects.filter(phone_number=value)
        if self.context.get('exclude_user'):
            qs = qs.exclude(user=self.context['exclude_user'])
        if qs.exists():
            raise serializers.ValidationError("This phone number is already registered with another doctor.")
        return value

    def validate_alternate_phone_number(self, value):
        if value and value.strip():PhoneValidator.validate(value.strip()); return value.strip()
        return value

    def validate_emergency_contact_number(self, value):
        if value and value.strip(): PhoneValidator.validate(value.strip()); return value.strip()
        return value

    def validate_city(self, v):
        v = v.strip()
        if not v: raise serializers.ValidationError("City cannot be empty.")
        return v

    def validate_alternate_email(self, v):       
        return v.strip().lower() if v else v
    def validate_registration_number(self, v):      
        return v.strip().upper() if v else v
    def validate_marital_status(self, v):           
        return v.strip() if v else v
    def validate_address(self, v):                  
        return v.strip() if v else v
    def validate_state(self, v):                    
        return v.strip() if v else v
    def validate_pincode(self, v):                  
        return v.strip() if v else v
    def validate_country(self, v):                  
        return v.strip() if v else v
    def validate_specialization(self, v):           
        return v.strip() if v else v
    def validate_qualification(self, v):            
        return v.strip() if v else v
    def validate_department(self, v):               
        return v.strip() if v else v
    def validate_clinic_name(self, v):              
        return v.strip() if v else v
    def validate_emergency_contact_person(self, v): 
        return v.strip() if v else v

    def validate(self, data):
        if data.get('alternate_phone_number') and data['alternate_phone_number'] == data.get('phone_number'):
            raise serializers.ValidationError({"alternate_phone_number": "Alternate phone cannot be the same as primary phone."})
        dob, exp = data.get('date_of_birth'), data.get('years_of_experience')
        if dob and exp is not None and exp > (date.today() - dob).days // 365 - 25:
            raise serializers.ValidationError({"years_of_experience": "Years of experience is not possible given the stated age."})
        return data

class PatientDetailsSerializer(serializers.Serializer):
    first_name = serializers.CharField(required=True, max_length=50)
    last_name = serializers.CharField(required=True, max_length=50)
    date_of_birth = serializers.DateField(required=True)
    blood_group = serializers.ChoiceField(choices=['A+','A-','B+','B-','AB+','AB-','O+','O-'], required=True)
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
    profile_image = serializers.ImageField(required=False, allow_null=True) 

    def validate_first_name(self, v): 
        return _validate_name(v, 'First name')
    def validate_last_name(self, v):  
        return _validate_name(v, 'Last name')

    def validate_date_of_birth(self, value):
        today = date.today()
        if value > today: 
            raise serializers.ValidationError("Date of birth cannot be in the future.")
        if (today - value).days // 365 > 120: 
            raise serializers.ValidationError("Please enter a valid date of birth.")
        return value

    def validate_phone_number(self, value):
        value = value.strip()
        PhoneValidator.validate(value)
        qs = Patient.objects.filter(phone_number=value)
        if self.context.get('exclude_user'):
            qs = qs.exclude(user=self.context['exclude_user'])
        if qs.exists():
            raise serializers.ValidationError("This phone number is already registered with another patient.")
        return value

    def validate_city(self, v):
        v = v.strip()
        if not v: 
            raise serializers.ValidationError("City cannot be empty.")
        return v

    def validate_emergency_contact(self, value):
        if value and value.strip(): PhoneValidator.validate(value.strip()); return value.strip()
        return value

    def validate_emergency_email(self, v):        
        return v.strip().lower() if v else v
    def validate_ins_company_name(self, v):       
        return v.strip() if v else v
    def validate_ins_policy_number(self, v):      
        return v.strip() if v else v
    def validate_known_allergies(self, v):        
        return v.strip() if v else v
    def validate_chronic_diseases(self, v):       
        return v.strip() if v else v
    def validate_previous_surgeries(self, v):     
        return v.strip() if v else v
    def validate_family_medical_history(self, v): 
        return v.strip() if v else v

    def validate(self, data):
        if data.get('is_insurance'):
            if not (data.get('ins_company_name') or '').strip():
                raise serializers.ValidationError({"ins_company_name": "Insurance company name is required when insurance is enabled."})
            if not (data.get('ins_policy_number') or '').strip():
                raise serializers.ValidationError({"ins_policy_number": "Insurance policy number is required when insurance is enabled."})
        if data.get('emergency_contact') and data['emergency_contact'] == data.get('phone_number'):
            raise serializers.ValidationError({"emergency_contact": "Emergency contact cannot be the same as your phone number."})
        return data

class NurseDetailsSerializer(serializers.Serializer):
    first_name = serializers.CharField(required=True, max_length=50)
    last_name = serializers.CharField(required=True, max_length=50)
    date_of_birth = serializers.DateField(required=True)
    gender = serializers.ChoiceField(choices=['M', 'F', 'O'], required=True)
    blood_group = serializers.ChoiceField(choices=['A+','A-','B+','B-','AB+','AB-','O+','O-'], required=True)
    phone_number = serializers.CharField(required=True, max_length=15)
    department = serializers.CharField(required=True, max_length=100)
    qualification = serializers.CharField(required=False, allow_blank=True, max_length=200)
    years_of_experience = serializers.IntegerField(required=False, allow_null=True, min_value=0, max_value=45)
    employee_id = serializers.CharField(required=False, allow_blank=True, max_length=50)
    city = serializers.CharField(required=True, max_length=100)
    state = serializers.CharField(required=False, allow_blank=True, max_length=100)
    country = serializers.CharField(required=False, allow_blank=True, max_length=100)
    profile_image = serializers.ImageField(required=False, allow_null=True) 

    def validate_first_name(self, v): 
        return _validate_name(v, 'First name')
    def validate_last_name(self, v):  
        return _validate_name(v, 'Last name')
    
    def validate_date_of_birth(self, value):
        today = date.today()
        if value > today: raise serializers.ValidationError("Date of birth cannot be in the future.")
        age = (today - value).days // 365
        if age < 20: raise serializers.ValidationError("Nurse must be at least 20 years old.")
        if age > 60: raise serializers.ValidationError("Age must be 60 or below for active registration.")
        return value

    def validate_phone_number(self, value):
        value = value.strip()
        PhoneValidator.validate(value)
        qs = Nurse.objects.filter(phone_number=value)
        if self.context.get('exclude_user'):
            qs = qs.exclude(user=self.context['exclude_user'])
        if qs.exists():
            raise serializers.ValidationError("This phone number is already registered with another nurse.")
        return value

    def validate_employee_id(self, value):
        if not value or not value.strip(): return None
        value = value.strip()
        qs = Nurse.objects.filter(employee_id=value)
        if self.context.get('exclude_user'):
            qs = qs.exclude(user=self.context['exclude_user'])
        if qs.exists():
            raise serializers.ValidationError("This employee ID is already assigned to another nurse.")
        return value

    def validate_city(self, v):
        v = v.strip()
        if not v: raise serializers.ValidationError("City cannot be empty.")
        return v

    def validate_department(self, v):
        v = v.strip()
        if not v: raise serializers.ValidationError("Department cannot be empty.")
        return v

    def validate_qualification(self, v): 
        return v.strip() if v else v
    def validate_state(self, v):         
        return v.strip() if v else v
    def validate_country(self, v):       
        return v.strip() if v else v

    def validate(self, data):
        dob, exp = data.get('date_of_birth'), data.get('years_of_experience')
        if dob and exp is not None and exp > (date.today() - dob).days // 365 - 20:
            raise serializers.ValidationError({"years_of_experience": "Years of experience is not possible given the stated age."})
        return data

class PharmacistDetailsSerializer(serializers.Serializer):
    first_name = serializers.CharField(required=True, max_length=50)
    last_name = serializers.CharField(required=True, max_length=50)
    date_of_birth = serializers.DateField(required=True)
    gender = serializers.ChoiceField(choices=['M', 'F', 'O'], required=True)
    blood_group = serializers.ChoiceField(choices=['A+','A-','B+','B-','AB+','AB-','O+','O-'], required=True)
    phone_number = serializers.CharField(required=True, max_length=15)
    license_number = serializers.CharField(required=False, allow_blank=True, max_length=50)
    qualification = serializers.CharField(required=False, allow_blank=True, max_length=200)
    years_of_experience = serializers.IntegerField(required=False, allow_null=True, min_value=0, max_value=45)
    employee_id = serializers.CharField(required=False, allow_blank=True, max_length=50)
    city = serializers.CharField(required=True, max_length=100)
    state = serializers.CharField(required=False, allow_blank=True, max_length=100)
    country = serializers.CharField(required=False, allow_blank=True, max_length=100)
    profile_image = serializers.ImageField(required=False, allow_null=True) 

    def validate_first_name(self, v): 
        return _validate_name(v, 'First name')
    def validate_last_name(self, v):  
        return _validate_name(v, 'Last name')

    def validate_date_of_birth(self, value):
        today = date.today()
        if value > today: raise serializers.ValidationError("Date of birth cannot be in the future.")
        age = (today - value).days // 365
        if age < 22: 
            raise serializers.ValidationError("Pharmacist must be at least 22 years old.")
        if age > 65: 
            raise serializers.ValidationError("Age must be 65 or below for active registration.")
        return value

    def validate_phone_number(self, value):
        value = value.strip()
        PhoneValidator.validate(value)
        qs = Pharmacist.objects.filter(phone_number=value)
        if self.context.get('exclude_user'):
            qs = qs.exclude(user=self.context['exclude_user'])
        if qs.exists():
            raise serializers.ValidationError("This phone number is already registered with another pharmacist.")
        return value

    def validate_license_number(self, value):
        if not value or not value.strip(): return None
        value = value.strip().upper()
        qs = Pharmacist.objects.filter(license_number=value)
        if self.context.get('exclude_user'):
            qs = qs.exclude(user=self.context['exclude_user'])
        if qs.exists():
            raise serializers.ValidationError("This license number is already registered with another pharmacist.")
        return value

    def validate_employee_id(self, value):
        if not value or not value.strip(): 
            return None
        value = value.strip()
        qs = Pharmacist.objects.filter(employee_id=value)
        if self.context.get('exclude_user'):
            qs = qs.exclude(user=self.context['exclude_user'])
        if qs.exists():
            raise serializers.ValidationError("This employee ID is already assigned to another pharmacist.")
        return value

    def validate_city(self, v):
        v = v.strip()
        if not v: 
            raise serializers.ValidationError("City cannot be empty.")
        return v
    
    def validate_qualification(self, v): 
        return v.strip() if v else v
    def validate_state(self, v):         
        return v.strip() if v else v
    def validate_country(self, v):       
        return v.strip() if v else v
    
    def validate(self, data):
        dob, exp = data.get('date_of_birth'), data.get('years_of_experience')
        if dob and exp is not None and exp > (date.today() - dob).days // 365 - 22:
            raise serializers.ValidationError({"years_of_experience": "Years of experience is not possible given the stated age."})
        return data