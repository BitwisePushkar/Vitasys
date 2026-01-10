from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import CustomUser, Doctor, Patient

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):

    list_display = [
        'email', 
        'username', 
        'role_badge', 
        'is_verified_badge', 
        'is_profile_complete_badge',
        'is_active',
        'created_at'
    ]
    
    list_filter = [
        'role', 
        'is_verified', 
        'is_profile_complete', 
        'is_active', 
        'is_staff',
        'created_at'
    ]
    
    search_fields = ['email', 'username', 'first_name', 'last_name']
    
    ordering = ['-created_at']
    
    readonly_fields = [
        'created_at', 
        'updated_at', 
        'last_login',
        'otp_created_at',
        'login_locked_until',
        'otp_locked_until'
    ]
    
    fieldsets = (
        ('Account Info', {
            'fields': ('username', 'email', 'password')
        }),
        ('Role & Verification', {
            'fields': ('role', 'is_verified', 'is_profile_complete')
        }),
        ('OTP & Security', {
            'fields': (
                'otp', 
                'otp_type',
                'otp_created_at', 
                'otp_attempts',
                'otp_locked_until'
            ),
            'classes': ('collapse',)
        }),
        ('Login Security', {
            'fields': (
                'login_attempts',
                'login_locked_until'
            ),
            'classes': ('collapse',)
        }),
        ('Permissions', {
            'fields': (
                'is_active',
                'is_staff',
                'is_superuser',
                'groups',
                'user_permissions'
            ),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'last_login'),
            'classes': ('collapse',)
        }),
    )
    
    add_fieldsets = (
        ('Create New User', {
            'classes': ('wide',),
            'fields': (
                'username',
                'email',
                'password1',
                'password2',
                'role',
                'is_verified',
                'is_profile_complete'
            ),
        }),
    )
    
    def role_badge(self, obj):

        colors = {
            'doctor': '#28a745',
            'patient': '#007bff',
            None: '#6c757d'
        }
        role = obj.role or 'unassigned'
        color = colors.get(obj.role, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; '
            'border-radius: 3px; font-weight: bold;">{}</span>',
            color, role.upper()
        )
    role_badge.short_description = 'Role'
    
    def is_verified_badge(self, obj):

        if obj.is_verified:
            return format_html(
                '<span style="color: green; font-size: 16px;">✓ Verified</span>'
            )
        return format_html(
            '<span style="color: red; font-size: 16px;">✗ Not Verified</span>'
        )
    is_verified_badge.short_description = 'Verified'
    
    def is_profile_complete_badge(self, obj):

        if obj.is_profile_complete:
            return format_html(
                '<span style="color: green; font-size: 16px;">✓ Complete</span>'
            )
        return format_html(
            '<span style="color: orange; font-size: 16px;">⚠ Incomplete</span>'
        )
    is_profile_complete_badge.short_description = 'Profile'
    
    actions = ['verify_users', 'mark_profile_complete', 'reset_otp_locks']
    
    def verify_users(self, request, queryset):

        updated = queryset.update(is_verified=True)
        self.message_user(request, f'{updated} user(s) verified successfully.')
    verify_users.short_description = "Verify selected users"
    
    def mark_profile_complete(self, request, queryset):
        """Mark profiles as complete"""
        updated = queryset.update(is_profile_complete=True)
        self.message_user(request, f'{updated} profile(s) marked as complete.')
    mark_profile_complete.short_description = "Mark profiles as complete"
    
    def reset_otp_locks(self, request, queryset):
        """Reset OTP locks for users"""
        updated = queryset.update(
            otp_attempts=0,
            otp_locked_until=None,
            login_attempts=0,
            login_locked_until=None
        )
        self.message_user(request, f'{updated} user(s) unlocked successfully.')
    reset_otp_locks.short_description = "Reset OTP/Login locks"


@admin.register(Doctor)
class DoctorAdmin(admin.ModelAdmin):

    list_display = [
        'id',
        'full_name_display',
        'specialization',
        'department',
        'city',
        'phone_number',
        'is_approved_badge',
        'created_at'
    ]
    
    list_filter = [
        'is_approved',
        'gender',
        'specialization',
        'department',
        'city',
        'blood_group',
        'created_at'
    ]
    
    search_fields = [
        'first_name',
        'last_name',
        'user__email',
        'user__username',
        'phone_number',
        'registration_number',
        'specialization'
    ]
    
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('User Account', {
            'fields': ('user',)
        }),
        ('Personal Information', {
            'fields': (
                'first_name',
                'last_name',
                'date_of_birth',
                'gender',
                'blood_group',
                'marital_status'
            )
        }),
        ('Contact Information', {
            'fields': (
                'phone_number',
                'alternate_phone_number',
                'alternate_email',
                'emergency_contact_person',
                'emergency_contact_number'
            )
        }),
        ('Address', {
            'fields': (
                'address',
                'city',
                'state',
                'pincode',
                'country'
            )
        }),
        ('Professional Information', {
            'fields': (
                'registration_number',
                'specialization',
                'qualification',
                'years_of_experience',
                'department',
                'clinic_name'
            )
        }),
        ('Approval Status', {
            'fields': ('is_approved',),
            'classes': ('wide',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    ordering = ['-created_at']
    
    def full_name_display(self, obj):
        """Display full name with link to user"""
        user_url = reverse('admin:Authapi_customuser_change', args=[obj.user.id])
        return format_html(
            'Dr. <a href="{}">{}</a>',
            user_url,
            obj.get_full_name()
        )
    full_name_display.short_description = 'Doctor Name'
    
    def is_approved_badge(self, obj):
        """Display approval status with badge"""
        if obj.is_approved:
            return format_html(
                '<span style="background-color: #28a745; color: white; padding: 3px 10px; '
                'border-radius: 3px; font-weight: bold;">✓ APPROVED</span>'
            )
        return format_html(
            '<span style="background-color: #dc3545; color: white; padding: 3px 10px; '
            'border-radius: 3px; font-weight: bold;">✗ PENDING</span>'
        )
    is_approved_badge.short_description = 'Status'
    
    actions = ['approve_doctors', 'disapprove_doctors']
    
    def approve_doctors(self, request, queryset):
        """Bulk approve doctors"""
        updated = queryset.update(is_approved=True)
        self.message_user(request, f'{updated} doctor(s) approved successfully.')
    approve_doctors.short_description = "✓ Approve selected doctors"
    
    def disapprove_doctors(self, request, queryset):
        """Bulk disapprove doctors"""
        updated = queryset.update(is_approved=False)
        self.message_user(request, f'{updated} doctor(s) disapproved.')
    disapprove_doctors.short_description = "✗ Disapprove selected doctors"


@admin.register(Patient)
class PatientAdmin(admin.ModelAdmin):

    list_display = [
        'id',
        'full_name_display',
        'gender',
        'blood_group',
        'city',
        'phone_number',
        'has_insurance_badge',
        'created_at'
    ]
    
    list_filter = [
        'gender',
        'blood_group',
        'city',
        'is_insurance',
        'created_at'
    ]
    
    search_fields = [
        'first_name',
        'last_name',
        'user__email',
        'user__username',
        'phone_number'
    ]
    
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('User Account', {
            'fields': ('user',)
        }),
        ('Personal Information', {
            'fields': (
                'first_name',
                'last_name',
                'date_of_birth',
                'gender',
                'blood_group',
                'city'
            )
        }),
        ('Contact Information', {
            'fields': (
                'phone_number',
                'emergency_contact',
                'emergency_email'
            )
        }),
        ('Insurance Information', {
            'fields': (
                'is_insurance',
                'ins_company_name',
                'ins_policy_number'
            )
        }),
        ('Medical History', {
            'fields': (
                'known_allergies',
                'chronic_diseases',
                'previous_surgeries',
                'family_medical_history'
            ),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    ordering = ['-created_at']
    
    def full_name_display(self, obj):

        user_url = reverse('admin:Authapi_customuser_change', args=[obj.user.id])
        return format_html(
            '<a href="{}">{}</a>',
            user_url,
            obj.get_full_name()
        )
    full_name_display.short_description = 'Patient Name'
    
    def has_insurance_badge(self, obj):

        if obj.is_insurance:
            return format_html(
                '<span style="color: green; font-size: 16px;">✓ Insured</span>'
            )
        return format_html(
            '<span style="color: gray; font-size: 16px;">○ No Insurance</span>'
        )
    has_insurance_badge.short_description = 'Insurance'