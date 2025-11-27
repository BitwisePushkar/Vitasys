from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import Appointment

@admin.register(Appointment)
class AppointmentAdmin(admin.ModelAdmin):
    list_display = [
        'id',
        'patient_name_link',
        'doctor_name_link',
        'appointment_date',
        'appointment_time',
        'status_badge',
        'created_at'
    ]
    
    list_filter = [
        'status',
        'appointment_date',
        'created_at',
        'doctor__specialization'
    ]
    
    search_fields = [
        'patient__first_name',
        'patient__last_name',
        'doctor__first_name',
        'doctor__last_name',
        'patient__user__email',
        'doctor__user__email',
        'reason'
    ]
    
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Appointment Details', {
            'fields': (
                'doctor',
                'patient',
                'appointment_date',
                'appointment_time',
                'reason'
            )
        }),
        ('Status & Notes', {
            'fields': (
                'status',
                'notes'
            )
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    date_hierarchy = 'appointment_date'
    ordering = ['-appointment_date', '-appointment_time']
    
    def patient_name_link(self, obj):
        """Link to patient profile"""
        url = reverse('admin:Authapi_patient_change', args=[obj.patient.id])
        return format_html('<a href="{}">{}</a>', url, obj.patient.get_full_name())
    patient_name_link.short_description = 'Patient'
    
    def doctor_name_link(self, obj):
        """Link to doctor profile"""
        url = reverse('admin:Authapi_doctor_change', args=[obj.doctor.id])
        return format_html('<a href="{}">Dr. {}</a>', url, obj.doctor.get_full_name())
    doctor_name_link.short_description = 'Doctor'
    
    def status_badge(self, obj):
        """Display status with colored badge"""
        colors = {
            'pending': '#ffc107',
            'confirmed': '#007bff',
            'completed': '#28a745',
            'cancelled': '#dc3545'
        }
        color = colors.get(obj.status, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; '
            'border-radius: 3px; font-weight: bold; text-transform: uppercase;">{}</span>',
            color, obj.status
        )
    status_badge.short_description = 'Status'
    
    actions = ['mark_confirmed', 'mark_completed', 'mark_cancelled']
    
    def mark_confirmed(self, request, queryset):
        updated = queryset.update(status='confirmed')
        self.message_user(request, f'{updated} appointment(s) confirmed.')
    mark_confirmed.short_description = "Mark as Confirmed"
    
    def mark_completed(self, request, queryset):
        updated = queryset.update(status='completed')
        self.message_user(request, f'{updated} appointment(s) marked as completed.')
    mark_completed.short_description = "Mark as Completed"
    
    def mark_cancelled(self, request, queryset):
        updated = queryset.update(status='cancelled')
        self.message_user(request, f'{updated} appointment(s) cancelled.')
    mark_cancelled.short_description = "Mark as Cancelled"