from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import DoctorReview


@admin.register(DoctorReview)
class DoctorReviewAdmin(admin.ModelAdmin):
    list_display = [
        'id',
        'doctor_name_link',
        'patient_name_link',
        'rating_stars',
        'short_comment',
        'created_at'
    ]
    
    list_filter = [
        'rating',
        'created_at',
        'doctor__specialization'
    ]
    
    search_fields = [
        'doctor__first_name',
        'doctor__last_name',
        'patient__first_name',
        'patient__last_name',
        'comment'
    ]
    
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Review Details', {
            'fields': (
                'doctor',
                'patient',
                'rating',
                'comment'
            )
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    date_hierarchy = 'created_at'
    ordering = ['-created_at']
    
    def doctor_name_link(self, obj):
        url = reverse('admin:Authapi_doctor_change', args=[obj.doctor.id])
        return format_html('<a href="{}">Dr. {}</a>', url, obj.doctor.get_full_name())
    doctor_name_link.short_description = 'Doctor'
    
    def patient_name_link(self, obj):
        url = reverse('admin:Authapi_patient_change', args=[obj.patient.id])
        return format_html('<a href="{}">{}</a>', url, obj.patient.get_full_name())
    patient_name_link.short_description = 'Patient'
    
    def rating_stars(self, obj):
        stars = '⭐' * obj.rating
        color = '#ffc107' if obj.rating >= 4 else '#dc3545' if obj.rating <= 2 else '#6c757d'
        return format_html(
            '<span style="color: {}; font-size: 18px;">{} ({})</span>',
            color, stars, obj.rating
        )
    rating_stars.short_description = 'Rating'
    
    def short_comment(self, obj):
        return obj.comment[:50] + '...' if len(obj.comment) > 50 else obj.comment
    short_comment.short_description = 'Comment'

    