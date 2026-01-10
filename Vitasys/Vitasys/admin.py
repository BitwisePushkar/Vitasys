from django.contrib import admin
from django.contrib.admin import AdminSite
from django.utils.html import format_html


class vitasysAdminSite(AdminSite):
    site_header = format_html('<span style="color: #667eea; font-weight: bold; font-size: 24px;">🏥 vitasys Admin</span>')
    site_title = 'Vitasys Admin Portal'
    index_title = 'Healthcare Management Dashboard'
    
    def index(self, request, extra_context=None):
        from Authapi.models import CustomUser, Doctor, Patient
        from appointments.models import Appointment
        from community.models import Post
        from django.utils import timezone
        
        extra_context = extra_context or {}
        
        # Get statistics
        today = timezone.now().date()
        
        stats = {
            'total_users': CustomUser.objects.count(),
            'total_doctors': Doctor.objects.count(),
            'approved_doctors': Doctor.objects.filter(is_approved=True).count(),
            'total_patients': Patient.objects.count(),
            'total_appointments': Appointment.objects.count(),
            'pending_appointments': Appointment.objects.filter(status='pending').count(),
            'today_appointments': Appointment.objects.filter(appointment_date=today).count(),
            'total_posts': Post.objects.count(),
            'published_posts': Post.objects.filter(status='published').count(),
        }
        
        extra_context['stats'] = stats
        
        return super().index(request, extra_context)


admin.site = vitasysAdminSite()
