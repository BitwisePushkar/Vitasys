from django.urls import path
from .views import (
    PatientBookAppointmentView,
    PatientAppointmentListView,
    DoctorAppointmentRequestsView,
    DoctorAppointmentsListView,
    DoctorAcceptAppointmentView,
    DoctorRejectAppointmentView,
    AvailableDoctorsListView,
    DoctorAvailableSlotsView,
    DoctorDashboardStatsView,
    PatientDashboardStatsView,
    PatientUpcomingAppointmentsView,
    PatientRecentAppointmentsView,
    DoctorQueueInfoView
)

urlpatterns = [
    # Patient endpoints
    path('patient/book/', PatientBookAppointmentView.as_view(), name='patient-book-appointment'),
    path('patient/list/', PatientAppointmentListView.as_view(), name='patient-appointments-list'),
    path('doctors/available/', AvailableDoctorsListView.as_view(), name='available-doctors'),
    path('doctors/<int:doctor_id>/available-slots/', DoctorAvailableSlotsView.as_view(), name='doctor-available-slots'),
    
    # Doctor endpoints
    path('doctor/requests/', DoctorAppointmentRequestsView.as_view(), name='doctor-appointment-requests'),
    path('doctor/appointments/', DoctorAppointmentsListView.as_view(), name='doctor-appointments-list'),
    path('doctor/<int:appointment_id>/accept/', DoctorAcceptAppointmentView.as_view(), name='doctor-accept-appointment'),
    path('doctor/<int:appointment_id>/reject/', DoctorRejectAppointmentView.as_view(), name='doctor-reject-appointment'),
    path('doctors/<int:doctor_id>/queue-info/', DoctorQueueInfoView.as_view(), name='doctor-queue-info'),
    path('doctor/dashboard/stats/', DoctorDashboardStatsView.as_view(), name='doctor-dashboard-stats'),
    path('patient/dashboard/stats/', PatientDashboardStatsView.as_view(), name='patient-dashboard-stats'),
    path('patient/dashboard/appointments/', PatientUpcomingAppointmentsView.as_view(), name='patient-upcoming-appointments'),
    path('patient/dashboard/appointments/recent/', PatientRecentAppointmentsView.as_view(), name='patient-recent-appointments'),
]