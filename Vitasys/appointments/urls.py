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
    DoctorQueueInfoView,
    DoctorCompleteAppointmentView,
    CancelAppointmentView
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
    
    # Lifecycle endpoints
    path('doctor/<int:appointment_id>/complete/', DoctorCompleteAppointmentView.as_view(), name='doctor-complete-appointment'),
    path('appointment/<int:appointment_id>/cancel/', CancelAppointmentView.as_view(), name='cancel-appointment'),
]