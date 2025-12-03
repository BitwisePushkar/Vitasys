from django.urls import path
from .views import (
    DoctorPatientsListView,
    CreatePrescriptionView,
    DoctorPrescriptionsListView,
    PatientPrescriptionsListView,
    PatientPrescriptionsByDoctorView
)

urlpatterns = [
    path('doctor/patients/', DoctorPatientsListView.as_view(), name='doctor-patients-list'),
    path('doctor/create/', CreatePrescriptionView.as_view(), name='create-prescription'),
    path('doctor/list/', DoctorPrescriptionsListView.as_view(), name='doctor-prescriptions-list'),
    path('patient/list/', PatientPrescriptionsListView.as_view(), name='patient-prescriptions-list'),
    path('patient/doctor/<int:doctor_id>/', PatientPrescriptionsByDoctorView.as_view(), name='patient-prescriptions-by-doctor'),
]