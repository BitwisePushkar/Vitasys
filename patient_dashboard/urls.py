from django.urls import path
from .views import PatientDashboardView,PatientUpcomingAppointmentsView, PatientRecentAppointmentsView,PatientDashboardStatsView,PatientCompleteProfileView

urlpatterns = [
    path('profile/', PatientDashboardView.as_view(), name='patient-dashboard-profile'),
    path('appointments/', PatientUpcomingAppointmentsView.as_view(), name='patient-upcoming-appointments'),
    path('appointments/recent/', PatientRecentAppointmentsView.as_view(), name='patient-recent-appointments'),
    path('stats/', PatientDashboardStatsView.as_view(), name='patient-dashboard-stats'),
    path('profile/complete/', PatientCompleteProfileView.as_view(), name='patient-complete-profile'),
]