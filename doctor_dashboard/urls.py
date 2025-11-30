from django.urls import path
from .views import (
    DoctorDashboardProfileView,
    DoctorDashboardStatsView,
    DoctorTodayAppointmentsView,
    DoctorUpcomingAppointmentsView,
    DoctorRecentReviewsView,
    DoctorWeeklyStatsView,DoctorCompleteProfileView
)

urlpatterns = [
    path('profile/', DoctorDashboardProfileView.as_view(), name='doctor-dashboard-profile'),
    path('stats/', DoctorDashboardStatsView.as_view(), name='doctor-dashboard-stats'),
    path('appointments/today/', DoctorTodayAppointmentsView.as_view(), name='doctor-today-appointments'),
    path('appointments/upcoming/', DoctorUpcomingAppointmentsView.as_view(), name='doctor-upcoming-appointments'),
    path('reviews/recent/', DoctorRecentReviewsView.as_view(), name='doctor-recent-reviews'),
    path('stats/weekly/', DoctorWeeklyStatsView.as_view(), name='doctor-weekly-stats'),
    path('profile/complete/', DoctorCompleteProfileView.as_view(), name='doctor-complete-profile'), 
]