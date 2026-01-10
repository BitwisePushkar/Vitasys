from rest_framework.throttling import AnonRateThrottle, UserRateThrottle

class AppointmentBookingThrottle(UserRateThrottle):
    scope = 'appointment_booking'

class AppointmentActionsThrottle(UserRateThrottle):
    scope = 'appointment_actions'

class DashboardThrottle(UserRateThrottle):
    scope = 'dashboard'