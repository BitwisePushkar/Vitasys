from django.urls import path
from . import views

urlpatterns = [
    path('signup/', views.SignupView.as_view(), name='signup'),
    path('verify-signup-otp/', views.VerifySignupOTPView.as_view(), name='verify_signup_otp'),
    path('resend-signup-otp/', views.ResendSignupOTPView.as_view(), name='resend_signup_otp'),
    path('complete-doctor-profile/', views.DoctorDetailsView.as_view(), name='complete_doctor_profile'),
    path('complete-patient-profile/', views.PatientDetailsView.as_view(), name='complete_patient_profile'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('forgot-password/', views.ForgotPasswordView.as_view(), name='forgot_password'),
    path('verify-password-reset-otp/', views.VerifyPasswordResetOTPView.as_view(), name='verify_password_reset_otp'),
    path('reset-password/', views.ResetPasswordView.as_view(), name='reset_password'),
    path('resend-password-reset-otp/', views.ResendPasswordResetOTPView.as_view(), name='resend_password_reset_otp'),
    path('refresh-token/', views.RefreshTokenView.as_view(), name='refresh_token'),
    path('verify-token/', views.VerifyTokenView.as_view(), name='verify_token'),
    path('logout/', views.LogoutView.as_view(), name='logout'),]