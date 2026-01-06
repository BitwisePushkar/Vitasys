from django.urls import path
from users import views

urlpatterns = [
    path('signup/',views.SignupView.as_view(),name='signup'),
    path('verify-signup/',views.VerifySignupOTPView.as_view(),name='verify_signup_otp'),
    path('resend-signup/',views.ResendSignupOTPView.as_view(),name='resend_signup_otp'),
    path('doctor-profile/',  views.DoctorDetailsView.as_view(),  name='complete_doctor_profile'),
    path('patient-profile/', views.PatientDetailsView.as_view(), name='complete_patient_profile'),
    path('login/',views.LoginView.as_view(),name='login'),
    path('refresh-token/',views.RefreshTokenView.as_view(),name='refresh_token'),
    path('me/',views.MeView.as_view(),name='me'),
    path('logout/',views.LogoutView.as_view(),name='logout'),
    path('forgot-password/',views.ForgotPasswordView.as_view(),name='forgot_password'),
    path('verify-password-reset-otp/',views.VerifyPasswordResetOTPView.as_view(),name='verify_password_reset_otp'),
    path('reset-password/',views.ResetPasswordView.as_view(),name='reset_password'),
    path('resend-password-reset-otp/',views.ResendPasswordResetOTPView.as_view(),name='resend_password_reset_otp'),
    path('deactivate-account/',views.DeactivateAccountView.as_view(),name='deactivate_account'),
    path('reactivate-account/',views.ReactivateAccountView.as_view(),name='reactivate_account'),
    path('delete-account/',views.DeleteAccountView.as_view(),name='delete_account'),
]