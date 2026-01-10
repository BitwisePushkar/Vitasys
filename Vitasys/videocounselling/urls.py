from django.urls import path
from .views import InitiateVideoCall, JoinVideoCall, EndVideoCall, VideoCallStatus

urlpatterns = [
    path('<int:appointment_id>/initiate/', InitiateVideoCall.as_view(), name='initiate-video-call'),
    path('<int:appointment_id>/join/', JoinVideoCall.as_view(), name='join-video-call'),
    path('<int:appointment_id>/end/', EndVideoCall.as_view(), name='end-video-call'),
    path('<int:appointment_id>/status/', VideoCallStatus.as_view(), name='video-call-status'),
]