from django.urls import path
from .views import (
    PatientChatViewSet,
    DoctorChatViewSet,
    ChatRoomViewSet,
)

urlpatterns = [
    path(
        'patient/doctors/',
        PatientChatViewSet.as_view({'get': 'list'}),
        name='patient-chats'
    ),

    path(
        'doctor/patients/',
        DoctorChatViewSet.as_view({'get': 'list_patients'}),
        name='doctor-patient-chats'
    ),

    path(
        'doctor/doctors/',
        DoctorChatViewSet.as_view({'get': 'list_doctors'}),
        name='doctor-doctor-chats'
    ),

    path(
        'doctor/search/',
        DoctorChatViewSet.as_view({'get': 'search_doctors'}),
        name='doctor-search'
    ),
    path(
        'doctor/connection/send/',
        DoctorChatViewSet.as_view({'post': 'send_connection_request'}),
        name='doctor-send-request'
    ),

    path(
        'doctor/connection/pending/',
        DoctorChatViewSet.as_view({'get': 'list_pending_requests'}),
        name='doctor-pending-requests'
    ),

    path(
        'doctor/connection/<int:pk>/accept/',
        DoctorChatViewSet.as_view({'post': 'accept_connection'}),
        name='doctor-accept'
    ),

    path(
        'doctor/connection/<int:pk>/reject/',
        DoctorChatViewSet.as_view({'post': 'reject_connection'}),
        name='doctor-reject'
    ),

    path(
        'room/<int:pk>/',
        ChatRoomViewSet.as_view({'get': 'retrieve'}),
        name='chat-room-detail'
    ),

    path(
        'room/<int:pk>/send/',
        ChatRoomViewSet.as_view({'post': 'send_message'}),
        name='chat-send-message'
    ),

    path(
        'room/<int:pk>/read/',
        ChatRoomViewSet.as_view({'post': 'mark_as_read'}),
        name='chat-mark-read'
    ),
]
