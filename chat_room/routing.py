from django.urls import path
from .consumers import ChatConsumer
from appointments.consumers import QueueConsumer 

websocket_urlpatterns = [
    path("ws/chat/<int:room_id>/", ChatConsumer.as_asgi()),

    path("ws/queue/<int:doctor_id>/", QueueConsumer.as_asgi()),
]
