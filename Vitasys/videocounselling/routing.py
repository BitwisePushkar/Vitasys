from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/video/(?P<appointment_id>\d+)/$', consumers.VideoCallConsumer.as_asgi()),
]