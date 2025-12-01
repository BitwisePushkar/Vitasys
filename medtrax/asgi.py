import os
import django
from urllib.parse import parse_qs

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "medtrax.settings")
django.setup()
from chat_room.middleware import WebSocketRateLimitMiddleware
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from rest_framework_simplejwt.tokens import AccessToken

from Authapi.models import CustomUser
import chat_room.routing
import videocounselling.routing
import appointments.routing


class JWTAuthMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        query_string = scope.get("query_string", b"").decode()
        params = parse_qs(query_string)
        token = params.get("token", [None])[0]

        if not token:
            headers = dict(scope.get("headers", []))
            cookie_header = headers.get(b"cookie", b"").decode()
            cookies = {}
            for part in cookie_header.split(";"):
                if "=" in part:
                    key, val = part.strip().split("=", 1)
                    cookies[key] = val
            token = cookies.get("access_token")

        if token:
            try:
                access_token = AccessToken(token)
                user = await self.get_user(access_token["user_id"])
                scope["user"] = user
                print(f"WebSocket authenticated user: {user.email if user.is_authenticated else 'Anonymous'}")
            except Exception as e:
                print(f"Invalid or expired token: {e}")
                scope["user"] = AnonymousUser()
        else:
            print(" No JWT token found in cookies or query string")
            scope["user"] = AnonymousUser()

        return await self.app(scope, receive, send)

    @database_sync_to_async
    def get_user(self, user_id):
        try:
            return CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            return AnonymousUser()

django_asgi_app = get_asgi_application()

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": WebSocketRateLimitMiddleware(AllowedHostsOriginValidator(
        JWTAuthMiddleware(
            URLRouter(
                chat_room.routing.websocket_urlpatterns +
                videocounselling.routing.websocket_urlpatterns +
                appointments.routing.websocket_urlpatterns
            )
        )
    )
    ),
})
