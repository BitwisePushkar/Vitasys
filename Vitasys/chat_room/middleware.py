from channels.middleware import BaseMiddleware
from django.core.cache import cache
from django.utils import timezone

class WebSocketRateLimitMiddleware(BaseMiddleware):
    async def __call__(self, scope, receive, send):
        if scope["type"] == "websocket":
            user = scope.get("user")
            
            if user and user.is_authenticated:
                cache_key = f"ws_limit_{user.id}"
                attempts = cache.get(cache_key, 0)
                
                if attempts >= 10:
                    await send({
                        "type": "websocket.close",
                        "code": 4029,
                    })
                    return
                
                cache.set(cache_key, attempts + 1, 60)
        
        return await super().__call__(scope, receive, send)
