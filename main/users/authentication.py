from rest_framework_simplejwt.authentication import JWTAuthentication as BaseJWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework import exceptions
from django.utils.translation import gettext_lazy as _
from django.core.cache import cache
from django.utils import timezone
import math

def blocklist_token(token) -> None:
    jti = token.get('jti')
    exp = token.get('exp')        
    now = timezone.now().timestamp()
    remaining = math.ceil(exp - now)

    if jti and remaining > 0:
        cache.set(f"blocklist_jti:{jti}", "1", timeout=remaining)

def is_token_blocklisted(token) -> bool:
    jti = token.get('jti')
    if not jti:
        return False
    return cache.get(f"blocklist_jti:{jti}") is not None

class JWTAuthentication(BaseJWTAuthentication):
    def authenticate(self, request):
        try:
            result = super().authenticate(request)
        except TokenError as e:
            raise exceptions.AuthenticationFailed(str(e))
        if result is None:
            return None
        user, token = result

        if is_token_blocklisted(token):
            raise exceptions.AuthenticationFailed(_('This token has been revoked. Please login again.'),
                                                  code='token_revoked',)

        if not user.is_active:
            raise exceptions.AuthenticationFailed(_('This account has been deactivated. Please contact support or reactivate your account.'),
                                                  code='user_inactive',)
        return user, token