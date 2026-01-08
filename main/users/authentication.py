from rest_framework_simplejwt.authentication import JWTAuthentication as BaseJWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework import exceptions
from django.utils.translation import gettext_lazy as _

class JWTAuthentication(BaseJWTAuthentication):
    def authenticate(self, request):
        try:
            result = super().authenticate(request)
        except TokenError as e:
            raise exceptions.AuthenticationFailed(str(e))
        if result is None:
            return None
        user, token = result
        if not user.is_active:
            raise exceptions.AuthenticationFailed(_('This account has been deactivated. Please contact support or reactivate your account.'),
                                                  code='user_inactive',)
        return user, token