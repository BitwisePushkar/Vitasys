from django.contrib import admin
from django.urls import path, include 
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import (SpectacularAPIView,SpectacularSwaggerView,SpectacularRedocView,)
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.http import JsonResponse

@api_view(['GET'])
def root_redirect(request):
    return Response({'message': 'Welcome to Vitesys API',})
def health_check(request):
    return JsonResponse({'status': 'ok'})

urlpatterns = [
    path('', root_redirect),
    path('health/', health_check, name='health-check'),
    path('admin/', admin.site.urls),
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    path('auth/', include('users.urls')),
    path('chat/', include('chat.urls')),
    path('appointment/', include('appointment.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)