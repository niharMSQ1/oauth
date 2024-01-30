from django.contrib import admin
from django.urls import path,include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include("oauth2app.urls")),
    path('o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
]