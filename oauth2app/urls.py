from django.urls import path
from .views import (
    user_registration,
    user_login,
    generate_token_endpoint,
    update_access_token_from_refresh,
    calling_dummy_api_in_another_project,
    calling_3rd_party,
)

urlpatterns = [
    path('user/registration/', user_registration, name='user-registration'),
    path('user/login/', user_login, name='user-login'),
    path('api/generate-token/', generate_token_endpoint, name='generate-token-endpoint'),
    path('api/update-access-token/', update_access_token_from_refresh, name='update-access-token'),
    path('api/call-dummy-api/', calling_dummy_api_in_another_project, name='call-dummy-api'),
    path('api/call-3rd-party/', calling_3rd_party, name='call-3rd-party'),
]
