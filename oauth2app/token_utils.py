import uuid
from django.utils import timezone
from oauthlib.common import generate_token
from oauth2_provider.models import AccessToken, RefreshToken, IDToken
from django.conf import settings

def generate_access_token(user, application):
    expires = timezone.now() + timezone.timedelta(seconds=settings.OAUTH2_PROVIDER['ACCESS_TOKEN_EXPIRE_SECONDS'])
    expires_iso = expires.isoformat()

    new_uuid = uuid.uuid4()
    id_token = IDToken.objects.create(jti=new_uuid, expires=expires)

    access_token = AccessToken.objects.create(
        user=user,
        application=application,
        token=generate_token(),
        expires=expires_iso,
        id_token=id_token,
    )

    return access_token

def generate_refresh_token(user, application, access_token):
    refresh_token = RefreshToken.objects.create(
        user=user,
        application=application,
        token=generate_token(),
        access_token=access_token,
    )

    return refresh_token
