import json
import requests
import uuid
from django.http import JsonResponse
from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.views.decorators.http import require_POST
from oauthlib.common import generate_token
from rest_framework_simplejwt.tokens import RefreshToken as RT
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status, permissions
from oauth2_provider.models import Application, AccessToken, RefreshToken, IDToken
from oauth2_provider.decorators import protected_resource
from django.conf import settings
from django.utils import timezone
from .utils import generate_base64_string
from .token_utils import generate_access_token, generate_refresh_token

@csrf_exempt
@require_POST
def user_registration(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')

        if not all([username, password, email]):
            raise ValueError('Incomplete data. Please provide username, password, and email.')

        if User.objects.filter(username=username).exists():
            raise IntegrityError('User already exists.')
        
        if User.objects.filter(email=email).exists():
            raise IntegrityError('Email already exists.')

        user = User.objects.create_user(username=username, password=password, email=email)

        return JsonResponse({'message': 'User registered successfully.'}, status=status.HTTP_201_CREATED)
    
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data.'}, status=status.HTTP_400_BAD_REQUEST)

    except IntegrityError as e:
        return JsonResponse({'error': str(e)}, status=status.HTTP_409_CONFLICT)

    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return JsonResponse({'error': f'Error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@csrf_exempt
@require_POST
def user_login(request):
    try:
        # Load JSON data from the request body
        data = json.loads(request.body.decode('utf-8'))
        username = data.get('username')

        # Check if the username exists
        if not User.objects.filter(username=username).exists():
            return JsonResponse({'error': 'User does not exist.'}, status=status.HTTP_404_NOT_FOUND)

        password = data.get('password')
        user = authenticate(request, username=username, password=password)

        # Check if authentication failed
        if user is None:
            return JsonResponse({'error': 'Login unsuccessful. Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)

        # Delete existing OAuth tokens
        AccessToken.objects.filter(user=user).delete()
        RefreshToken.objects.filter(user=user).delete()

        # Generate new OAuth tokens
        refresh = RT.for_user(user)
        headers = {'Authorization': f'Bearer {str(refresh.access_token)}'}
        create_oauth_refresh_token = requests.post("http://127.0.0.1:8001/api/generate-token/", headers=headers)

        # Return the response with new tokens
        return JsonResponse({
            "jwt_refresh_token": str(refresh),
            "jwt_access_token": str(refresh.access_token),
            "oauth_refresh_token": (create_oauth_refresh_token.json())['refresh_token'],
            "oauth_access_token": (create_oauth_refresh_token.json())['access_token'],
        })

    except json.JSONDecodeError:
        # Handle JSON decoding error
        return JsonResponse({'error': 'Invalid JSON data.'}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        # Handle other exceptions
        return JsonResponse({'error': f'Error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def generate_token_endpoint(request):
    username = request.user.username
    password = request.user.password
    client_id = settings.CLIENT_ID

    try:
        application = Application.objects.get(client_id=client_id)
    except Application.DoesNotExist:
        return JsonResponse({'error': 'Invalid client credentials'}, status=401)

    user = User.objects.get(username=username)
    if user.password == password:
        if user is not None:
            AccessToken.objects.filter(user=user, application=application).delete() # deleting if I am calling the current api separately, otherwise this line is not required
            RefreshToken.objects.filter(user=user, application=application).delete() # deleting if I am calling the current api separately, otherwise this line is not required

            expires = timezone.now() + timezone.timedelta(seconds=1)
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

            refresh_token = RefreshToken.objects.create(
                user=user,
                application=application,
                token=generate_token(),
                access_token=access_token,
            )

            response_data = {
                'access_token': access_token.token,
                'token_type': 'Bearer',
                'expires_in': (expires - timezone.now()).total_seconds(),
                'refresh_token': refresh_token.token,
            }

            return JsonResponse(response_data)
        else:
            return JsonResponse({'error': 'Invalid user credentials'}, status=401)


'''
This particular API has to be called to obtain the new oAuth access token from
the existing oauth refresh token, there's no need for this because we'll be 
calling this API internally, for testing purpose we can hit it with JWT access token.
'''
@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def update_access_token_from_refresh(request):
    try:
        # Retrieve the refresh token from the JWT access token
        refresh_token = RefreshToken.objects.get(user_id=request.user.id).token
        
        # Check if refresh token is present
        if not refresh_token:
            raise Exception("Refresh token not found")

        # Query the OAuth access token object from the OAuth refresh token
        access_token_obj = AccessToken.objects.get(pk=(RefreshToken.objects.get(token=refresh_token)).access_token_id)

        # Create a new OAuth access token
        new_access_token = generate_base64_string()

        # Set the expiration time for the new OAuth access token
        expires_in = timezone.now() + timezone.timedelta(seconds=settings.OAUTH2_PROVIDER['ACCESS_TOKEN_EXPIRE_SECONDS'])
        access_token_obj.token = new_access_token
        expires_iso = expires_in.isoformat()

        # Assign the new OAuth access token and save it
        access_token_obj.expires = expires_iso
        access_token_obj.save()

        return JsonResponse(
            {
                "status": "Success",
                "message": "New access token has been issued",
                "token": new_access_token
            }
        )

    except Exception as ex:
        return JsonResponse({
            "status": "failed",
            "message": str(ex)
        })

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def calling_dummy_api_in_another_project(request):
    try:
        # Extract data from the request body
        data = json.loads(request.body)
        url = data.get('url')
        num = data.get('data')
        
        # Get the OAuth access token
        access_token = AccessToken.objects.get(user_id=request.user.id).token

        # Check if the access token has expired
        if timezone.now() > AccessToken.objects.get(user_id=request.user.id).expires:
            # Prepare headers for the request with the expired access token
            headers = {
                'Authorization': f'Bearer {str(request.auth)}',
                'Content-Type': 'application/json'
            }

            # Call the API to update the access token
            calling_update_access_token_api = requests.post("http://127.0.0.1:8001/api/update-access-token/", headers=headers)
            
            # Get the newly generated access token
            newly_generated_access_token = calling_update_access_token_api.json()['token']

            # Prepare headers for the request with the new access token
            headers = {
                'Authorization': f'Bearer {newly_generated_access_token}',
                'Content-Type': 'application/json'
            }

            # Prepare the data for the request
            post_data = {'data': num}
            post_data_json = json.dumps(post_data)

            # Make the API call to the 3rd party endpoint
            calling_inbuilt_3rdparty_api = requests.post("http://127.0.0.1:8001/api/call-3rd-party/", headers=headers, data=post_data_json)

            # Return the response from the 3rd party API
            return JsonResponse(calling_inbuilt_3rdparty_api.json())

        else:
            # Prepare headers for the request with the existing access token
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }

            # Prepare the data for the request
            post_data = {'data': num}
            post_data_json = json.dumps(post_data)

            # Make the API call to the 3rd party endpoint
            calling_inbuilt_3rdparty_api = requests.post("http://127.0.0.1:8001/api/call-3rd-party/", headers=headers, data=post_data_json)

            # Return the response from the 3rd party API
            return JsonResponse(calling_inbuilt_3rdparty_api.json())

    except Exception as ex:
        # Handle exceptions and return an error response
        return JsonResponse({
            "status": "failed",
            "message": str(ex)
        })


@csrf_exempt
@protected_resource()
def calling_3rd_party(request):
    try:
        # Extract data from the request body
        data = json.loads(request.body)
        post_data_json = json.dumps(data)

        # Make a POST request to the 3rd party API
        calling_project2 = requests.post("http://127.0.0.1:8000/api/dummyApi/", data=post_data_json)

        # Get the response data from the 3rd party API
        response_data = calling_project2.json()

        # Prepare and return the JsonResponse with the response data
        return JsonResponse(
            {
                "status": response_data['status'],
                "message": response_data['message']
            }
        )

    except Exception as ex:
        # Handle exceptions and return an error response
        return JsonResponse({
            "status": "failed",
            "message": str(ex)
        })
