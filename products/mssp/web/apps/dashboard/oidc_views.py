"""
OIDC Views for MSSP Dashboard

Handles the OIDC authentication callback from Logto.
"""

import logging
import requests
from django.conf import settings
from django.contrib.auth import get_user_model, login as auth_login
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseBadRequest
from django.shortcuts import redirect
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

logger = logging.getLogger(__name__)
User = get_user_model()


class LogtoCallbackView(View):
    """
    Handles the OIDC callback from Logto after user authentication.

    Flow:
    1. Logto redirects user back with authorization code
    2. We exchange the code for access/id tokens
    3. We decode the tokens to get user info
    4. We create/update the Django user
    5. We log the user in
    """

    def get(self, request):
        """Handle the callback from Logto."""
        # Get the authorization code
        code = request.GET.get('code')
        error = request.GET.get('error')
        error_description = request.GET.get('error_description', '')

        if error:
            logger.error(f"OIDC error: {error} - {error_description}")
            return redirect('/login/?error=' + error)

        if not code:
            logger.error("No authorization code in callback")
            return HttpResponseBadRequest("Missing authorization code")

        # Get Logto configuration
        logto_endpoint = getattr(settings, 'LOGTO_ENDPOINT', '')
        client_id = getattr(settings, 'LOGTO_APP_ID', '')
        client_secret = getattr(settings, 'LOGTO_APP_SECRET', '')

        if not all([logto_endpoint, client_id]):
            logger.error("Logto not configured properly")
            return redirect('/login/?error=configuration_error')

        # Build redirect URI (must match what was sent in auth request)
        redirect_uri = request.build_absolute_uri('/oidc/callback/')

        # Exchange authorization code for tokens
        try:
            token_response = requests.post(
                f"{logto_endpoint}/oidc/token",
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': redirect_uri,
                    'client_id': client_id,
                    'client_secret': client_secret or '',
                },
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                timeout=30
            )

            if token_response.status_code != 200:
                logger.error(f"Token exchange failed: {token_response.status_code} - {token_response.text}")
                return redirect('/login/?error=token_exchange_failed')

            tokens = token_response.json()

        except requests.RequestException as e:
            logger.error(f"Token exchange request failed: {e}")
            return redirect('/login/?error=token_exchange_failed')

        access_token = tokens.get('access_token')
        id_token = tokens.get('id_token')

        if not access_token:
            logger.error("No access token in response")
            return redirect('/login/?error=no_access_token')

        # Get user info from Logto
        try:
            userinfo_response = requests.get(
                f"{logto_endpoint}/oidc/me",
                headers={
                    'Authorization': f'Bearer {access_token}',
                },
                timeout=30
            )

            if userinfo_response.status_code != 200:
                logger.error(f"Userinfo request failed: {userinfo_response.status_code}")
                return redirect('/login/?error=userinfo_failed')

            userinfo = userinfo_response.json()

        except requests.RequestException as e:
            logger.error(f"Userinfo request failed: {e}")
            return redirect('/login/?error=userinfo_failed')

        # Extract user information
        sub = userinfo.get('sub')  # Logto user ID
        email = userinfo.get('email', '')
        name = userinfo.get('name', '')
        username = userinfo.get('username') or email or sub
        roles = userinfo.get('roles', [])

        if not sub:
            logger.error("No subject in userinfo")
            return redirect('/login/?error=no_subject')

        # Create or update Django user
        try:
            user, created = User.objects.get_or_create(
                username=username[:150],  # Django username max length
                defaults={
                    'email': email,
                    'first_name': name.split()[0] if name else '',
                    'last_name': ' '.join(name.split()[1:]) if name and len(name.split()) > 1 else '',
                    'is_active': True,
                }
            )

            if not created:
                # Update existing user
                user.email = email
                if name:
                    user.first_name = name.split()[0]
                    user.last_name = ' '.join(name.split()[1:]) if len(name.split()) > 1 else ''
                user.save()

            # Store Logto ID and roles in session
            request.session['logto_sub'] = sub
            request.session['logto_roles'] = roles
            request.session['access_token'] = access_token
            if id_token:
                request.session['id_token'] = id_token

            # Set staff/superuser based on roles
            if 'admin' in roles:
                user.is_staff = True
                user.is_superuser = True
                user.save()
            elif 'soc_analyst' in roles:
                user.is_staff = True
                user.save()

            # Log the user in
            auth_login(request, user, backend='shared.iam.backends.LogtoAuthenticationBackend')

            logger.info(f"User {username} logged in via Logto with roles: {roles}")

            # Redirect to dashboard
            next_url = request.GET.get('state', '').split('next=')[-1]
            if next_url and next_url.startswith('/'):
                return HttpResponseRedirect(next_url)

            return redirect('/mssp/')

        except Exception as e:
            logger.exception(f"Failed to create/update user: {e}")
            return redirect('/login/?error=user_creation_failed')


@method_decorator(csrf_exempt, name='dispatch')
class LogtoLogoutCallbackView(View):
    """
    Handles the logout callback from Logto (optional back-channel logout).
    """

    def post(self, request):
        """Handle back-channel logout notification."""
        # This is called by Logto when a user logs out from another app
        # We should invalidate their session here

        # For now, just acknowledge the request
        return HttpResponse('OK', content_type='text/plain')
