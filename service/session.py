"""
service.auth - provides the business logic for implementing application authentication when
the various `lm auth <subcmd>` sub-commands are called.
"""
# Imports
# Standard Library
import base64
import datetime as dt
import json
import logging
import threading
from urllib.parse import urlparse, parse_qs
import webbrowser

# Third Party
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt
from jwt import (
    InvalidIssuerError,
    MissingRequiredClaimError,
    PyJWKClient,
    PyJWKClientError
)
import keyring
from keyring.errors import PasswordDeleteError
import requests
from rich import print

# Custom
from shared.auth import (
    AuthServerResponse,
    AccessToken,
    create_server,
    CurrentUserClaims,
    PKCECodes,
    YouVersionPlatformJWKS
)

# module logger
logger = logging.getLogger(__name__)


class AuthSession:
    """Stores the user's current authentication session information, and provides an easy reference for the URLs and tokens required to complete the PKCE authorization flow for this platform.

    Attributes:
        _client_id: The provided public Client ID for the application.
        _callback_url: The configured callback URL provided for the application.
        pkce: The codes used to perform authentication using the OAuth 2.0 PKCE flow. Created when AuthSession is initialized, no need to initialize directly. Don't change any of these members or the flow will no longer work.
        jwks: The JWKS URI and validation information needed to validate auth tokens in the final step of the flow. Unchanging initialization, may be configured dynamically later.
        granted_permissions: A set of permissions granted by the YouVersion platform API.
        authorization_code: The authorization code provided after the PKCE callbck step.
        token: The full access token retrieved after the PKCE flow completes.
        current_user: The parsed current user, will be populated after the PKCE authentication flow has completed and the AccessToken.id_token has been decoded and validated.
    Methods:

    """
    def __init__(self):
        # static, should never change with this app registration
        self._client_id: str = "CApjAnlXGBEMLVeGj8ibFMxNPSXDMSmGx4NXb6JDBjWNCepA"
        self._callback_url: str = "http://localhost:13333"

        # dynamically initialized, unchanging during runtime
        self.pkce: PKCECodes = PKCECodes()
        self.jwks: YouVersionPlatformJWKS = YouVersionPlatformJWKS()

        # initialized and used throughout the code as the PKCE flow proceeds
        self.granted_permissions: list[str] | list[None] = [None]
        self.authorization_code: str | None = None
        self.token: AccessToken | None = None
        self.current_user: CurrentUserClaims | None = None


    def authorize_url(self) -> str:
        return f"https://api.youversion.com/auth/authorize?response_type=code&client_id={self._client_id}&redirect_uri={self._callback_url}&scope=openid%20profile%20email&nonce={self.pkce.nonce}&state={self.pkce.state}&code_challenge={self.pkce.code_challenge}&code_challenge_method=S256&requested_permissions[]=highlights"


    def callback_url(self) -> str:
        return f"https://api.youversion.com/auth/callback?state={self.pkce.state}"


    def auth_token_request_url(self) -> str:
        return "https://api.youversion.com/auth/token"


    def auth_token_request_body(self) -> dict:
        return {
            "grant_type": "authorization_code",
            "code": self.authorization_code,
            "redirect_uri": self._callback_url,
            "client_id": self._client_id,
            "code_verifier": self.pkce.code_verifier
        }

    def refresh_token_request_body(self) -> dict:
        return {
            "grant_type": "refresh_token",
            "refresh_token": keyring.get_password("LivingMargins", ""),
            "client_id": self._client_id
        }

    def verify_auth_token(self, token: str) -> dict:
        try:
            jwk_client = PyJWKClient(self.jwks.uri)

            signing_key = jwk_client.get_signing_key_from_jwt(token)

            logger.info("Able to parse the token normally for user claims.")
        except PyJWKClientError as err:
            logger.warning("Unable to extract a 'kid' header from the JWT, trying manual process.")

            jwks = requests.get(self.jwks.uri).json()

            # they aren't returning a "kid" header
            jwks_key = [key for key in jwks['keys'] if key['kid'] == self.jwks.kid][0]

            # get public numbers
            n = int.from_bytes(base64.urlsafe_b64decode(jwks_key['n'] + '=' * (-len(jwks_key['n']) % 4)), 'big')  
            e = int.from_bytes(base64.urlsafe_b64decode(jwks_key['e'] + '=' * (-len(jwks_key['e']) % 4)), 'big')    

            public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())

            signing_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

        try:
            return jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                audience=self._client_id,
                issuer=self.jwks.iss
            )
        except InvalidIssuerError as err:
            logger.exception(err)
            logger.debug(f"Configured Issuer: {self.jwks.iss}")
        except MissingRequiredClaimError as err:
            logger.exception(err)
            logger.debug(f"Configured Audience: {self._client_id}")

        return {}

    def login(self):
        """Facilitates the PKCE procedure for OAuth 2.0 sign ins to the YouVersion application, to carry highlights to the CLI application.
        """
        server = create_server()

        logger.info("Starting up HTTP OAuth Callback Server")
        threading.Thread(
            target=server.serve_forever,
            daemon=True
        ).start()

        # PKCE Step 1, Authorize
        logger.debug(f"Opened initial web browser for end user interaction: {self.authorize_url()}")
        webbrowser.open(self.authorize_url())

        auth_event: AuthServerResponse = server.requests.get()
        logger.debug("Retrieved the auth event")

        if auth_event.state != self.pkce.state:
            raise AssertionError(f"Possible CSRF, state value recieved from server {auth_event.state} not original sent state ({self.pkce.state})")
        
        self.granted_permissions = auth_event.granted_permissions

        logger.info("Retrieved and validated scope and granted permissions")

        # terminate OAuth callback server
        server.shutdown()
        logger.info("Shut down the OAuth callback server")

        # PKCE Step 2, Callback
        resp = requests.get(self.callback_url(), allow_redirects=False)
        logger.info("Received callback redirected response")
        resp.raise_for_status()

        # parse the client-side redirect back to this location
        callback_location: str = resp.headers.get('location', '')
        query = parse_qs(urlparse(callback_location).query)

        callback_event = AuthServerResponse(
            state=query.get('state', [None])[0],
            granted_permissions=query.get('granted_permissions', [None]),
            code=query.get('code', [None])[0]
        )

        if callback_event.state != self.pkce.state:
            raise AssertionError(f"Possible CSRF, state value recieved from server {auth_event.state} not original sent state ({self.pkce.state})")

        self.authorization_code = callback_event.code
        logger.info("Parsed successfully the callback to receive the authorization code")

        # PKCE Step 3, access token request
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }

        logger.info("Sending the access token request now")

        access_resp = requests.post(
            url=self.auth_token_request_url(),
            data=self.auth_token_request_body(),
            headers=headers,
            allow_redirects=False
        )

        access_resp.raise_for_status()

        try:
            resp_json = access_resp.json()

            logger.info("Retrieved the JSON response with access token information")

            keyring.set_password("LivingMargins", "refresh_token", resp_json.get("refresh_token", ""))

            logger.debug("Saved the refresh token!")

            self.token = AccessToken(
                access_token=resp_json.get("access_token", ""),
                token_type=resp_json.get("token_type", "Bearer"),
                expires_at=dt.datetime.now() + dt.timedelta(seconds=int(resp_json.get("expires_in", "3599"))),
                scope=resp_json.get("scope", "")
            )

            logger.info("Fully parsed the access token information")

            id_token_decoded = self.verify_auth_token(resp_json.get("id_token", ""))

            self.current_user = CurrentUserClaims(
                yvp_id=id_token_decoded.get('yvp_id', ''),
                subject=id_token_decoded.get('sub', ''),
                email=id_token_decoded.get('email', ''),
                name=id_token_decoded.get('name', ''),
                profile_picture_url=id_token_decoded.get('profile_picture', ''),
                issued_at=dt.datetime.fromtimestamp(int(id_token_decoded.get('iat', ''))),
                expiration=dt.datetime.fromtimestamp(int(id_token_decoded.get('exp', '')))
            )

            # write user profile to keyring
            # keyring.set_password("LivingMargins", "user", base64.b64encode(json.dumps(self.current_user.to_dict).encode('utf-8')).decode('utf-8'))
        except json.JSONDecodeError as err:
            logger.error(f"Status: {access_resp.status_code}, text: {access_resp.text}")
            logger.exception(err)

    def logout(self):
        # clear refresh token completely out of memory, forces re-auth during login
        try:
            keyring.delete_password("LivingMargins", "refresh_token")
            keyring.delete_password("LivingMargins", "user")
        except PasswordDeleteError as err:
            logger.exception(err)


    def refresh(self):
        # attempt to get refresh token out of memory
        refresh_token = keyring.get_password("LivingMargins", "refresh_token")

        if not refresh_token:
            print("[red]Not Signed In[/red]: Please use `lm-cli auth login` to sign in to YouVersion.")
            return  # early termination

        # attempt to get current auth token and pass to function
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }

        refresh_resp = requests.post(
            url=self.auth_token_request_url(),
            data=self.refresh_token_request_body(),
            headers=headers,
            allow_redirects=False
        )

        refresh_resp.raise_for_status()

        try:
            resp_json = refresh_resp.json()

            keyring.set_password("LivingMargins", "refresh_token", resp_json.get('refresh_token'))

            self.token = AccessToken(
                access_token=resp_json.get('access_token'),
                token_type=resp_json.get('token_type'),
                expires_at=dt.datetime.now() + dt.timedelta(seconds=int(resp_json.get('expires_in'))),
                scope=resp_json.get('scope')
            )

            user_encoded = keyring.get_password("LivingMargins", "user")
            
            if user_encoded:
                self.current_user = CurrentUserClaims(**json.loads(base64.b64decode(user_encoded).decode('utf-8')))

        except json.JSONDecodeError as err:
            logger.exception(err)
            return
