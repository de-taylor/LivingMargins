# Imports
# Standard Library
import base64
from dataclasses import dataclass
import datetime as dt
from http.server import BaseHTTPRequestHandler, HTTPServer
import hashlib
import logging
import queue
import random
import secrets
from typing import Annotated
from urllib.parse import urlparse, parse_qs
import uuid

# Third Party
from pydantic import BaseModel

logger = logging.getLogger(__name__)

@dataclass
class AuthServerResponse:
    """AuthServerResponse is a Pydantic model used to codify the YouVersion authorization server's response during the PKCE authorization flow.
    """
    state: Annotated[str | None, "The original PKCE state value, used for CSRF validation."]
    granted_permissions: Annotated[list[str] | list[None], "The list of granted permissions, if any."]
    code: Annotated[str | None, "The authorization code we can use to exchange for tokens."]

# Create server class to actually launch server
class AuthFlowServer(HTTPServer):
    def __init__(self, address, handler):
        super().__init__(address, handler)

        self.requests = queue.Queue()

# Create handler for localhost redirect
class AuthFlowHandler(BaseHTTPRequestHandler):

    # handle the basic GET request
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)

        if self.server.requests.qsize() == 0:  # type: ignore
            # respond to browser
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"Authentication successfully initiated, you may now close this browser window.")

        self.server.requests.put(AuthServerResponse(  # type: ignore
            state=query.get('state', [None])[0],
            granted_permissions=query.get('granted_permissions', [None]),
            code=query.get('code', [None])[0]
        ))

def create_server(port=13333):
    # start up the server
    server = AuthFlowServer(("localhost", port), AuthFlowHandler)

    logger.debug(f"Listening for callback on port {port}")

    return server

class PKCECodes:
    """Generates and stores the values required for OAuth 2.0 with Proof Key for Code Exchange (PKCE).

    This should only be done once per authentication attempt, and this object should NOT be recycled during the OAuth 2.0 PKCE authorization flow, or else it invalidates the flow.

    Attributes:
        code_verifier: A URL-safe token generated for the PKCE process.
        code_challenge: A Base64-encoded bytes object representing the hashed code verifier.
        state: Used to make the initial authorization request to YouVersion, and used for ensuring that CSRF has not taken place during the request flow.
        nonce: Used to make the initial authorization request to YouVersion, allowing LivingMargins to use part of the YouVersion profile.
    """
    def __init__(self):
        """__init__ automatically instantiates the PKCE components when an object is instantiated.

        This object should only be created as part of the init for AuthSession.
        """
        self.code_verifier: str = self._create_code_verifier()
        self.code_challenge: str | None = self._create_code_challenge()
        self.state: str = secrets.token_urlsafe(random.randint(21, 33))
        self.nonce: str = str(uuid.uuid4())


    def _create_code_verifier(self) -> str:
        """_create_code_verifier generates the code verified used both the create the code challenge, and in the final /auth/token request to prove that this client should
        use the authorization code passed back in step 2.

        Returns:
            str: The stripped and decoded string that the YouVersion Platform wants as the code_verifier.
        """
        _token_bytes = secrets.token_bytes(64)
        _encoded_bytes = base64.urlsafe_b64encode(_token_bytes)
        _stripped_decoded_bytes = _encoded_bytes.rstrip(b"=").decode("utf-8")

        return _stripped_decoded_bytes


    def _create_code_challenge(self):
        """_create_code_challenge is a helper function that implements the more complex logic to encrypt and encode the `self.code_verifier` in the first part of the PKCE auth flow.

        Returns:
            str: The encrypted, stripped, and decoded challenge sent in the first step of the PKCE authorization flow.
        """
        logger.debug(f"Verifier used: {self.code_verifier}")
        # SHA256 encrypted, Base64 encoded
        return base64.urlsafe_b64encode(
            hashlib
            .sha256(self.code_verifier.encode('utf-8'))
            .digest()
        ).rstrip(b"=").decode("utf-8")


class AccessToken(BaseModel):
    access_token: Annotated[str, "The active token that can be used to make API calls."]
    token_type: Annotated[str, "The type of token, usually Bearer"]
    expires_at: Annotated[dt.datetime, "When the authentication token expires, about an hour after the token is issued, usually."]
    scope: Annotated[str, "The list of granted scopes for the user."]


@dataclass
class CurrentUserClaims:
    yvp_id: Annotated[str, "The YouVersion Platform ID for the user, stable and unique, good primary key for the user."]
    subject: Annotated[str, "The subject, contains the user's YVP unique ID"]
    email: Annotated[str, "The user's currently configured email address"]
    name: Annotated[str, "The user's currently configured full name."]
    profile_picture_url: Annotated[str, "The URL to the user's current profile picture."]
    issued_at: Annotated[dt.datetime, "The issued-at datetime, derived from a UNIX timestamp."]
    expiration: Annotated[dt.datetime, "The expiration date of this access token, derived from a UNIX timestamp."]

    def to_dict(self):
        return {
            "yvp_id": self.yvp_id,
            "subject": self.subject,
            "email": self.email,
            "name": self.name,
            "profile_picture_url": self.profile_picture_url,
            "issued_at": str(self.issued_at.timestamp()),
            "expiration": str(self.expiration.timestamp())
        }


@dataclass
class YouVersionPlatformJWKS:
    uri: Annotated[str, "The JWKS endpoint for the YouVersion API."] = "https://api.youversion.com/.well-known/jwks.json"
    iss: Annotated[str, "The validated issuer that should be used to validate received JWTs"] = "https://api.youversion.com/auth/token"
    oidc_discovery_url: Annotated[str | None, "Not yet supported"] = None
    kid: Annotated[str, "The 'kid' key to use from the .well-known/JWKS.json endpoint."] = "apigee-oauth-crypto-key"