"""
shared.models - The place to keep the communication contracts across LivingMargins.
"""
# Imports
# Standard Library
import base64
import hashlib
import random
import secrets
from typing import Annotated
import uuid

# Third Party
from pydantic import BaseModel

class PKCECodes(BaseModel):
    code_verifier: Annotated[str, "A URL-safe token generated for the PKCE process."] = secrets.token_urlsafe(random.randint(44, 127))
    code_challenge: Annotated[bytes | None, "A Base64-encoded bytes object representing the hashed code verifier."] = None
    nonce: Annotated[str, "Used to make the initial authorization request to YouVersion, allowing LivingMargins to use part of the YouVersion profile."] = str(uuid.uuid4())
    state: Annotated[str, "Used to make the initial authorization request to YouVersion, allowing LivingMargins to use part of the YouVersion profile."] = secrets.token_urlsafe(random.randint(21, 33))
    response_state: Annotated[str | None, "The state sent back in the first part of the OAuth PKCE flow."] = None

    def create_code_challenge(self):
        # SHA256 encryption
        _sha256_hash_obj = hashlib.sha256()
        _sha256_hash_obj.update(self.code_verifier.encode('utf-8'))

        # SHA256 encrypted, Base64 encoded
        self.code_challenge = base64.urlsafe_b64encode(_sha256_hash_obj.digest())

class AuthSession(BaseModel):
    client_id: Annotated[str, "The provided public Client ID for the application."] = "CApjAnlXGBEMLVeGj8ibFMxNPSXDMSmGx4NXb6JDBjWNCepA"
    callback_url: Annotated[str, "The configured callback URL provided for the application."] = "http://localhost:13333"
    PKCE: Annotated[PKCECodes, "The codes used to perform authentication using the OAuth 2.0 PKCE flow."] = PKCECodes()


    def authorize_url(self) -> str:
        return f"https://api.youversion.com/auth/authorize?response_type=code&client_id={self.client_id}&redirect_uri={self.callback_url}&scope=openid%20profile%20email&nonce={self.PKCE.nonce}&state={self.PKCE.state}&code_challenge={self.PKCE.code_challenge}&code_challenge_method=S256&requested_permissions[]=highlights"