"""
service.auth - provides the business logic for implementing application authentication when
the various `lm auth <subcmd>` sub-commands are called.
"""
# Imports
import base64
import hashlib
import logging
import random
import secrets
import threading
import webbrowser
import uuid

# Custom
from shared.auth import create_server
from shared.models import AuthSession

logger = logging.getLogger()

class YouversionAuthenticator:
    def __init__(self):
        self.auth_session = AuthSession()


    def login(self):
        """Facilitates the PKCE procedure for OAuth 2.0 sign ins to the YouVersion application, to carry highlights to the CLI application.
        """
        self.auth_session.PKCE.create_code_challenge()

        server = create_server()

        threading.Thread(
            target=server.serve_forever,
            daemon=True
        ).start()

        webbrowser.open(self.auth_session.authorize_url())

        server.callback_event.wait()

        state = server.state

        server.shutdown()

        logger.info(state)
        print(state)
