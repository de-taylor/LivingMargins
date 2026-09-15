# Imports
# Standard Library
import logging

# Third Party
from requests import HTTPError
from rich import print
import typer

# Custom
from service.session import AuthSession

# Establish app
app = typer.Typer()

logger = logging.getLogger(__name__)


@app.command()
def login():
    """Invokes the OAuth 2.0 PKCE authorization flow for the YouVersion platform API.

    This login flow creates a refresh_token that is accessible from the `keyring`. This refresh token is used to grab auth tokens to make API calls with for the duration of each command.
    """
    session = AuthSession()

    try:
        session.login()
    except HTTPError as err:
        logger.exception(err)


@app.command()
def logout():
    """Clears the refresh_token out of the local `keyring`, effectively logging the user out.
    """
    session = AuthSession()
    session.logout()
