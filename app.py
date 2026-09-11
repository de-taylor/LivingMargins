# Imports
# Standard Library
import json
import logging

# Third Party
import typer

# Custom
from service.auth import YouversionAuthenticator

# Establish app
app = typer.Typer()

logger = logging.getLogger('LivingMargins')

@app.command()
def login():
    authenticator = YouversionAuthenticator()

    authenticator.login()


if __name__ == '__main__':
    # Typer app entrypoint
    app()