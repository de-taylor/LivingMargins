# Imports
# Standard Library
import logging

# Third Party
from requests import HTTPError
import typer

# Custom
from service.session import AuthSession

# Establish app
app = typer.Typer()

logger = logging.getLogger('LivingMargins')
logging.basicConfig(filename='logs/debug.log', encoding='utf-8', level=logging.DEBUG)

@app.command()
def main():
    print("Hello from main!")

@app.command()
def login():
    session = AuthSession()

    try:
        session.login()
    except HTTPError as err:
        logger.exception(err)

if __name__ == '__main__':
    # Typer app entrypoint
    app()