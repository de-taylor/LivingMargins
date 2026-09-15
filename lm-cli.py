# Imports
# Standard Library
import datetime as dt
import logging
from pathlib import Path

# Third Party
from rich import print
import typer

# Custom
# CLIs
from cli.auth import app as auth_app

# shared
from service.session import AuthSession

# Establish app
app = typer.Typer(
    no_args_is_help=True,
    help="LivingMargins CLI brings God's word to the command-line, allowing you to peruse scripture with your added highlights as you'd like."
    )

log_path: Path = Path(typer.get_app_dir("LivingMargins", roaming=False)) / "logs"

if not log_path.exists():
    log_path.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger('LivingMargins')
logging.basicConfig(filename=log_path / f'{dt.datetime.now().strftime('%Y-%m-%d')}.log', encoding='utf-8', level=logging.DEBUG)

app.add_typer(auth_app, name="auth", rich_help_panel="Authentication")

@app.command()
def test():
    auth_session = AuthSession()
    auth_session.refresh()

    if auth_session.token:
        print(auth_session.token.access_token)
        print(auth_session.token.expires_at)

if __name__ == '__main__':
    # Typer app entrypoint
    app()
