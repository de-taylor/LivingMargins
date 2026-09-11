# Imports
# Standard Library
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import threading
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

# Create server class to actually launch server
class AuthFlowServer(HTTPServer):
    def __init__(self, address, handler):
        super().__init__(address, handler)

        self.state: str | None = None
        self.callback_event = threading.Event()

# Create handler for localhost redirect
class AuthFlowHandler(BaseHTTPRequestHandler):

    # handle the basic GET request
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)

        self.server.state = query.get('state', [None])[0]  # type: ignore

        # respond to browser
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Auth successful!</h1><p>You may now close this browser.</p></body></html>")

        self.server.callback_event.set()  # type: ignore

def create_server(port=13333):
    # start up the server
    server = AuthFlowServer(("localhost", port), AuthFlowHandler)

    logger.info(f"Listening for callback on port {port}")

    return server