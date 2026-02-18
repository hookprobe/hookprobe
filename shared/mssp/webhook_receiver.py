"""
MSSP Webhook Receiver

Lightweight HTTP server that receives recommendation callbacks
from MSSP. Runs on port 8199 on each edge node.

Security:
    - Ed25519 signature verification on all payloads
    - Rate limiting (20 req/min)
    - Bind to localhost by default (mesh relay handles external)
    - No sensitive data in responses
"""

import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Dict, Optional

from .auth import verify_recommendation_signature
from .types import RecommendedAction

logger = logging.getLogger(__name__)

DEFAULT_PORT = 8199
DEFAULT_HOST = "127.0.0.1"  # Localhost only — mesh handles external
MAX_BODY_SIZE = 65536  # 64KB max payload
RATE_LIMIT = 20  # Max requests per minute
RATE_WINDOW = 60.0


class WebhookHandler(BaseHTTPRequestHandler):
    """HTTP handler for MSSP webhook callbacks."""

    # Suppress default logging
    def log_message(self, format, *args):
        logger.debug("Webhook: %s", format % args)

    def do_POST(self):
        if self.path == "/webhook/recommendation":
            self._handle_recommendation()
        elif self.path == "/health":
            self._respond(200, {"status": "ok"})
        else:
            self._respond(404, {"error": "not_found"})

    def do_GET(self):
        if self.path == "/health":
            self._respond(200, {"status": "ok"})
        else:
            self._respond(404, {"error": "not_found"})

    def _handle_recommendation(self):
        """Process incoming recommendation webhook."""
        # Rate limit check
        if not self.server.check_rate_limit():
            self._respond(429, {"error": "rate_limited"})
            return

        # Read body
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > MAX_BODY_SIZE:
            self._respond(413, {"error": "payload_too_large"})
            return

        if content_length == 0:
            self._respond(400, {"error": "empty_body"})
            return

        body = self.rfile.read(content_length)

        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {"error": "invalid_json"})
            return

        # Verify signature
        if not verify_recommendation_signature(payload):
            logger.warning("Webhook: rejected recommendation with invalid signature")
            self._respond(403, {"error": "invalid_signature"})
            return

        # Parse recommendation
        try:
            action = RecommendedAction.from_dict(payload)
        except Exception as e:
            logger.warning("Webhook: failed to parse recommendation: %s", e)
            self._respond(400, {"error": "invalid_payload"})
            return

        # Dispatch to handler
        if self.server.recommendation_callback:
            try:
                self.server.recommendation_callback(action)
                self._respond(200, {"status": "accepted", "action_id": action.action_id})
            except Exception as e:
                logger.error("Webhook handler error: %s", e)
                self._respond(500, {"error": "handler_error"})
        else:
            self._respond(200, {"status": "received_no_handler"})

    def _respond(self, status: int, data: Dict):
        """Send JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())


class WebhookServer(HTTPServer):
    """Extended HTTPServer with rate limiting and callback support."""

    def __init__(self, host: str, port: int):
        super().__init__((host, port), WebhookHandler)
        self.recommendation_callback: Optional[Callable] = None
        self._rate_count = 0
        self._rate_window_start = time.time()
        self._rate_lock = threading.Lock()

    def check_rate_limit(self) -> bool:
        """Check if request is within rate limit."""
        with self._rate_lock:
            now = time.time()
            if now - self._rate_window_start > RATE_WINDOW:
                self._rate_count = 0
                self._rate_window_start = now

            if self._rate_count >= RATE_LIMIT:
                return False

            self._rate_count += 1
            return True


class MSSPWebhookReceiver:
    """Manages the webhook receiver lifecycle.

    Usage:
        receiver = MSSPWebhookReceiver()
        receiver.on_recommendation(handler_func)
        receiver.start()
        # ... later ...
        receiver.stop()
    """

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self._host = host
        self._port = port
        self._server: Optional[WebhookServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def on_recommendation(self, callback: Callable[[RecommendedAction], None]) -> None:
        """Set the callback for received recommendations."""
        if self._server:
            self._server.recommendation_callback = callback
        self._callback = callback

    def start(self) -> None:
        """Start the webhook receiver in a background thread."""
        if self._running:
            return

        self._server = WebhookServer(self._host, self._port)
        if hasattr(self, '_callback'):
            self._server.recommendation_callback = self._callback

        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        self._running = True
        logger.info("Webhook receiver started on %s:%d", self._host, self._port)

    def stop(self) -> None:
        """Stop the webhook receiver."""
        self._running = False
        if self._server:
            self._server.shutdown()
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.info("Webhook receiver stopped")

    def _serve(self) -> None:
        """Background serve loop."""
        self._server.serve_forever()
