#!/usr/bin/env python3
"""
HookProbe Globe Visualization - WebSocket Server

Simple WebSocket server that broadcasts threat events to connected clients.
Designed for low maintenance and easy extension.

Usage:
    python server.py [--port 8765] [--demo]

Options:
    --port  WebSocket port (default: 8765)
    --demo  Run with simulated demo data
"""

import asyncio
import json
import logging
import argparse
from datetime import datetime
from typing import Set

try:
    import websockets
    from websockets.server import WebSocketServerProtocol
except ImportError:
    print("Install dependencies: pip install -r requirements.txt")
    raise

from demo_data import DemoDataGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Connected clients
CLIENTS: Set[WebSocketServerProtocol] = set()


async def register(websocket: WebSocketServerProtocol) -> None:
    """Register a new client connection."""
    CLIENTS.add(websocket)
    client_info = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
    logger.info(f"Client connected: {client_info} (total: {len(CLIENTS)})")


async def unregister(websocket: WebSocketServerProtocol) -> None:
    """Unregister a client connection."""
    CLIENTS.discard(websocket)
    logger.info(f"Client disconnected (total: {len(CLIENTS)})")


async def broadcast(message: dict) -> None:
    """Broadcast a message to all connected clients."""
    if not CLIENTS:
        return

    payload = json.dumps(message)
    await asyncio.gather(
        *[client.send(payload) for client in CLIENTS],
        return_exceptions=True
    )


async def handle_client(websocket: WebSocketServerProtocol) -> None:
    """Handle individual client connection."""
    await register(websocket)
    try:
        # Send initial node status on connect
        await websocket.send(json.dumps({
            "type": "connected",
            "message": "HookProbe Globe Visualization",
            "version": "0.1.0",
            "timestamp": datetime.utcnow().isoformat()
        }))

        # Keep connection alive and handle incoming messages
        async for message in websocket:
            try:
                data = json.loads(message)
                # Handle client requests (e.g., request current state)
                if data.get("type") == "request_nodes":
                    # Future: fetch real node data
                    pass
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON from client: {message[:100]}")

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        await unregister(websocket)


async def demo_mode(interval: float = 3.0) -> None:
    """Generate demo events for testing."""
    generator = DemoDataGenerator()
    logger.info("Demo mode: generating simulated events")

    while True:
        event = generator.generate_event()
        await broadcast(event)
        await asyncio.sleep(interval)


async def main(port: int = 8765, demo: bool = False) -> None:
    """Start the WebSocket server."""
    logger.info(f"Starting HookProbe Globe Server on ws://0.0.0.0:{port}")

    async with websockets.serve(handle_client, "0.0.0.0", port):
        if demo:
            await demo_mode()
        else:
            # Production: wait forever (HTP/Neuro collectors push events)
            await asyncio.Future()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HookProbe Globe WebSocket Server")
    parser.add_argument("--port", type=int, default=8765, help="WebSocket port")
    parser.add_argument("--demo", action="store_true", help="Run with demo data")
    args = parser.parse_args()

    try:
        asyncio.run(main(port=args.port, demo=args.demo))
    except KeyboardInterrupt:
        logger.info("Server shutdown")
