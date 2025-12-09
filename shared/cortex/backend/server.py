#!/usr/bin/env python3
"""
HookProbe Globe Visualization - WebSocket Server

Digital twin visualization server that:
1. Connects to the HookProbe mesh via product connectors
2. Broadcasts real-time events to connected browsers
3. Supports dynamic switching between demo and live data
4. Provides snapshot API for new connections

Usage:
    python server.py [--port 8765] [--demo] [--api-port 8766]

Options:
    --port      WebSocket port (default: 8765)
    --api-port  REST API port (default: 8766)
    --demo      Start in demo mode (can be toggled at runtime)
"""

import asyncio
import json
import logging
import argparse
from datetime import datetime
from typing import Set, Dict, Any, Optional

try:
    import websockets
    from websockets.server import WebSocketServerProtocol
except ImportError:
    print("Install dependencies: pip install -r requirements.txt")
    raise

try:
    from aiohttp import web
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from demo_data import DemoDataGenerator
from node_registry import get_registry, NodeTier

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


class GlobeServer:
    """
    Globe visualization WebSocket server with demo/live toggle.

    Features:
    - WebSocket broadcast to all connected browsers
    - Dynamic demo/live data switching
    - Product connector integration
    - REST API for configuration
    """

    VERSION = "0.2.0"

    def __init__(self, port: int = 8765, api_port: int = 8766):
        self.port = port
        self.api_port = api_port
        self.clients: Set[WebSocketServerProtocol] = set()
        self.registry = get_registry()

        # Data source mode
        self.demo_mode = True
        self.demo_generator = DemoDataGenerator()
        self.demo_interval = 3.0  # seconds

        # Connector manager (for live data)
        self._connector_manager = None

        # Statistics
        self.stats = {
            "start_time": None,
            "events_broadcast": 0,
            "clients_total": 0,
            "mode_switches": 0,
        }

        # Background tasks
        self._tasks: list = []

    async def start(self, demo: bool = True) -> None:
        """Start the server."""
        self.demo_mode = demo
        self.stats["start_time"] = datetime.utcnow()

        logger.info(f"Starting HookProbe Globe Server v{self.VERSION}")
        logger.info(f"  WebSocket: ws://0.0.0.0:{self.port}")
        logger.info(f"  Mode: {'DEMO' if self.demo_mode else 'LIVE'}")

        # Start WebSocket server
        ws_server = await websockets.serve(
            self._handle_client,
            "0.0.0.0",
            self.port
        )

        # Start REST API if aiohttp available
        api_task = None
        if AIOHTTP_AVAILABLE:
            api_task = asyncio.create_task(self._start_api_server())
            logger.info(f"  REST API: http://0.0.0.0:{self.api_port}")

        # Start data generation
        self._tasks.append(asyncio.create_task(self._data_loop()))

        # Run until cancelled
        try:
            await asyncio.Future()
        finally:
            ws_server.close()
            await ws_server.wait_closed()
            for task in self._tasks:
                task.cancel()

    async def _handle_client(self, websocket: WebSocketServerProtocol) -> None:
        """Handle individual client connection."""
        await self._register(websocket)

        try:
            # Send initial state
            await websocket.send(json.dumps({
                "type": "connected",
                "message": "HookProbe Globe Digital Twin",
                "version": self.VERSION,
                "mode": "demo" if self.demo_mode else "live",
                "timestamp": datetime.utcnow().isoformat()
            }))

            # Send current snapshot
            snapshot = self._get_snapshot()
            await websocket.send(json.dumps(snapshot))

            # Handle incoming messages
            async for message in websocket:
                await self._handle_message(websocket, message)

        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            await self._unregister(websocket)

    async def _handle_message(self, websocket: WebSocketServerProtocol, message: str) -> None:
        """Handle a message from a client."""
        try:
            data = json.loads(message)
            msg_type = data.get("type", "")

            if msg_type == "request_snapshot":
                # Send current state snapshot
                snapshot = self._get_snapshot()
                await websocket.send(json.dumps(snapshot))

            elif msg_type == "set_mode":
                # Switch between demo and live mode
                new_mode = data.get("mode", "demo")
                await self._set_mode(new_mode == "demo")

            elif msg_type == "set_demo_interval":
                # Adjust demo event frequency
                interval = data.get("interval", 3.0)
                self.demo_interval = max(0.5, min(30.0, float(interval)))
                logger.info(f"Demo interval set to {self.demo_interval}s")

            elif msg_type == "ping":
                await websocket.send(json.dumps({
                    "type": "pong",
                    "timestamp": datetime.utcnow().isoformat()
                }))

        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON from client: {message[:100]}")
        except Exception as e:
            logger.error(f"Error handling message: {e}")

    async def _register(self, websocket: WebSocketServerProtocol) -> None:
        """Register a new client."""
        self.clients.add(websocket)
        self.stats["clients_total"] += 1
        client_info = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
        logger.info(f"Client connected: {client_info} (total: {len(self.clients)})")

    async def _unregister(self, websocket: WebSocketServerProtocol) -> None:
        """Unregister a client."""
        self.clients.discard(websocket)
        logger.info(f"Client disconnected (total: {len(self.clients)})")

    async def broadcast(self, event: Dict[str, Any]) -> None:
        """Broadcast an event to all connected clients."""
        if not self.clients:
            return

        self.stats["events_broadcast"] += 1
        payload = json.dumps(event)

        await asyncio.gather(
            *[client.send(payload) for client in self.clients],
            return_exceptions=True
        )

    async def _data_loop(self) -> None:
        """Main data generation/collection loop."""
        while True:
            try:
                if self.demo_mode:
                    # Generate demo event
                    event = self.demo_generator.generate_event()
                    await self.broadcast(event)
                    await asyncio.sleep(self.demo_interval)
                else:
                    # Live mode - events come from connectors
                    # Just keep the loop alive
                    await asyncio.sleep(1.0)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Data loop error: {e}")
                await asyncio.sleep(1.0)

    async def _set_mode(self, demo: bool) -> None:
        """Switch between demo and live mode."""
        if demo == self.demo_mode:
            return

        self.demo_mode = demo
        self.stats["mode_switches"] += 1
        mode_str = "DEMO" if demo else "LIVE"
        logger.info(f"Mode switched to: {mode_str}")

        # Notify all clients
        await self.broadcast({
            "type": "mode_changed",
            "mode": "demo" if demo else "live",
            "timestamp": datetime.utcnow().isoformat()
        })

    def _get_snapshot(self) -> Dict[str, Any]:
        """Get current state snapshot."""
        if self.demo_mode:
            # Generate demo snapshot
            return self.demo_generator._generate_node_status()
        else:
            # Get real snapshot from registry
            return self.registry.get_snapshot()

    def on_connector_event(self, event: Dict[str, Any]) -> None:
        """
        Handle event from a product connector.

        Call this from connector callbacks to forward events to browsers.
        """
        if not self.demo_mode:
            asyncio.create_task(self.broadcast(event))

    # =========================================================================
    # REST API
    # =========================================================================

    async def _start_api_server(self) -> None:
        """Start REST API server for configuration."""
        app = web.Application()

        app.router.add_get("/api/status", self._api_status)
        app.router.add_get("/api/snapshot", self._api_snapshot)
        app.router.add_post("/api/mode", self._api_set_mode)
        app.router.add_get("/api/stats", self._api_stats)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", self.api_port)
        await site.start()

    async def _api_status(self, request: web.Request) -> web.Response:
        """GET /api/status - Server status."""
        return web.json_response({
            "version": self.VERSION,
            "mode": "demo" if self.demo_mode else "live",
            "clients": len(self.clients),
            "uptime_seconds": (
                int((datetime.utcnow() - self.stats["start_time"]).total_seconds())
                if self.stats["start_time"] else 0
            ),
        })

    async def _api_snapshot(self, request: web.Request) -> web.Response:
        """GET /api/snapshot - Current state snapshot."""
        return web.json_response(self._get_snapshot())

    async def _api_set_mode(self, request: web.Request) -> web.Response:
        """POST /api/mode - Set demo/live mode."""
        try:
            data = await request.json()
            mode = data.get("mode", "demo")
            await self._set_mode(mode == "demo")
            return web.json_response({"mode": "demo" if self.demo_mode else "live"})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def _api_stats(self, request: web.Request) -> web.Response:
        """GET /api/stats - Server statistics."""
        return web.json_response({
            **self.stats,
            "start_time": (
                self.stats["start_time"].isoformat()
                if self.stats["start_time"] else None
            ),
            "current_clients": len(self.clients),
            "demo_mode": self.demo_mode,
            "demo_interval": self.demo_interval,
        })


# Global server instance
_server: Optional[GlobeServer] = None


def get_server() -> GlobeServer:
    """Get or create the global server instance."""
    global _server
    if _server is None:
        _server = GlobeServer()
    return _server


async def main(port: int = 8765, api_port: int = 8766, demo: bool = False) -> None:
    """Start the globe server."""
    server = GlobeServer(port=port, api_port=api_port)
    await server.start(demo=demo)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HookProbe Globe WebSocket Server")
    parser.add_argument("--port", type=int, default=8765, help="WebSocket port")
    parser.add_argument("--api-port", type=int, default=8766, help="REST API port")
    parser.add_argument("--demo", action="store_true", help="Start in demo mode")
    args = parser.parse_args()

    try:
        asyncio.run(main(port=args.port, api_port=args.api_port, demo=args.demo))
    except KeyboardInterrupt:
        logger.info("Server shutdown")
