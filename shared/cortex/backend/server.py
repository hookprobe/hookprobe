#!/usr/bin/env python3
"""
HookProbe Globe Visualization - WebSocket Server

Phase 1C: Production Integration

Digital twin visualization server that:
1. Connects to the HookProbe mesh via HTP protocol (production mode)
2. Integrates with product connectors (Guardian, Fortress, Nexus)
3. Broadcasts real-time events to connected browsers
4. Supports dynamic switching between demo and live data
5. Provides REST API for configuration and statistics

Usage:
    # Demo mode (simulated events)
    python server.py --demo

    # Production mode (connect to mesh)
    python server.py --bootstrap mesh.hookprobe.com:8144

    # With product connector
    python server.py --connector guardian --node-id guardian-home-001

Options:
    --port          WebSocket port (default: 8765)
    --api-port      REST API port (default: 8766)
    --demo          Start in demo mode (can be toggled at runtime)
    --bootstrap     Bootstrap node for HTP mesh (host:port)
    --connector     Product connector to use (guardian, fortress, nexus)
    --node-id       Node ID for this instance
    --lat           Latitude for geographic placement
    --lng           Longitude for geographic placement
    --label         Human-readable label for this node
"""

import asyncio
import json
import logging
import argparse
from datetime import datetime
from typing import Set, Dict, Any, Optional, List

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
from htp_bridge import HTPBridge, HTPBridgeConfig, create_bridge, HTP_AVAILABLE, QSECBIT_AVAILABLE

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
    - HTP Bridge integration (production mode)
    - Product connector integration
    - REST API for configuration
    """

    VERSION = "1.0.0"

    def __init__(self, port: int = 8765, api_port: int = 8766):
        self.port = port
        self.api_port = api_port
        self.clients: Set[WebSocketServerProtocol] = set()
        self.registry = get_registry()

        # Data source mode
        self.demo_mode = True
        self.demo_generator = DemoDataGenerator()
        self.demo_interval = 2.5  # seconds (slightly faster than before)

        # HTP Bridge (for production mode)
        self._htp_bridge: Optional[HTPBridge] = None
        self._bridge_config: Optional[HTPBridgeConfig] = None

        # Connector manager (for live data)
        self._connector_manager = None
        self._active_connector = None

        # Statistics
        self.stats = {
            "start_time": None,
            "events_broadcast": 0,
            "clients_total": 0,
            "mode_switches": 0,
            "demo_events": 0,
            "live_events": 0,
        }

        # Background tasks
        self._tasks: List[asyncio.Task] = []

    async def start(
        self,
        demo: bool = True,
        bootstrap_nodes: List[tuple] = None,
        node_id: str = "cortex-server-001",
        lat: float = 0.0,
        lng: float = 0.0,
        label: str = "Cortex Server",
    ) -> None:
        """Start the server."""
        self.demo_mode = demo
        self.stats["start_time"] = datetime.utcnow()

        logger.info(f"Starting HookProbe Cortex Server v{self.VERSION}")
        logger.info(f"  WebSocket: ws://0.0.0.0:{self.port}")
        logger.info(f"  Mode: {'DEMO' if self.demo_mode else 'LIVE'}")
        logger.info(f"  HTP Available: {HTP_AVAILABLE}")
        logger.info(f"  Qsecbit Available: {QSECBIT_AVAILABLE}")

        # Initialize HTP bridge if in live mode
        if not demo and bootstrap_nodes:
            self._bridge_config = HTPBridgeConfig(
                bootstrap_nodes=bootstrap_nodes,
                node_id=node_id,
                lat=lat,
                lng=lng,
                label=label,
            )
            self._htp_bridge = HTPBridge(self._bridge_config)
            self._htp_bridge.add_event_callback(self._on_bridge_event)
            await self._htp_bridge.start()
            logger.info(f"  HTP Bridge: Connected to {len(bootstrap_nodes)} bootstrap node(s)")

        # Register registry events for broadcasting
        self.registry.add_event_callback(self._on_registry_event)

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

        # Start data generation/collection
        self._tasks.append(asyncio.create_task(self._data_loop()))

        # Run until cancelled
        try:
            await asyncio.Future()
        finally:
            ws_server.close()
            await ws_server.wait_closed()
            for task in self._tasks:
                task.cancel()
            if self._htp_bridge:
                await self._htp_bridge.stop()

    async def _handle_client(self, websocket: WebSocketServerProtocol) -> None:
        """Handle individual client connection."""
        await self._register(websocket)

        try:
            # Send initial state
            await websocket.send(json.dumps({
                "type": "connected",
                "message": "HookProbe Cortex - Neural Command Center",
                "version": self.VERSION,
                "mode": "demo" if self.demo_mode else "live",
                "htp_available": HTP_AVAILABLE,
                "qsecbit_available": QSECBIT_AVAILABLE,
                "htp_connected": self._htp_bridge.is_htp_connected if self._htp_bridge else False,
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
                interval = data.get("interval", 2.5)
                self.demo_interval = max(0.5, min(30.0, float(interval)))
                logger.info(f"Demo interval set to {self.demo_interval}s")

            elif msg_type == "trigger_burst":
                # Trigger a burst of demo events
                if self.demo_mode:
                    burst = self.demo_generator.generate_burst(data.get("count", 5))
                    for event in burst:
                        await self.broadcast(event)

            elif msg_type == "request_stats":
                # Send server statistics
                await websocket.send(json.dumps({
                    "type": "stats",
                    "server": self._get_stats(),
                    "demo": self.demo_generator.get_statistics() if self.demo_mode else None,
                    "bridge": self._htp_bridge.get_stats() if self._htp_bridge else None,
                    "timestamp": datetime.utcnow().isoformat(),
                }))

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
        if self.demo_mode:
            self.stats["demo_events"] += 1
        else:
            self.stats["live_events"] += 1

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
                    # Live mode - events come from HTP bridge and connectors
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
            "htp_connected": self._htp_bridge.is_htp_connected if self._htp_bridge else False,
            "timestamp": datetime.utcnow().isoformat()
        })

    def _get_snapshot(self) -> Dict[str, Any]:
        """Get current state snapshot."""
        if self.demo_mode:
            # Generate demo snapshot
            return self.demo_generator.get_full_snapshot()
        else:
            # Get real snapshot from registry
            return self.registry.get_snapshot()

    def _on_bridge_event(self, event: Dict[str, Any]) -> None:
        """Handle event from HTP bridge (live mode)."""
        if not self.demo_mode:
            asyncio.create_task(self.broadcast(event))

    def _on_registry_event(self, event: Dict[str, Any]) -> None:
        """Handle event from node registry."""
        if not self.demo_mode:
            asyncio.create_task(self.broadcast(event))

    def _get_stats(self) -> Dict[str, Any]:
        """Get server statistics."""
        uptime = 0
        if self.stats["start_time"]:
            uptime = (datetime.utcnow() - self.stats["start_time"]).total_seconds()

        return {
            **self.stats,
            "start_time": (
                self.stats["start_time"].isoformat()
                if self.stats["start_time"] else None
            ),
            "uptime_seconds": int(uptime),
            "current_clients": len(self.clients),
            "demo_mode": self.demo_mode,
            "demo_interval": self.demo_interval,
            "htp_available": HTP_AVAILABLE,
            "qsecbit_available": QSECBIT_AVAILABLE,
        }

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
        app.router.add_post("/api/burst", self._api_trigger_burst)
        app.router.add_get("/api/health", self._api_health)

        # CORS headers for browser access
        @web.middleware
        async def cors_middleware(request, handler):
            response = await handler(request)
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
            return response

        app.middlewares.append(cors_middleware)

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
            "htp_available": HTP_AVAILABLE,
            "qsecbit_available": QSECBIT_AVAILABLE,
            "htp_connected": self._htp_bridge.is_htp_connected if self._htp_bridge else False,
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
            "server": self._get_stats(),
            "demo": self.demo_generator.get_statistics() if self.demo_mode else None,
            "bridge": self._htp_bridge.get_stats() if self._htp_bridge else None,
        })

    async def _api_trigger_burst(self, request: web.Request) -> web.Response:
        """POST /api/burst - Trigger a burst of demo events."""
        if not self.demo_mode:
            return web.json_response({"error": "Burst only available in demo mode"}, status=400)

        try:
            data = await request.json()
            count = min(20, max(1, data.get("count", 5)))
            burst = self.demo_generator.generate_burst(count)
            for event in burst:
                await self.broadcast(event)
            return web.json_response({"events_triggered": len(burst)})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def _api_health(self, request: web.Request) -> web.Response:
        """GET /api/health - Health check endpoint."""
        return web.json_response({
            "status": "healthy",
            "version": self.VERSION,
            "timestamp": datetime.utcnow().isoformat(),
        })


# Global server instance
_server: Optional[GlobeServer] = None


def get_server() -> GlobeServer:
    """Get or create the global server instance."""
    global _server
    if _server is None:
        _server = GlobeServer()
    return _server


async def main(
    port: int = 8765,
    api_port: int = 8766,
    demo: bool = True,
    bootstrap: str = None,
    node_id: str = "cortex-server-001",
    lat: float = 0.0,
    lng: float = 0.0,
    label: str = "Cortex Server",
) -> None:
    """Start the globe server."""
    # Parse bootstrap nodes
    bootstrap_nodes = []
    if bootstrap:
        for node in bootstrap.split(","):
            host, port_str = node.strip().split(":")
            bootstrap_nodes.append((host, int(port_str)))

    server = GlobeServer(port=port, api_port=api_port)
    await server.start(
        demo=demo,
        bootstrap_nodes=bootstrap_nodes if not demo else None,
        node_id=node_id,
        lat=lat,
        lng=lng,
        label=label,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HookProbe Cortex WebSocket Server")
    parser.add_argument("--port", type=int, default=8765, help="WebSocket port")
    parser.add_argument("--api-port", type=int, default=8766, help="REST API port")
    parser.add_argument("--demo", action="store_true", help="Start in demo mode")
    parser.add_argument("--bootstrap", type=str, help="Bootstrap node(s) for HTP mesh (host:port,host:port)")
    parser.add_argument("--node-id", type=str, default="cortex-server-001", help="Node ID")
    parser.add_argument("--lat", type=float, default=0.0, help="Latitude")
    parser.add_argument("--lng", type=float, default=0.0, help="Longitude")
    parser.add_argument("--label", type=str, default="Cortex Server", help="Human-readable label")
    args = parser.parse_args()

    try:
        asyncio.run(main(
            port=args.port,
            api_port=args.api_port,
            demo=args.demo or not args.bootstrap,  # Default to demo if no bootstrap
            bootstrap=args.bootstrap,
            node_id=args.node_id,
            lat=args.lat,
            lng=args.lng,
            label=args.label,
        ))
    except KeyboardInterrupt:
        logger.info("Server shutdown")
