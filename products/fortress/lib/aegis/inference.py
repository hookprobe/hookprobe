"""
AEGIS Inference Engine

OpenRouter API inference with background initialization,
thread-safe chat completions, and graceful degradation.

Two-tier progressive intelligence:
  1. Template fallback (instant, always available — no API key)
  2. OpenRouter cloud LLM (~1s, API key configured)
"""

import json
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


class NativeInferenceEngine:
    """Thread-safe OpenRouter inference engine.

    Features:
    - Background API key discovery (non-blocking startup)
    - Configurable model selection via registry or direct model ID
    - Thread-safe HTTP calls
    - OpenAI-compatible chat() return format
    - Health status reporting with latency tracking
    - Cached availability checks (30s TTL)
    """

    def __init__(self):
        self._ready: bool = False
        self._lock = threading.Lock()
        self._loading: bool = False
        self._load_error: str = ""
        self._start_time: float = time.time()
        self._inference_times: List[float] = []
        self._max_inference_samples = 100

        # Resolved config (set during init)
        self._api_key: str = ""
        self._api_url: str = ""
        self._model_id: str = ""
        self._model_key: str = ""

        # Availability cache
        self._available: Optional[bool] = None
        self._available_checked: float = 0
        self._available_cache_ttl = 30.0

        # Configuration from environment
        self._model_pref = os.environ.get("AEGIS_MODEL", "auto")
        self._enabled = os.environ.get("AEGIS_ENABLED", "true").lower() in (
            "true", "1", "yes",
        )

        if self._enabled:
            self._start_background_init()

    def _start_background_init(self):
        """Initialize API config in a daemon thread."""
        thread = threading.Thread(
            target=self._background_init,
            name="aegis-init",
            daemon=True,
        )
        thread.start()

    def _background_init(self):
        """Discover API key and resolve model in background."""
        self._loading = True
        self._load_error = ""

        try:
            from . import model_manager

            # Discover API key
            self._api_key = model_manager.get_api_key()
            self._api_url = model_manager.get_api_url()

            if not self._api_key:
                self._load_error = "No OpenRouter API key configured"
                logger.warning("AEGIS: %s", self._load_error)
                return

            # Resolve model
            self._model_id = model_manager.get_model_id(self._model_pref)
            info = model_manager.get_model_info(self._model_pref)
            self._model_key = info.get("model_key", self._model_pref)

            self._ready = True
            logger.info(
                "AEGIS: ready — model=%s (%s)",
                self._model_key, self._model_id,
            )

        except Exception as e:
            self._load_error = str(e)
            logger.error("AEGIS: initialization failed: %s", e)
        finally:
            self._loading = False

    @property
    def is_ready(self) -> bool:
        """Check if the engine has a valid API key and model configured."""
        return self._ready and bool(self._api_key)

    @property
    def is_loading(self) -> bool:
        """Check if initialization is in progress."""
        return self._loading

    @property
    def model_name(self) -> str:
        """Get the active model display name."""
        if self._ready:
            return self._model_id
        if self._loading:
            return "initializing..."
        if self._load_error:
            return f"error: {self._load_error[:50]}"
        return "not configured"

    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Any]] = None,
        max_tokens: int = 512,
    ) -> Optional[Dict[str, Any]]:
        """Send a chat completion request to OpenRouter.

        Args:
            messages: OpenAI-format messages (role, content).
            tools: Optional tool definitions for function calling.
            max_tokens: Maximum tokens to generate.

        Returns:
            Dict with 'message' key containing {role, content},
            or None if unavailable.
        """
        if not self.is_ready:
            return None

        start = time.time()

        payload: Dict[str, Any] = {
            "model": self._model_id,
            "messages": messages,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = tools

        try:
            result = self._http_post(payload)
            if not result:
                return None

            elapsed_ms = (time.time() - start) * 1000
            self._record_inference_time(elapsed_ms)

            # Extract from OpenAI-compatible response
            choices = result.get("choices", [])
            if not choices:
                return None

            message = choices[0].get("message", {})
            return {
                "message": {
                    "role": message.get("role", "assistant"),
                    "content": message.get("content", ""),
                    "tool_calls": message.get("tool_calls"),
                },
            }

        except Exception as e:
            logger.error("AEGIS: chat error: %s", e)
            # Invalidate availability cache on error
            self._available = None
            return None

    def health_check(self) -> Dict[str, Any]:
        """Return health status as a dict.

        Used by AegisClient.get_status() to build AegisStatus.
        """
        ram_usage_mb = 0.0
        try:
            import psutil
            process = psutil.Process()
            ram_usage_mb = process.memory_info().rss / (1024 * 1024)
        except (ImportError, Exception):
            pass

        return {
            "llm_ready": self.is_ready,
            "model_loaded": self.is_ready,
            "model_name": self.model_name,
            "loading": self._loading,
            "load_error": self._load_error,
            "tier": self._get_tier(),
            "ram_usage_mb": round(ram_usage_mb, 1),
            "avg_inference_ms": self._avg_inference_ms(),
            "uptime": time.time() - self._start_time,
            "enabled": self._enabled,
        }

    def _get_tier(self) -> str:
        """Get the current intelligence tier."""
        if self._ready:
            return "cloud"
        if self._loading:
            return "loading"
        return "template"

    def _http_post(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Make an HTTP POST request to OpenRouter."""
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://hookprobe.com",
            "X-Title": "HookProbe Fortress AEGIS",
        }

        body = json.dumps(payload).encode("utf-8")
        req = Request(self._api_url, data=body, headers=headers, method="POST")

        try:
            with urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except URLError as e:
            logger.error("AEGIS: API request failed: %s", e)
            return None
        except json.JSONDecodeError as e:
            logger.error("AEGIS: invalid JSON response: %s", e)
            return None

    def _record_inference_time(self, elapsed_ms: float):
        """Record an inference time sample."""
        self._inference_times.append(elapsed_ms)
        if len(self._inference_times) > self._max_inference_samples:
            self._inference_times = self._inference_times[-self._max_inference_samples:]

    def _avg_inference_ms(self) -> float:
        """Calculate average inference time."""
        if not self._inference_times:
            return 0.0
        return round(sum(self._inference_times) / len(self._inference_times), 1)


# ------------------------------------------------------------------
# Singleton
# ------------------------------------------------------------------

_engine: Optional[NativeInferenceEngine] = None
_engine_lock = threading.Lock()


def get_inference_engine() -> NativeInferenceEngine:
    """Get or create the global NativeInferenceEngine singleton."""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = NativeInferenceEngine()
    return _engine
