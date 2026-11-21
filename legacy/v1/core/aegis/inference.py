"""
AEGIS Inference Engine — Hybrid LLM Backend

Three-tier progressive intelligence with hybrid routing:
  1. Template fallback (instant, always available — no API key)
  2. Local Ollama (fast classify/short responses, ~100ms)
  3. OpenRouter cloud LLM (complex reasoning, ~1s)

Backend routing:
  - "auto" (default): Ollama -> OpenRouter -> template
  - "local": Ollama only
  - "cloud": OpenRouter only
  - "fast": Ollama for short responses, OpenRouter for complex
"""

import json
import logging
import os
import threading
import time
from collections import deque
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


class OllamaBackend:
    """Local Ollama inference backend.

    Connects to a local Ollama instance for fast, private inference.
    Used for quick classification and short responses.
    """

    def __init__(self):
        self._base_url = os.environ.get("AEGIS_OLLAMA_URL", "http://localhost:11434")
        self._model = os.environ.get("AEGIS_OLLAMA_MODEL", "llama3.2:3b")
        self._available: Optional[bool] = None
        self._available_checked: float = 0
        self._cache_ttl = 30.0

    @property
    def is_available(self) -> bool:
        """Check if Ollama is reachable (cached for 30s)."""
        now = time.time()
        if self._available is not None and (now - self._available_checked) < self._cache_ttl:
            return self._available

        try:
            req = Request(f"{self._base_url}/api/tags", method="GET")
            with urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                models = [m.get("name", "") for m in data.get("models", [])]
                # Check if our model is available
                model_base = self._model.split(":")[0]
                self._available = any(model_base in m for m in models)
        except Exception:
            self._available = False

        self._available_checked = now
        return self._available

    def chat(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 512,
    ) -> Optional[Dict[str, Any]]:
        """Send a chat completion to Ollama."""
        if not self.is_available:
            return None

        payload = {
            "model": self._model,
            "messages": messages,
            "stream": False,
            "options": {"num_predict": max_tokens},
        }

        try:
            body = json.dumps(payload).encode("utf-8")
            req = Request(
                f"{self._base_url}/api/chat",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                msg = data.get("message", {})
                return {
                    "message": {
                        "role": msg.get("role", "assistant"),
                        "content": msg.get("content", ""),
                        "tool_calls": None,
                    },
                    "backend": "ollama",
                }
        except Exception as e:
            logger.debug("Ollama chat error: %s", e)
            self._available = None
            return None

    @property
    def model_name(self) -> str:
        return self._model


class NativeInferenceEngine:
    """Thread-safe hybrid inference engine.

    Features:
    - Background API key discovery (non-blocking startup)
    - Hybrid backend: Ollama (local) + OpenRouter (cloud)
    - Configurable routing: auto, local, cloud, fast
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
        self._inference_times: deque = deque(maxlen=100)

        # Resolved config (set during init)
        self._api_key: str = ""
        self._api_url: str = ""
        self._model_id: str = ""
        self._model_key: str = ""

        # Availability cache
        self._available: Optional[bool] = None
        self._available_checked: float = 0
        self._available_cache_ttl = 30.0

        # Hybrid backends
        self._ollama = OllamaBackend()
        self._backend_stats: Dict[str, int] = {"ollama": 0, "openrouter": 0, "template": 0}
        self._last_backend: str = ""

        # Configuration from environment
        self._model_pref = os.environ.get("AEGIS_MODEL", "auto")
        self._backend_mode = os.environ.get("AEGIS_BACKEND", "auto")  # auto, local, cloud, fast
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
        backend: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Send a chat completion request using hybrid routing.

        Backend routing:
        - "auto" (default): Try Ollama -> OpenRouter -> None
        - "local": Ollama only
        - "cloud": OpenRouter only
        - "fast": Ollama for short responses, OpenRouter for complex

        Args:
            messages: OpenAI-format messages (role, content).
            tools: Optional tool definitions for function calling.
            max_tokens: Maximum tokens to generate.
            backend: Override backend routing mode.

        Returns:
            Dict with 'message' key containing {role, content},
            or None if unavailable.
        """
        mode = backend or self._backend_mode
        start = time.time()

        # Route to appropriate backend
        result = None

        if mode == "local":
            result = self._chat_ollama(messages, max_tokens)
        elif mode == "cloud":
            result = self._chat_openrouter(messages, tools, max_tokens)
        elif mode == "fast":
            # Use Ollama for short responses, OpenRouter for complex
            if max_tokens <= 100 and not tools:
                result = self._chat_ollama(messages, max_tokens)
            if not result:
                result = self._chat_openrouter(messages, tools, max_tokens)
        else:  # auto
            # Try Ollama first (faster, private), fall back to OpenRouter
            if not tools:  # Ollama doesn't support tool calling well
                result = self._chat_ollama(messages, max_tokens)
            if not result:
                result = self._chat_openrouter(messages, tools, max_tokens)

        if result:
            elapsed_ms = (time.time() - start) * 1000
            self._record_inference_time(elapsed_ms)
            self._last_backend = result.get("backend", "unknown")
            self._backend_stats[self._last_backend] = (
                self._backend_stats.get(self._last_backend, 0) + 1
            )

        return result

    def _chat_ollama(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int,
    ) -> Optional[Dict[str, Any]]:
        """Try Ollama backend."""
        return self._ollama.chat(messages, max_tokens)

    def _chat_openrouter(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Any]],
        max_tokens: int,
    ) -> Optional[Dict[str, Any]]:
        """Try OpenRouter backend."""
        if not self.is_ready:
            return None

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
                "backend": "openrouter",
            }

        except Exception as e:
            logger.error("AEGIS: OpenRouter chat error: %s", e)
            self._available = None
            return None

    @property
    def is_any_ready(self) -> bool:
        """Check if any backend (Ollama or OpenRouter) is available."""
        return self.is_ready or self._ollama.is_available

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
            "llm_ready": self.is_any_ready,
            "model_loaded": self.is_any_ready,
            "model_name": self.model_name,
            "loading": self._loading,
            "load_error": self._load_error,
            "tier": self._get_tier(),
            "ram_usage_mb": round(ram_usage_mb, 1),
            "avg_inference_ms": self._avg_inference_ms(),
            "uptime": time.time() - self._start_time,
            "enabled": self._enabled,
            "backends": {
                "openrouter": self.is_ready,
                "ollama": (
                    self._ollama.is_available
                    if self._backend_mode != "cloud" else False
                ),
                "ollama_model": self._ollama.model_name,
            },
            "backend_mode": self._backend_mode,
            "backend_stats": dict(self._backend_stats),
            "last_backend": self._last_backend,
        }

    def _get_tier(self) -> str:
        """Get the current intelligence tier."""
        if self._backend_mode == "cloud":
            return "cloud" if self._ready else ("loading" if self._loading else "template")
        if self._ready and self._ollama.is_available:
            return "hybrid"
        if self._ready:
            return "cloud"
        if self._ollama.is_available:
            return "local"
        if self._loading:
            return "loading"
        return "template"

    def _http_post(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Make an HTTP POST request to OpenRouter."""
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://hookprobe.com",
            "X-Title": "HookProbe AEGIS",
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
