#!/usr/bin/env python3
"""
HookProbe LLM Engine — Local inference via llama-cpp-python

Provides text generation and embedding on edge devices using quantized
GGUF models. Gracefully degrades if llama-cpp-python is not installed
or the model doesn't fit in available RAM.

Model recommendations per tier:
  Guardian (1.5GB):  SmolLM-135M-Q4   (~80MB RAM)
  Fortress (4GB):    TinyLlama-1.1B-Q4 (~670MB RAM)
  Nexus (16GB+):     Phi-3-mini-Q4     (~2.3GB RAM)
  Nexus (48GB+):     Llama-3.1-70B-Q4  (~40GB RAM)
"""

import logging
import os
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

# Model paths (downloaded on demand or pre-installed)
MODEL_DIR = Path(os.environ.get("HOOKPROBE_MODEL_DIR",
                                 "/opt/hookprobe/models"))

# Model file mappings
MODEL_FILES = {
    "smollm-135m-q4":    "smollm-135M-instruct-v0.2.Q4_K_M.gguf",
    "tinyllama-1.1b-q4": "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
    "phi-3-mini-q4":     "Phi-3-mini-4k-instruct-q4.gguf",
    "llama-3.1-70b-q4":  "Meta-Llama-3.1-70B-Instruct-Q4_K_M.gguf",
}

# Thread allocation per tier
TIER_THREADS = {
    "guardian": 2,
    "fortress": 4,
    "nexus": 8,
}


class LlamaEngine:
    """Local LLM inference via llama-cpp-python."""

    def __init__(self, model_path: str, n_threads: int = 4,
                 n_ctx: int = 2048, n_batch: int = 512):
        try:
            from llama_cpp import Llama
        except ImportError:
            raise ImportError(
                "llama-cpp-python not installed. "
                "Install with: pip install llama-cpp-python"
            )

        self._model_path = model_path
        self._model_name = Path(model_path).stem
        self._llm = Llama(
            model_path=model_path,
            n_threads=n_threads,
            n_ctx=n_ctx,
            n_batch=n_batch,
            embedding=True,  # Enable embedding support
            verbose=False,
        )
        logger.info(f"LlamaEngine loaded: {self._model_name} "
                     f"(threads={n_threads}, ctx={n_ctx})")

    @classmethod
    def from_recommendation(cls, recommendation: str,
                            hw_profile=None) -> Optional['LlamaEngine']:
        """Create engine from hardware recommendation string."""
        if recommendation == "none":
            return None

        model_file = MODEL_FILES.get(recommendation)
        if not model_file:
            logger.warning(f"Unknown model recommendation: {recommendation}")
            return None

        model_path = MODEL_DIR / model_file
        if not model_path.exists():
            logger.info(f"Model not found at {model_path} — LLM disabled. "
                        f"Download with: hookprobe-ctl model download {recommendation}")
            return None

        tier = hw_profile.tier_recommendation if hw_profile else "fortress"
        n_threads = TIER_THREADS.get(tier, 4)

        # Smaller context for constrained devices
        n_ctx = 512 if tier == "guardian" else 2048

        try:
            return cls(str(model_path), n_threads=n_threads, n_ctx=n_ctx)
        except Exception as e:
            logger.error(f"Failed to load LLM {model_file}: {e}")
            return None

    def generate(self, prompt: str, max_tokens: int = 256) -> str:
        """Generate text from prompt."""
        try:
            output = self._llm(
                prompt,
                max_tokens=max_tokens,
                stop=["</s>", "\n\n\n"],
                echo=False,
            )
            return output["choices"][0]["text"].strip()
        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            return ""

    def embed(self, text: str) -> List[float]:
        """Generate text embedding."""
        try:
            return self._llm.embed(text)
        except Exception as e:
            logger.error(f"LLM embedding failed: {e}")
            return []

    def model_info(self) -> dict:
        return {
            "name": self._model_name,
            "path": self._model_path,
            "backend": "llama.cpp",
            "type": "gguf",
        }
