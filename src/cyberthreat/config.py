"""Central configuration: paths, LLM selection and API-key handling."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KB_DIR = ROOT / "knowledge_base"
OUTPUT_DIR = ROOT / "outputs"
CHROMA_DIR = ROOT / "chroma_db"
SEED = 42

DEFAULT_MODELS = {
    "groq": "groq/llama-3.3-70b-versatile",
    "gemini": "gemini/gemini-2.0-flash",
}
KEY_VARS = {"groq": "GROQ_API_KEY", "gemini": "GEMINI_API_KEY"}


def load_env() -> None:
    """Load .env (if python-dotenv is present) and Colab secrets (if running in Colab)."""
    try:
        from dotenv import load_dotenv

        load_dotenv(ROOT / ".env")
    except ImportError:
        pass
    try:  # Google Colab secrets
        from google.colab import userdata  # type: ignore

        for var in (*KEY_VARS.values(), "LLM_PROVIDER"):
            if not os.environ.get(var):
                try:
                    os.environ[var] = userdata.get(var)
                except Exception:
                    pass
    except ImportError:
        pass


@dataclass
class LLMSettings:
    provider: str  # groq | gemini | offline
    model: str | None
    api_key: str | None

    @property
    def offline(self) -> bool:
        return self.provider == "offline"


def get_llm_settings(provider: str | None = None) -> LLMSettings:
    """Resolve the LLM backend. Falls back to ``offline`` when no API key is found."""
    load_env()
    provider = (provider or os.environ.get("LLM_PROVIDER") or "groq").lower()
    if provider == "offline":
        return LLMSettings("offline", None, None)
    if provider not in KEY_VARS:
        raise ValueError(f"Unknown LLM_PROVIDER '{provider}' (use groq, gemini or offline)")
    key = os.environ.get(KEY_VARS[provider])
    if not key:
        return LLMSettings("offline", None, None)
    model = os.environ.get(f"{provider.upper()}_MODEL", DEFAULT_MODELS[provider])
    return LLMSettings(provider, model, key)


def build_llm(settings: LLMSettings | None = None):
    """Create a CrewAI ``LLM`` for the chosen provider (None when offline)."""
    settings = settings or get_llm_settings()
    if settings.offline:
        return None
    from crewai import LLM

    return LLM(model=settings.model, api_key=settings.api_key, temperature=0.1)
