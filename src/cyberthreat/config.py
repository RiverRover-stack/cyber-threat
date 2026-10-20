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
    "openrouter": "openrouter/nvidia/nemotron-3.5-super-vl:free",
}
KEY_VARS = {"groq": "GROQ_API_KEY", "gemini": "GEMINI_API_KEY", "openrouter": "OPENROUTER_API_KEY"}


def load_env() -> None:
    """Load .env (if python-dotenv is present) and Colab secrets (if running in Colab)."""
    try:
        from dotenv import load_dotenv

        load_dotenv(ROOT / ".env")
    except ImportError:
        pass
    try:  # Google Colab secrets
        from google.colab import userdata  # type: ignore

        for var in (*KEY_VARS.values(), "LLM_PROVIDER", *(f"{p.upper()}_MODEL" for p in KEY_VARS)):
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
    note: str = ""

    @property
    def offline(self) -> bool:
        return self.provider == "offline"


def _normalise_model(provider: str, model: str) -> str:
    """Return the LiteLLM/CrewAI form ``<provider>/<model-id>``.

    Strips only prefixes that belong to the provider, so OpenRouter ids such as ``google/gemma-...`` stay intact.
    """
    model = model.strip()
    prefixes = {"gemini": ("gemini/", "models/", "google/"), "groq": ("groq/",), "openrouter": ("openrouter/",)}
    for prefix in prefixes[provider]:
        if model.lower().startswith(prefix):
            model = model[len(prefix):]
    return f"{provider}/{model}"


def _infer_provider(text: str) -> str | None:
    t = text.lower()
    if t.startswith("openrouter/") or t.endswith(":free") or t.startswith("nvidia/"):
        return "openrouter"
    if "gemma" in t or "gemini" in t or t.startswith("google/"):
        return "gemini"
    if t.startswith("groq/") or "llama" in t or "mixtral" in t:
        return "groq"
    return None


def get_llm_settings(provider: str | None = None) -> LLMSettings:
    """Resolve the LLM backend.

    ``LLM_PROVIDER`` may be ``groq``, ``gemini``, ``openrouter``, ``offline`` or empty (auto: use whichever API key is set).
    If it holds a model name (e.g. ``google/gemma-4-26B-A4B-it``) it is treated as the model ID.
    Falls back to ``offline`` when no usable API key is found.
    """
    load_env()
    raw = (provider or os.environ.get("LLM_PROVIDER") or "").strip()
    low, model_override, note = raw.lower(), None, ""
    if low == "offline":
        return LLMSettings("offline", None, None, "LLM_PROVIDER=offline")
    if low in KEY_VARS:
        chosen = low
    else:
        chosen = None
        if low not in ("", "auto"):  # a model name was supplied instead of a provider
            model_override = raw
            chosen = _infer_provider(raw)
            note = f"LLM_PROVIDER='{raw}' is not a provider; treating it as the model ID. "
        if chosen is None:  # auto-detect from whichever key exists
            chosen = next((p for p, var in KEY_VARS.items() if os.environ.get(var)), "groq")
    key = os.environ.get(KEY_VARS[chosen])
    if not key:
        other = next((p for p, var in KEY_VARS.items() if os.environ.get(var)), None)
        hint = f" (a {KEY_VARS[other]} exists - set LLM_PROVIDER={other})" if other else ""
        missing = f"No {KEY_VARS[chosen]} found{hint}" if other else "No GEMINI_API_KEY, GROQ_API_KEY or OPENROUTER_API_KEY found"
        return LLMSettings("offline", None, None, f"{note}{missing}; running offline.")
    model = model_override or os.environ.get(f"{chosen.upper()}_MODEL") or DEFAULT_MODELS[chosen]
    return LLMSettings(chosen, _normalise_model(chosen, model), key, note.strip())


def list_gemini_models(api_key: str | None = None) -> list[str]:
    """IDs of models your Gemini/AI Studio key can call with generateContent (copy one into GEMINI_MODEL)."""
    import json
    import urllib.request

    load_env()
    api_key = api_key or os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not set")
    names, token = [], ""
    while True:
        url = "https://generativelanguage.googleapis.com/v1beta/models?pageSize=200" + (f"&pageToken={token}" if token else "")
        req = urllib.request.Request(url, headers={"x-goog-api-key": api_key})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
        names += [m["name"].removeprefix("models/") for m in data.get("models", [])
                  if "generateContent" in m.get("supportedGenerationMethods", [])]
        token = data.get("nextPageToken", "")
        if not token:
            return sorted(names)


def build_llm(settings: LLMSettings | None = None):
    """Create a CrewAI ``LLM`` for the chosen provider (None when offline)."""
    settings = settings or get_llm_settings()
    if settings.offline:
        return None
    from crewai import LLM

    return LLM(model=settings.model, api_key=settings.api_key, temperature=0.1)
