import pytest

from cyberthreat import config, crew

VARS = ["LLM_PROVIDER", "GROQ_API_KEY", "GEMINI_API_KEY", "OPENROUTER_API_KEY", "GROQ_MODEL", "GEMINI_MODEL", "OPENROUTER_MODEL"]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for v in VARS:
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setattr(config, "load_env", lambda: None)


def test_only_gemini_key_autodetects(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    s = config.get_llm_settings()
    assert s.provider == "gemini" and s.model == "gemini/gemini-2.0-flash"


def test_only_groq_key(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "k")
    assert config.get_llm_settings().provider == "groq"


def test_no_key_is_offline():
    assert config.get_llm_settings().offline


def test_explicit_offline_wins(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k"); monkeypatch.setenv("LLM_PROVIDER", "offline")
    assert config.get_llm_settings().offline


def test_model_name_in_provider_is_tolerated(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k"); monkeypatch.setenv("LLM_PROVIDER", "google/gemma-4-26B-A4B-it")
    s = config.get_llm_settings()
    assert s.provider == "gemini" and s.model == "gemini/gemma-4-26B-A4B-it" and "model ID" in s.note


def test_gemini_model_override_is_normalised(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k"); monkeypatch.setenv("GEMINI_MODEL", "models/gemma-4-26b-a4b-it")
    assert config.get_llm_settings().model == "gemini/gemma-4-26b-a4b-it"


def test_missing_key_hint(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k"); monkeypatch.setenv("LLM_PROVIDER", "groq")
    s = config.get_llm_settings()
    assert s.offline and "LLM_PROVIDER=gemini" in s.note


def test_live_crew_failure_falls_back_offline(monkeypatch):
    from cyberthreat.rag import Embedder, KnowledgeBase
    import tempfile

    monkeypatch.setenv("GEMINI_API_KEY", "k")
    crew.setup_context(kb=KnowledgeBase(persist_dir=tempfile.mkdtemp(), embedder=Embedder(prefer_transformer=False)))
    monkeypatch.setattr(crew, "build_crew", lambda llm: (_ for _ in ()).throw(RuntimeError("tool calling unsupported")))
    result = crew.run_pipeline()
    assert "# Security Incident Report" in result["report"]


def test_kickoff_works_inside_running_event_loop():
    """Jupyter/Colab run cells inside an event loop; CrewAI rejects sync execution there."""
    import asyncio

    class FakeCrew:
        def kickoff(self):
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                return "ok"
            raise RuntimeError("invoked synchronously from within a running event loop")

    async def main():
        return crew._kickoff(FakeCrew())

    assert asyncio.run(main()) == "ok"


def test_only_openrouter_key_autodetects(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    s = config.get_llm_settings()
    assert s.provider == "openrouter" and s.model == "openrouter/nvidia/nemotron-3.5-super-vl:free"


def test_openrouter_model_override_keeps_vendor_prefix(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "k"); monkeypatch.setenv("LLM_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_MODEL", "google/gemma-3-27b-it:free")
    assert config.get_llm_settings().model == "openrouter/google/gemma-3-27b-it:free"


def test_openrouter_model_name_as_provider(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "k"); monkeypatch.setenv("LLM_PROVIDER", "nvidia/nemotron-3.5-super-vl:free")
    s = config.get_llm_settings()
    assert s.provider == "openrouter" and s.model == "openrouter/nvidia/nemotron-3.5-super-vl:free"


def test_openrouter_llm_builds(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    llm = config.build_llm()
    assert llm is not None and "openrouter.ai" in str(llm.base_url)
