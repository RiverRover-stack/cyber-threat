import pytest

from cyberthreat import crew, tools
from cyberthreat.rag import Embedder, KnowledgeBase


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    kb = KnowledgeBase(persist_dir=tmp_path_factory.mktemp("chroma"), embedder=Embedder(prefer_transformer=False))
    crew.setup_context(kb=kb)
    return crew.run_offline()


def test_report_generated(result):
    assert "# Security Incident Report" in result["report"]
    assert len(result["alerts"]) >= 6


def test_actions_simulated_and_valid(result):
    assert result["actions"]
    assert all(a["mode"] == "SIMULATED" and a["action"] in tools.ALLOWED_ACTIONS for a in result["actions"])


def test_containment_targets_are_correct(result):
    targets = {a["target"] for a in result["actions"]}
    assert {"185.220.101.7", "10.0.5.23"} <= targets  # block C2 IP + isolate host
    assert "10.0.3.40" in targets and "bob" in targets  # exfil host isolated, escalating account disabled
    assert all(not a["target"].startswith("10.") for a in result["actions"] if a["action"] == "block_ip")


def test_invalid_action_rejected():
    assert tools.take_response_action("rm_rf", "x", "y").startswith("REJECTED")


def test_crew_builds_without_llm_call():
    c = crew.build_crew(llm=None)
    assert len(c.agents) == 4 and len(c.tasks) == 4
