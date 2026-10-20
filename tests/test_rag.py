import pytest

from cyberthreat.evaluation import RAG_TEST_CASES
from cyberthreat.rag import Embedder, KnowledgeBase, load_chunks, retrieval_hit_rate


@pytest.fixture(scope="module")
def kb(tmp_path_factory):
    return KnowledgeBase(persist_dir=tmp_path_factory.mktemp("chroma"), embedder=Embedder(prefer_transformer=False))


def test_chunks_loaded():
    types = {c.metadata["doc_type"] for c in load_chunks()}
    assert types == {"mitre", "cve", "playbook"}


def test_hit_rate(kb):
    assert retrieval_hit_rate(kb, RAG_TEST_CASES, k=3) >= 0.85


def test_doc_type_filter(kb):
    assert all(r["metadata"]["doc_type"] == "playbook" for r in kb.search("block ip", k=3, doc_type="playbook"))
