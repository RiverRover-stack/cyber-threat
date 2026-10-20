"""Retrieval-Augmented Generation layer: knowledge-base loading, chunking, embedding, ChromaDB search."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

import numpy as np

from .config import CHROMA_DIR, KB_DIR


@dataclass
class Chunk:
    id: str
    text: str
    metadata: dict


class Embedder:
    """Sentence-transformers (all-MiniLM-L6-v2) when available, else a TF-IDF-style hashing embedding."""

    def __init__(self, prefer_transformer: bool = True):
        self.name = "hashing-tfidf"
        self._st = None
        if prefer_transformer:
            try:
                from sentence_transformers import SentenceTransformer

                self._st = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
                self.name = "all-MiniLM-L6-v2"
            except Exception:
                self._st = None
        if self._st is None:
            from sklearn.feature_extraction.text import HashingVectorizer

            self._hv = HashingVectorizer(n_features=1024, alternate_sign=False, norm="l2",
                                         ngram_range=(1, 2), stop_words="english")

    def encode(self, texts: list[str]) -> list[list[float]]:
        if self._st is not None:
            return self._st.encode(texts, normalize_embeddings=True).tolist()
        return self._hv.transform(texts).toarray().astype(float).tolist()


def load_chunks(kb_dir=KB_DIR) -> list[Chunk]:
    chunks: list[Chunk] = []
    for t in json.load(open(kb_dir / "mitre_attack_techniques.json")):
        text = (f"{t['id']} {t['name']} ({t['tactic']}). {t['description']} Mitigation: {t['mitigation']}")
        chunks.append(Chunk(f"mitre-{t['id']}", text, {"doc_type": "mitre", "mitre_id": t["id"], "title": t["name"]}))
    for c in json.load(open(kb_dir / "cve_samples.json")):
        chunks.append(Chunk(f"cve-{c['id']}", f"{c['id']}: {c['description']} Remediation: {c['remediation']}",
                            {"doc_type": "cve", "mitre_id": c["mitre_id"], "title": c["id"]}))
    for p in sorted((kb_dir / "playbooks").glob("*.md")):
        raw = p.read_text()
        title = raw.splitlines()[0].lstrip("# ").strip()
        m = re.search(r"T\d{4}", title)
        mid = m.group(0) if m else ""
        for i, sec in enumerate(re.split(r"\n(?=## )", raw)[1:] or [raw]):
            chunks.append(Chunk(f"playbook-{p.stem}-{i}", f"{title}\n{sec.strip()}",
                                {"doc_type": "playbook", "mitre_id": mid, "title": title, "playbook": p.stem}))
    return chunks


class KnowledgeBase:
    """ChromaDB-backed vector store with cosine similarity search."""

    def __init__(self, persist_dir=None, embedder: Embedder | None = None, rebuild: bool = True):
        import chromadb

        self.embedder = embedder or Embedder()
        self.client = chromadb.PersistentClient(path=str(persist_dir or CHROMA_DIR))
        name = "security_kb"
        if rebuild:
            try:
                self.client.delete_collection(name)
            except Exception:
                pass
        self.col = self.client.get_or_create_collection(name, metadata={"hnsw:space": "cosine"})
        if self.col.count() == 0:
            chunks = load_chunks()
            self.col.add(ids=[c.id for c in chunks], documents=[c.text for c in chunks],
                         metadatas=[c.metadata for c in chunks], embeddings=self.embedder.encode([c.text for c in chunks]))

    def search(self, query: str, k: int = 3, doc_type: str | None = None) -> list[dict]:
        res = self.col.query(query_embeddings=self.embedder.encode([query]), n_results=k,
                             where={"doc_type": doc_type} if doc_type else None)
        return [{"id": i, "text": d, "metadata": m, "score": round(1 - float(dist), 3)}
                for i, d, m, dist in zip(res["ids"][0], res["documents"][0], res["metadatas"][0], res["distances"][0])]


    def get_playbook(self, stem: str) -> str:
        """Return a full playbook (all its chunks in order) by file stem."""
        res = self.col.get(where={"playbook": stem})
        return "\n\n".join(d for _, d in sorted(zip(res["ids"], res["documents"])))


def retrieval_hit_rate(kb: KnowledgeBase, cases: list[tuple[str, str]], k: int = 3) -> float:
    """Fraction of (query, expected_mitre_id) pairs whose top-k results contain the expected technique."""
    hits = sum(any(r["metadata"].get("mitre_id") == exp for r in kb.search(q, k)) for q, exp in cases)
    return hits / len(cases)
