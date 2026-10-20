# RAG Pipeline

## Corpus (`knowledge_base/`)
| File | Content | Chunking |
|---|---|---|
| `mitre_attack_techniques.json` | 10 ATT&CK techniques: id, name, tactic, description, mitigation | 1 chunk per technique |
| `cve_samples.json` | 5 well-known CVEs mapped to techniques | 1 chunk per CVE |
| `playbooks/*.md` | 6 IR playbooks (indicators, containment, eradication, post-incident) | 1 chunk per `##` section, title prepended |
| `ioc_feed.json` | Small simulated IOC feed (not embedded; used by `ioc_lookup`) | - |

Every chunk carries metadata: `doc_type` (`mitre`/`cve`/`playbook`), `mitre_id`, `title` (and `playbook` stem).

## Embeddings
- Preferred: `sentence-transformers/all-MiniLM-L6-v2` (384-d, normalised).
- Fallback: `HashingVectorizer` (1024-d, uni+bi-grams, English stop words, L2-normalised) when the transformer is
  unavailable (not installed or no network).
`KnowledgeBase.embedder.name` reports which is active.

## Store and retrieval
ChromaDB `PersistentClient` (`chroma_db/`, git-ignored), cosine space. `search(query, k, doc_type)` filters by
`doc_type` through Chroma's `where` clause and returns `score = 1 - cosine_distance`.
`get_playbook(stem)` returns all chunks of one playbook in order so the responder sees complete containment steps.
The collection is rebuilt on each `KnowledgeBase()` (cheap at this size); pass `rebuild=False` to reuse.

## How retrieval is used
- **Intel agent:** query = attack type + alert evidence -> ATT&CK technique and CVE context.
- **Responder:** query = attack type -> best playbook -> *Containment* steps are converted into simulated actions.
  This keeps responses grounded in the knowledge base instead of hard-coded per attack.

## Extending the knowledge base
Add a JSON entry or a Markdown playbook (first line `# Title (TXXXX)`, sections `## Detection indicators`,
`## Containment`, ...). It is picked up automatically on the next build.
