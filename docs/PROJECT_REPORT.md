# Project Report: Multi-Agent Cyber-Threat Detection and Response System Using CrewAI and RAG

## Abstract
Security teams face alert fatigue and slow, manual enrichment and response. This project builds a multi-agent system in
which specialised LLM agents (CrewAI) collaborate to detect threats in logs, enrich them with Retrieval-Augmented
Generation over MITRE ATT&CK, CVE and incident-response playbook knowledge, execute simulated containment, and write an
incident report. On a labelled synthetic dataset containing six attack types, the hybrid detector found all attack
events (recall 1.00), correctly classified every incident, and RAG retrieved the right ATT&CK technique for 7 of 8 test
queries even with a lightweight embedding fallback.

## 1. Problem statement
SOC analysts triage thousands of alerts, then manually look up techniques and playbooks before acting. Pure ML detectors
give no explanation or response; standalone LLMs hallucinate without grounding. A grounded, tool-using, multi-agent
approach can automate triage-to-response while remaining auditable.

## 2. Objectives
1. Detect common attacks in heterogeneous logs with a hybrid rules + anomaly detector.
2. Ground enrichment and response in a retrievable knowledge base (RAG).
3. Coordinate specialised agents with CrewAI using custom tools.
4. Keep responses safe (simulated, allow-listed) and the system reproducible and runnable without paid APIs.
5. Evaluate detection and retrieval quantitatively.

## 3. Methodology
- **Data:** synthetic auth, firewall and web logs with injected SSH brute force, port scan, SQL injection, C2 beaconing,
  data exfiltration and privilege escalation (see `data_generator.py`).
- **Detection:** rule/threshold detectors per attack plus IsolationForest over per-source 5-minute behaviour features
  (event count, failures, distinct ports, bytes out, distinct targets).
- **RAG:** curated ATT&CK/CVE/playbook corpus -> chunks -> embeddings -> ChromaDB cosine search with metadata filters.
- **Agents:** Detector -> Intel Analyst -> Responder -> Report Writer in a sequential CrewAI process; Groq or Gemini LLM.
- **Offline mode:** identical tools executed deterministically when no key is available.
- **Evaluation:** event-level precision/recall/F1, per-attack recall, hit-rate@k, rules-only ablation.

## 4. Implementation summary
See [ARCHITECTURE.md](ARCHITECTURE.md), [AGENTS_AND_TOOLS.md](AGENTS_AND_TOOLS.md) and [RAG_PIPELINE.md](RAG_PIPELINE.md).
Stack: Python, CrewAI, LiteLLM (Groq / Gemini), ChromaDB, sentence-transformers, scikit-learn, pandas, matplotlib, pytest.

## 5. Results
See [EVALUATION.md](EVALUATION.md): recall 1.00; precision 1.00 (rules) / 0.93 (rules + anomaly); RAG hit-rate@3 0.88.
Containment actions derived from playbooks were correct for all incidents (external attackers blocked, infected
internal hosts isolated, compromised accounts disabled).

## 6. Limitations
Synthetic data and tuned thresholds; small knowledge base; benign periodic traffic can imitate beaconing; actions are
simulated; LLM non-determinism and free-tier rate limits; live-LLM crew quality not automatically scored.

## 7. Future work
Public datasets (CICIDS2017, UNSW-NB15, Zeek/Suricata), full ATT&CK STIX ingestion, hybrid BM25 + dense retrieval and
re-ranking, human-in-the-loop approval for actions, SIEM/SOAR integration, streaming detection, and LLM-as-judge scoring.

## 8. Conclusion
A grounded multi-agent architecture can automate the detect-enrich-respond-report loop with transparent, auditable
steps. Separating deterministic detection from agentic reasoning keeps the system cheap, testable and runnable offline.

## References
1. CrewAI documentation - https://docs.crewai.com
2. MITRE ATT&CK - https://attack.mitre.org
3. Lewis et al., "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks", NeurIPS 2020.
4. Liu, Ting, Zhou, "Isolation Forest", IEEE ICDM 2008.
5. ChromaDB - https://docs.trychroma.com
6. Reimers & Gurevych, "Sentence-BERT", EMNLP 2019.
7. NIST SP 800-61 Rev. 2, Computer Security Incident Handling Guide.
