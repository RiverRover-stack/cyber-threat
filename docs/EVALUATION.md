# Evaluation

## Method
- **Data:** 2,500 benign events + 196 injected attack events (6 incidents), seed 42, three hours of simulated time.
- **Detection (event level):** an event is "flagged" if it belongs to any alert; compared with the ground-truth `label`.
- **Classification:** per attack type, the share of its events covered by an alert of the correct type.
- **Retrieval:** hit-rate@k over 8 natural-language queries with an expected ATT&CK id (`evaluation.RAG_TEST_CASES`).
- **Ablation:** rules only vs rules + IsolationForest.

## Results (offline run, executed notebook)
| Configuration | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| Rules only | 196 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Rules + IsolationForest | 196 | 16 | 0 | 0.925 | 1.000 | 0.961 |

Per attack type: recall 1.00 for all six, each correctly classified.
RAG hit-rate@1 = hit-rate@3 = 0.88 (7/8) with the TF-IDF hashing embedder.

## Interpretation and caveats
- Rules reach perfect scores because thresholds were designed alongside the synthetic generator; this validates the
  pipeline mechanics, not real-world accuracy.
- The anomaly layer adds a few Low-severity alerts that need analyst review (2 alerts, 16 benign events) in exchange for
  catching attacks the rules do not describe. It never triggers automatic containment.
- Re-run with other seeds (`generate_logs(seed=...)`); precision of the full system stayed between 0.92 and 0.94 for seeds 1, 7, 42.
- Agent (LLM) output quality is not scored automatically; the live crew was not executed in the development
  environment (no API key), only constructed and unit-tested. Review `outputs/incident_report.md` manually.

## Reproduce
`pytest -q` and `jupyter nbconvert --to notebook --execute notebooks/Multi_Agent_Cyber_Threat_Detection.ipynb`.
