# User Guide

## 1. Getting a free API key (optional)
| Provider | Where | Env var |
|---|---|---|
| Groq | <https://console.groq.com> -> API Keys | `GROQ_API_KEY` |
| Google Gemini | <https://aistudio.google.com> -> Get API key | `GEMINI_API_KEY` |
Without a key the system runs in **offline mode**.

## 2. Google Colab
1. Open the notebook via the Colab badge in the README.
2. Left sidebar -> **Secrets** (key icon) -> add `GROQ_API_KEY` (or `GEMINI_API_KEY`) and toggle *Notebook access* on.
3. **Runtime -> Run all.** The first cell clones the repo and installs `requirements.txt` (about 2-3 minutes).
   If Colab asks to restart the session after installing, restart and run all again.

## 3. Local Jupyter
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt jupyter
cp .env.example .env   # edit: LLM_PROVIDER and key
jupyter notebook notebooks/Multi_Agent_Cyber_Threat_Detection.ipynb
```
Python 3.10-3.13 is supported (CrewAI requires < 3.14).

## 4. Running without a notebook
```python
import sys; sys.path.insert(0, "src")
from cyberthreat import crew
crew.setup_context(); out = crew.run_pipeline(); print(out["report"])
```
Outputs are written to `outputs/` (`incident_report.md`, `action_log.json`, `results.png`).

## 5. Using your own logs
Provide a DataFrame with columns `event_id, timestamp, source, src_ip, dst_ip, dst_port, host, user, action,
bytes_out, request, status, label` (`label` may be `"benign"` if unknown) and call `crew.setup_context(logs=df)`.
Adjust thresholds in `detection.py`.

## 6. Troubleshooting
| Symptom | Fix |
|---|---|
| "[mode] OFFLINE" although a key is set | Check the variable name, `LLM_PROVIDER`, and Colab *Notebook access* |
| `429` / rate-limit errors | Lower `max_rpm` in `crew.build_crew`, or wait; free tiers have tight limits |
| Embedder shows `hashing-tfidf` | `sentence-transformers` not installed or model download blocked; results still work, retrieval is slightly weaker |
| Chroma errors after upgrading | Delete the `chroma_db/` folder |
| Agent loops or ignores tools | Use a larger model (`GROQ_MODEL`), keep `temperature` low |
