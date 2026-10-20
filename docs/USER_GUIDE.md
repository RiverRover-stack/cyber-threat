# User Guide

## 1. Getting a free API key (optional)
| Provider | Where | Env var |
|---|---|---|
| Groq | <https://console.groq.com> -> API Keys | `GROQ_API_KEY` |
| Google Gemini | <https://aistudio.google.com> -> Get API key | `GEMINI_API_KEY` |
| OpenRouter | <https://openrouter.ai/keys> | `OPENROUTER_API_KEY` |
Without a key the system runs in **offline mode**.

## 2. Google Colab
The notebook is self-contained: it installs its own dependencies and embeds all code and knowledge-base files.
1. Upload `notebooks/Multi_Agent_Cyber_Threat_Detection.ipynb` (File -> Upload notebook), or open it from GitHub.
2. Left sidebar -> **Secrets** (key icon) -> add `GEMINI_API_KEY` (or `GROQ_API_KEY`) and toggle *Notebook access* on.
   The provider is auto-detected from the key; set a `LLM_PROVIDER` secret (`gemini`/`groq`/`offline`) only to force one.
   `LLM_PROVIDER` must be a provider name, **not** a model name.
3. OpenRouter: add the `OPENROUTER_API_KEY` secret; the default model is `nvidia/nemotron-3.5-super-vl:free`. To change it set
   `os.environ["OPENROUTER_MODEL"] = "<vendor>/<model>[:free]"`. Free models are rate limited (HTTP 429) and not all support tool
   calling; if the crew fails the notebook falls back to offline mode and prints why.
4. Optional Gemini model choice: in the config cell set `os.environ["GEMINI_MODEL"] = "gemini/<model-id>"`. The notebook's
   model-list cell prints the IDs your key can use (including Gemma models on AI Studio).
5. **Runtime -> Run all** (installing takes about 2-3 minutes). If Colab asks to restart after installing, restart and run all again.
6. Models without tool-calling support make the live crew fail; the notebook then prints the reason and falls back to offline mode.

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
| `[mode] OFFLINE` although a key is set | Check the secret name (`GEMINI_API_KEY`/`GROQ_API_KEY`) and that Colab *Notebook access* is on; the `Note:` line printed by the config cell says what was missing |
| Live crew fails then falls back to offline | Read the printed `[warning]`; try `GEMINI_MODEL=gemini/gemini-2.0-flash` (some Gemma models lack tool calling) |
| `429` / rate-limit errors | Lower `max_rpm` in `crew.build_crew`, or wait; free tiers have tight limits |
| Embedder shows `hashing-tfidf` | `sentence-transformers` not installed or model download blocked; results still work, retrieval is slightly weaker |
| Chroma errors after upgrading | Delete the `chroma_db/` folder |
| Agent loops or ignores tools | Use a larger model (`GROQ_MODEL`), keep `temperature` low |
