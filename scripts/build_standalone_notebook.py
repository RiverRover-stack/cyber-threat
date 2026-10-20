"""Build a single self-contained notebook from src/cyberthreat and knowledge_base.

Usage:  python scripts/build_standalone_notebook.py
The result (notebooks/Multi_Agent_Cyber_Threat_Detection.ipynb) needs no repo checkout: it embeds the
knowledge base, installs its own dependencies and defines every module inline.
"""
import re
from pathlib import Path

import nbformat as nbf

ROOT = Path(__file__).resolve().parents[1]
SRC, KB = ROOT / "src" / "cyberthreat", ROOT / "knowledge_base"
OUT = ROOT / "notebooks" / "Multi_Agent_Cyber_Threat_Detection.ipynb"

md = lambda s: nbf.v4.new_markdown_cell(s.strip())  # noqa: E731
code = lambda s: nbf.v4.new_code_cell(s.strip())  # noqa: E731


def inline(name: str) -> str:
    """Return a module's source with package-relative imports removed (all modules share one namespace)."""
    s = (SRC / f"{name}.py").read_text()
    s = re.sub(r"^from __future__ import annotations\n+", "", s, flags=re.M)
    s = re.sub(r"^[ \t]*from \.\w* import \([^)]*\)\n", "", s, flags=re.M)
    s = re.sub(r"^[ \t]*from \.\w* import .*\n", "", s, flags=re.M)
    s = re.sub(r"^from \. import \w+\n", "", s, flags=re.M)
    if name == "crew":
        s = s.replace("tools.", "")
    if name == "config":
        s = s.replace("ROOT = Path(__file__).resolve().parents[2]", "ROOT = Path.cwd()")
    return s.strip() + "\n"


def kb_cell() -> str:
    files = {p.relative_to(KB).as_posix(): p.read_text() for p in sorted(KB.rglob("*")) if p.is_file()}
    body = ",\n".join(f'    "{k}": r\'\'\'{v.strip()}\'\'\'' for k, v in files.items())
    return (f"KB_FILES = {{\n{body},\n}}\n\n"
            "for rel, text in KB_FILES.items():\n"
            "    path = KB_DIR / rel\n"
            "    path.parent.mkdir(parents=True, exist_ok=True)\n"
            "    path.write_text(text)\n"
            "print(f'Wrote {len(KB_FILES)} knowledge-base files to {KB_DIR}')")


cells = [
md("""
# Multi-Agent Cyber-Threat Detection and Response System Using CrewAI and RAG

**Self-contained notebook** - everything (code and knowledge base) is inside this file; no repository is needed.
Runs in Google Colab or local Jupyter.

Pipeline:
1. Generate labelled security telemetry (auth / firewall / web logs) with six injected attacks
2. Detect threats with rules + IsolationForest
3. Build a **RAG** knowledge base (MITRE ATT&CK, CVEs, response playbooks) in ChromaDB
4. Run a **CrewAI** crew: Log Analyst -> Threat-Intel Analyst -> Incident Responder -> Report Writer
5. Evaluate detection and retrieval quality and produce an incident report

**LLM:** add a free `GEMINI_API_KEY` (Google AI Studio) or `GROQ_API_KEY` as a Colab secret (key icon, switch on *Notebook access*).
With no key the notebook runs in **offline mode** (same tools and RAG, deterministic logic).
Source of truth: the `src/cyberthreat` package in the GitHub repo; this notebook is generated from it.
"""),
md("## 1. Install dependencies\nOnly installs what is missing (about 1-3 minutes on a fresh Colab VM)."),
code("""
import importlib.util, subprocess, sys

REQUIRED = {"crewai": "crewai>=1.0", "chromadb": "chromadb>=0.5", "sklearn": "scikit-learn", "litellm": "litellm",
            "google.genai": "google-genai", "dotenv": "python-dotenv", "matplotlib": "matplotlib", "pandas": "pandas"}
missing = [pkg for mod, pkg in REQUIRED.items() if importlib.util.find_spec(mod.split('.')[0]) is None]
if missing:
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", *missing], check=True)
print("Dependencies ready." if not missing else f"Installed: {missing}")
"""),
md("## 2. Configuration\nPaths, `.env` / Colab-secret loading and LLM selection. The provider is auto-detected from whichever API key is set."),
code("import json, re, os\nfrom dataclasses import dataclass, field, asdict\nfrom datetime import datetime\nfrom pathlib import Path\n\n"
     "import numpy as np\nimport pandas as pd\nfrom sklearn.ensemble import IsolationForest\nfrom crewai.tools import BaseTool\n"
     "from pydantic import BaseModel, Field\nimport warnings; warnings.filterwarnings('ignore')\n"
     "pd.set_option('display.width', 200); pd.set_option('display.max_colwidth', 90)"),
code(inline("config")),
md("## 3. Embedded knowledge base\nMITRE ATT&CK techniques, CVE samples, an IOC feed and six incident-response playbooks are stored here as text and written to `knowledge_base/` so the RAG layer can index them. Edit or add entries to extend the system."),
code(kb_cell()),
md("## 4. Security telemetry generator\nThree log sources in one schema; `label` is ground truth used only for evaluation."),
code(inline("data_generator")),
md("## 5. Detection layer\nRule-based detectors (thresholds, signatures, beacon periodicity) plus IsolationForest for unexplained outliers."),
code(inline("detection")),
md("## 6. RAG layer\nChunking, embeddings (MiniLM when available, TF-IDF hashing otherwise) and a ChromaDB vector store."),
code(inline("rag")),
md("## 7. Agent tools\nPlain functions plus CrewAI `BaseTool` wrappers. Response actions are **simulated** and restricted to an allow-list."),
code(inline("tools")),
md("## 8. Agents and tasks"),
code(inline("agents")),
code(inline("tasks")),
md("## 9. Crew orchestration\n`run_pipeline()` runs the CrewAI crew when an API key exists, otherwise (or if the live crew fails) the deterministic offline pipeline."),
code(inline("crew")),
md("## 10. Evaluation helpers"),
code(inline("evaluation")),
md("---\n# Run the system"),
md("""
## 11. Choose the LLM
Add `GEMINI_API_KEY` (or `GROQ_API_KEY`) as a Colab secret with **Notebook access** on. Optional overrides (uncomment):

- `LLM_PROVIDER` = `gemini`, `groq` or `offline` (leave unset to auto-detect from the key)
- `GEMINI_MODEL` = `gemini/<model-id>` - run the model-list cell below to see valid IDs for your key (e.g. a Gemma model)
"""),
code("""
# os.environ["LLM_PROVIDER"] = "gemini"
# os.environ["GEMINI_MODEL"] = "gemini/<model-id>"      # e.g. a Gemma model id from the list below

settings = get_llm_settings()
if settings.note:
    print("Note:", settings.note)
print(f"Provider: {settings.provider} | model: {settings.model}")
print("Mode:", "OFFLINE (deterministic)" if settings.offline else "LIVE CrewAI crew")
"""),
code("""
# Which models can my Gemini / AI Studio key call? (skipped when no Gemini key is set)
if os.environ.get("GEMINI_API_KEY"):
    try:
        print("\\n".join(list_gemini_models()))
    except Exception as e:
        print("Could not list models:", e)
else:
    print("No GEMINI_API_KEY set - skipping.")
"""),
md("## 12. Generate telemetry"),
code("""
logs = generate_logs()
print(logs.shape)
print(logs.label.value_counts().to_string())
logs.sample(6, random_state=1)
"""),
md("## 13. Detect threats"),
code("""
alerts = detect_all(logs)
alerts_to_frame(alerts)
"""),
md("## 14. Build the RAG knowledge base"),
code("""
kb = KnowledgeBase()
print("Embedder:", kb.embedder.name, "| chunks:", kb.col.count(),
      "|", pd.Series([c.metadata['doc_type'] for c in load_chunks()]).value_counts().to_dict())

for q in ["periodic small connections to an external server", "huge upload to unknown host"]:
    print(f"\\nQuery: {q}")
    for h in kb.search(q, k=2):
        print(f"  {h['score']:.2f}  [{h['metadata']['doc_type']}] {h['metadata']['title']}")
"""),
md("## 15. Run the multi-agent system"),
code("""
setup_context(logs=logs, kb=kb)
result = run_pipeline()
print(f"{len(result['alerts'])} alerts, {len(result['actions'])} simulated actions")
"""),
md("### Incident report"),
code("""
from IPython.display import Markdown
Markdown(result["report"])
"""),
md("### Simulated response actions"),
code("""pd.DataFrame(result["actions"])[["action", "target", "reason", "mode"]]"""),
md("## 16. Evaluation"),
code("""
full, rules_only = event_metrics(logs, result["alerts"]), event_metrics(logs, rule_detect(logs))
print(pd.DataFrame({"rules + anomaly (full)": full, "rules only": rules_only}).T)
per_attack_report(logs, result["alerts"])
"""),
code("""
for k in (1, 3):
    print(f"RAG hit-rate@{k}: {retrieval_hit_rate(kb, RAG_TEST_CASES, k):.2f}  ({len(RAG_TEST_CASES)} queries)")
"""),
code("""
OUTPUT_DIR.mkdir(exist_ok=True)
plot_results(logs, result["alerts"], OUTPUT_DIR / "results.png");
"""),
md("""
## 17. Conclusion

- Every injected incident is detected and typed correctly and mapped to the right ATT&CK technique via RAG.
- Responses are derived from retrieved **playbooks** and restricted to a simulated allow-list.
- The same tools run under a live CrewAI crew (Gemini / Gemma / Groq) when an API key is available; if the live crew fails
  the notebook falls back to offline mode and says why.

*Limitations:* synthetic data with tuned thresholds, small knowledge base, simulated actions. See the repo's `docs/`.
"""),
]
nb = nbf.v4.new_notebook(cells=cells)
nb.metadata["kernelspec"] = {"display_name": "Python 3", "language": "python", "name": "python3"}
nbf.write(nb, OUT)
print("Wrote", OUT)
