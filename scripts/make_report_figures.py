"""Generate the diagrams used in docs/Project_Report.docx (Figures 3.1, 3.2, 4.2)."""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

OUT = Path(__file__).resolve().parents[1] / "docs" / "figures"
plt.rcParams["font.family"] = "DejaVu Serif"


def box(ax, x, y, w, h, text, fc="#eef2f7", ec="#1f3a5f", fs=9, bold=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08", fc=fc, ec=ec, lw=1.3))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, weight="bold" if bold else "normal")


def arrow(ax, a, b, both=False, rad=0.0):
    ax.add_patch(FancyArrowPatch(a, b, arrowstyle="<|-|>" if both else "-|>", mutation_scale=13, lw=1.3,
                                 color="#333", connectionstyle=f"arc3,rad={rad}"))


def architecture():
    fig, ax = plt.subplots(figsize=(10, 5.6)); ax.set_xlim(0, 10); ax.set_ylim(0, 5.6); ax.axis("off")
    box(ax, 0.2, 4.3, 2.3, 0.9, "Security logs\n(auth / firewall / web)", "#fdf3e1", "#8a5a00")
    box(ax, 3.2, 4.3, 3.0, 0.9, "Detection layer\nrules + IsolationForest", "#fdf3e1", "#8a5a00")
    box(ax, 7.0, 4.3, 2.8, 0.9, "Alerts\n(type, severity, MITRE id)", "#fdf3e1", "#8a5a00")
    arrow(ax, (2.5, 4.75), (3.2, 4.75)); arrow(ax, (6.2, 4.75), (7.0, 4.75))
    ax.text(2.7, 3.58, "CrewAI crew (sequential process)", fontsize=10, weight="bold", color="#1f3a5f")
    ys = 2.45
    box(ax, 0.2, ys, 2.1, 1.0, "Agent 1\nLog Analyst /\nThreat Detector", bold=True)
    box(ax, 2.7, ys, 2.1, 1.0, "Agent 2\nThreat Intelligence\nAnalyst", bold=True)
    box(ax, 5.2, ys, 2.1, 1.0, "Agent 3\nIncident\nResponder", bold=True)
    box(ax, 7.7, ys, 2.1, 1.0, "Agent 4\nSecurity Report\nWriter", bold=True)
    for x in (2.3, 4.8, 7.3):
        arrow(ax, (x, ys + 0.5), (x + 0.4, ys + 0.5))
    ax.plot([8.4, 8.4, 1.25], [4.3, 3.95, 3.95], color="#333", lw=1.3)  # elbow: alerts -> agent 1
    arrow(ax, (1.25, 3.95), (1.25, 3.45))
    box(ax, 2.2, 0.6, 3.6, 1.0, "RAG knowledge base (ChromaDB)\nATT&CK - CVEs - IR playbooks", "#e8f5e9", "#1b5e20")
    arrow(ax, (3.75, 2.45), (3.4, 1.6), both=True); arrow(ax, (6.25, 2.45), (5.0, 1.6), both=True)
    box(ax, 6.4, 0.6, 3.4, 1.0, "Outputs: incident report (.md)\nsimulated action log (.json)", "#fdecea", "#8e1b10")
    arrow(ax, (8.75, 2.45), (8.4, 1.6)); arrow(ax, (6.25, 2.45), (6.9, 1.6), rad=0.1)
    ax.text(5.0, 0.15, "Response actions are simulated and restricted to an allow-list", ha="center", fontsize=8.5, style="italic")
    fig.savefig(OUT / "fig_architecture.png", dpi=170, bbox_inches="tight"); plt.close(fig)


def rag():
    fig, ax = plt.subplots(figsize=(10, 4.2)); ax.set_xlim(0, 10); ax.set_ylim(0, 4.2); ax.axis("off")
    ax.text(0.1, 3.85, "Indexing (once)", fontsize=10, weight="bold", color="#1b5e20")
    box(ax, 0.1, 2.7, 2.0, 0.9, "Knowledge files\nJSON + Markdown", "#e8f5e9", "#1b5e20")
    box(ax, 2.6, 2.7, 2.0, 0.9, "Chunking\n(1 per technique /\nCVE / playbook section)", "#e8f5e9", "#1b5e20", fs=8)
    box(ax, 5.1, 2.7, 2.0, 0.9, "Embedding\nMiniLM or TF-IDF\nhashing", "#e8f5e9", "#1b5e20", fs=8.5)
    box(ax, 7.6, 2.7, 2.2, 0.9, "ChromaDB\n(cosine, metadata)", "#e8f5e9", "#1b5e20")
    for x in (2.1, 4.6, 7.1): arrow(ax, (x, 3.15), (x + 0.5, 3.15))
    ax.text(0.1, 1.95, "Retrieval (per alert)", fontsize=10, weight="bold", color="#1f3a5f")
    box(ax, 0.1, 0.7, 2.0, 0.9, "Alert text\n(type + evidence)", "#eef2f7")
    box(ax, 2.6, 0.7, 2.0, 0.9, "Embed query", "#eef2f7")
    box(ax, 5.1, 0.7, 2.0, 0.9, "Top-k search\n+ doc_type filter", "#eef2f7")
    box(ax, 7.6, 0.7, 2.2, 0.9, "Context to agent\n(technique / playbook)", "#eef2f7")
    for x in (2.1, 4.6, 7.1): arrow(ax, (x, 1.15), (x + 0.5, 1.15))
    arrow(ax, (8.7, 2.7), (6.5, 1.6), rad=-0.15)
    fig.savefig(OUT / "fig_rag.png", dpi=170, bbox_inches="tight"); plt.close(fig)


def metrics():
    import numpy as np

    labels = ["Precision", "Recall", "F1-score"]
    rules, full = [1.0, 1.0, 1.0], [0.925, 1.0, 0.961]
    x = np.arange(3); w = 0.36
    fig, ax = plt.subplots(figsize=(6.6, 3.8))
    b1 = ax.bar(x - w / 2, rules, w, label="Rules only", color="#1f3a5f")
    b2 = ax.bar(x + w / 2, full, w, label="Rules + IsolationForest", color="#c0392b")
    for bars in (b1, b2):
        for r in bars: ax.text(r.get_x() + r.get_width() / 2, r.get_height() + 0.01, f"{r.get_height():.3f}", ha="center", fontsize=8.5)
    ax.set_xticks(x, labels); ax.set_ylim(0.8, 1.06); ax.set_ylabel("Score"); ax.legend(loc="upper center", bbox_to_anchor=(0.5, 1.14), ncol=2, fontsize=8.5, frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.savefig(OUT / "fig_metrics.png", dpi=170, bbox_inches="tight"); plt.close(fig)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    architecture(); rag(); metrics()
    print("figures written to", OUT)
