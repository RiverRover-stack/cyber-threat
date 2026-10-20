"""Evaluation: detection precision/recall/F1 (event + incident level), RAG hit-rate, plots."""
from __future__ import annotations

import pandas as pd

from .data_generator import ATTACK_TYPES
from .detection import Alert

RAG_TEST_CASES = [
    ("many failed ssh logins from one ip", "T1110"),
    ("attacker scanning many ports on a server", "T1046"),
    ("union select in web request parameter", "T1190"),
    ("periodic small connections to external server at fixed interval", "T1071"),
    ("huge outbound data upload to unknown destination", "T1041"),
    ("chmod u+s and sudoers modification", "T1548"),
    ("login success after repeated password failures", "T1110"),
    ("network service discovery probing open ports", "T1046"),
]


def event_metrics(df: pd.DataFrame, alerts: list[Alert]) -> dict:
    """Binary (attack vs benign) event-level metrics."""
    flagged = {e for a in alerts for e in a.event_ids}
    truth = set(df[df.label != "benign"].event_id)
    tp, fp, fn = len(flagged & truth), len(flagged - truth), len(truth - flagged)
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    tn = len(df) - tp - fp - fn
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=round(p, 3), recall=round(r, 3), f1=round(f1, 3))


def per_attack_report(df: pd.DataFrame, alerts: list[Alert]) -> pd.DataFrame:
    """Per-attack-type event recall and whether the incident was typed correctly."""
    rows = []
    for t in ATTACK_TYPES:
        ev = set(df[df.label == t].event_id)
        typed = {e for a in alerts if a.attack_type == t for e in a.event_ids}
        anyd = {e for a in alerts for e in a.event_ids}
        rows.append(dict(attack_type=t, events=len(ev), detected_any=len(ev & anyd),
                         correctly_classified=len(ev & typed), recall=round(len(ev & typed) / len(ev), 3)))
    return pd.DataFrame(rows)


def plot_results(df: pd.DataFrame, alerts: list[Alert], path=None):
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(1, 3, figsize=(17, 4.5))
    df.label.value_counts().drop("benign", errors="ignore").plot.barh(ax=ax[0], color="#c0392b")
    ax[0].set_title("Injected attack events (ground truth)")
    sev = pd.Series([a.severity for a in alerts]).value_counts().reindex(["Critical", "High", "Medium", "Low"]).fillna(0)
    sev.plot.bar(ax=ax[1], color=["#7b241c", "#e67e22", "#f1c40f", "#3498db"])
    ax[1].set_title("Alerts by severity"); ax[1].tick_params(axis="x", rotation=0)
    ts = df.set_index("timestamp").assign(a=lambda x: (x.label != "benign").astype(int)).a.resample("10min").sum()
    ts.plot(ax=ax[2], color="#c0392b", marker="o"); ax[2].set_title("Attack events over time (10-min bins)")
    plt.tight_layout()
    if path:
        fig.savefig(path, dpi=130)
    return fig
