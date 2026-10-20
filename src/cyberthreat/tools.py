"""Agent tools. Plain functions hold the logic; thin CrewAI ``BaseTool`` wrappers expose them to agents.

All tools read/write a shared :class:`SecurityContext` (logs, alerts, knowledge base, simulated action log).
Response actions are SIMULATED - they are only recorded, never executed.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime

import pandas as pd
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from .config import KB_DIR
from .detection import Alert, anomaly_detect, rule_detect
from .rag import KnowledgeBase

ALLOWED_ACTIONS = {"block_ip", "isolate_host", "disable_account", "reset_credentials", "enable_waf_rule", "create_ticket"}


@dataclass
class SecurityContext:
    logs: pd.DataFrame | None = None
    kb: KnowledgeBase | None = None
    alerts: list[Alert] = field(default_factory=list)
    actions: list[dict] = field(default_factory=list)
    ioc_feed: dict = field(default_factory=dict)

    def __post_init__(self):
        self.ioc_feed = {i["ip"]: i for i in json.load(open(KB_DIR / "ioc_feed.json"))}


CTX = SecurityContext()  # shared by all tools; set via crew.setup_context()


# ---- plain functions -------------------------------------------------------------------------------------------
def analyze_logs() -> str:
    CTX.alerts = rule_detect(CTX.logs)
    return _summarise(CTX.alerts)


def detect_anomalies() -> str:
    covered = {e for a in CTX.alerts for e in a.event_ids}
    extra = anomaly_detect(CTX.logs, exclude_events=covered)
    for a in extra:
        a.alert_id = f"ALERT-{len(CTX.alerts) + 1:03d}"
        CTX.alerts.append(a)
    return _summarise(extra) if extra else "No additional anomalies beyond rule-based alerts."


def _summarise(alerts: list[Alert]) -> str:
    return json.dumps([{k: v for k, v in a.to_dict().items() if k not in ("event_ids", "first_seen", "last_seen")}
                       for a in alerts], indent=1)


def search_threat_intel(query: str) -> str:
    hits = CTX.kb.search(query, k=2, doc_type="mitre") + CTX.kb.search(query, k=1, doc_type="cve")
    return "\n".join(f"[{h['metadata']['title']} | {h['metadata'].get('mitre_id','')} | score {h['score']}] {h['text']}"
                     for h in hits)


def lookup_ioc(ip: str) -> str:
    feed = CTX.ioc_feed.get(ip)
    ev = CTX.logs[CTX.logs.src_ip.eq(ip) | CTX.logs.dst_ip.eq(ip)]
    internal = ip.startswith("10.")
    return json.dumps({"ip": ip, "internal": internal, "threat_feed_match": feed or "none",
                       "events_in_logs": int(len(ev)),
                       "first_seen": str(ev.timestamp.min()) if len(ev) else None})


def search_playbook(query: str) -> str:
    top = CTX.kb.search(query, k=1, doc_type="playbook")[0]
    return CTX.kb.get_playbook(top["metadata"]["playbook"])


def take_response_action(action: str, target: str, reason: str) -> str:
    if action not in ALLOWED_ACTIONS:
        return f"REJECTED: '{action}' not in {sorted(ALLOWED_ACTIONS)}"
    if any(a["action"] == action and a["target"] == target for a in CTX.actions):
        return f"SKIPPED: {action} on {target} already recorded"
    rec = {"time": datetime.now().isoformat(timespec="seconds"), "action": action, "target": target,
           "reason": reason, "mode": "SIMULATED"}
    CTX.actions.append(rec)
    return f"[SIMULATED] {action} applied to {target}"


# ---- CrewAI wrappers -------------------------------------------------------------------------------------------
class _NoArgs(BaseModel):
    pass


class _Query(BaseModel):
    query: str = Field(..., description="Natural-language description of the threat or behaviour")


class _IP(BaseModel):
    ip: str = Field(..., description="IP address to look up")


class _Action(BaseModel):
    action: str = Field(..., description=f"One of {sorted(ALLOWED_ACTIONS)}")
    target: str = Field(..., description="IP address, hostname or account name")
    reason: str = Field(..., description="Short justification")


class LogAnalysisTool(BaseTool):
    name: str = "log_analysis"
    description: str = "Run signature/threshold detection rules over the security logs and return the alerts as JSON."
    args_schema: type[BaseModel] = _NoArgs

    def _run(self) -> str:
        return analyze_logs()


class AnomalyDetectionTool(BaseTool):
    name: str = "anomaly_detection"
    description: str = "Run IsolationForest anomaly detection on logs for activity the rules did not explain."
    args_schema: type[BaseModel] = _NoArgs

    def _run(self) -> str:
        return detect_anomalies()


class ThreatIntelRAGTool(BaseTool):
    name: str = "threat_intel_search"
    description: str = "Semantic search of the MITRE ATT&CK / CVE knowledge base to map observed behaviour to techniques."
    args_schema: type[BaseModel] = _Query

    def _run(self, query: str) -> str:
        return search_threat_intel(query)


class IOCLookupTool(BaseTool):
    name: str = "ioc_lookup"
    description: str = "Check an IP against the threat-intelligence feed and the log history."
    args_schema: type[BaseModel] = _IP

    def _run(self, ip: str) -> str:
        return lookup_ioc(ip)


class PlaybookRAGTool(BaseTool):
    name: str = "playbook_search"
    description: str = "Retrieve incident-response playbook steps (containment, eradication, recovery) for a threat."
    args_schema: type[BaseModel] = _Query

    def _run(self, query: str) -> str:
        return search_playbook(query)


class ResponseActionTool(BaseTool):
    name: str = "response_action"
    description: str = "Execute a SIMULATED response action (block_ip, isolate_host, disable_account, ...). Logged only."
    args_schema: type[BaseModel] = _Action

    def _run(self, action: str, target: str, reason: str) -> str:
        return take_response_action(action, target, reason)
