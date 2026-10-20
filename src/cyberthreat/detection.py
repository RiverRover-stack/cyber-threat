"""Detection layer: signature/threshold rules + IsolationForest anomaly scoring."""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from .config import SEED

SQLI_RE = re.compile(
    r"(union\s+select|'\s*or\s*'|\bor\s+1\s*=\s*1|--|;\s*drop\s+table|sleep\s*\(|information_schema)", re.I)
PRIVESC_RE = re.compile(r"(chmod\s+u\+s|/etc/sudoers|usermod\s+-aG\s+sudo|NOPASSWD|COMMAND=/bin/bash|su\s+root)", re.I)

MITRE_MAP = {
    "ssh_brute_force": "T1110", "port_scan": "T1046", "sql_injection": "T1190",
    "c2_beaconing": "T1071", "data_exfiltration": "T1041", "privilege_escalation": "T1548",
    "anomalous_activity": "T1595",
}
SEVERITY = {
    "ssh_brute_force": "High", "port_scan": "Medium", "sql_injection": "High",
    "c2_beaconing": "Critical", "data_exfiltration": "Critical", "privilege_escalation": "Critical",
    "anomalous_activity": "Low",
}


@dataclass
class Alert:
    alert_id: str
    attack_type: str
    severity: str
    src_ip: str
    host: str
    method: str  # rule | anomaly
    description: str
    mitre_id: str
    first_seen: str
    last_seen: str
    event_ids: list = field(default_factory=list)
    threat_ip: str = ""  # remote malicious party to block (empty if none, e.g. insider/anomaly)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["event_count"] = len(self.event_ids)
        return d


def _mk(idx: int, atype: str, src: str, host: str, method: str, desc: str, ev: pd.DataFrame,
        threat_ip: str = "") -> Alert:
    fmt = "%Y-%m-%d %H:%M:%S"
    return Alert(f"ALERT-{idx:03d}", atype, SEVERITY[atype], src, host, method, desc, MITRE_MAP[atype],
                 ev.timestamp.min().strftime(fmt), ev.timestamp.max().strftime(fmt),
                 [int(i) for i in ev.event_id], threat_ip)


def rule_detect(df: pd.DataFrame) -> list[Alert]:
    """Deterministic signatures and thresholds, one alert per offending source."""
    alerts: list[Alert] = []
    n = lambda: len(alerts) + 1  # noqa: E731

    # SSH brute force: >=10 failed logins from one IP within 5 minutes
    failed = df[(df.source == "auth") & (df.action == "login_failed")]
    for ip, g in failed.groupby("src_ip"):
        g = g.sort_values("timestamp")
        if len(g) >= 10 and (g.timestamp.max() - g.timestamp.min()) <= pd.Timedelta(minutes=5):
            ok = df[(df.src_ip == ip) & (df.action == "login_success")]
            ev = pd.concat([g, ok]).sort_values("timestamp")
            extra = " followed by a SUCCESSFUL login (possible compromise)" if len(ok) else ""
            alerts.append(_mk(n(), "ssh_brute_force", ip, g.host.iloc[0], "rule",
                              f"{len(g)} failed SSH logins in {(g.timestamp.max()-g.timestamp.min()).seconds}s "
                              f"across {g.user.nunique()} accounts{extra}", ev, threat_ip=ip))

    # Port scan: >=20 distinct destination ports denied by firewall from one IP
    fw = df[(df.source == "firewall") & (df.action == "deny")]
    for ip, g in fw.groupby("src_ip"):
        if g.dst_port.nunique() >= 20:
            alerts.append(_mk(n(), "port_scan", ip, g.host.iloc[0], "rule",
                              f"{g.dst_port.nunique()} distinct ports probed on {g.dst_ip.iloc[0]}", g, threat_ip=ip))

    # SQL injection: web requests with SQLi signatures
    web = df[df.source == "web"]
    hits = web[web.request.str.contains(SQLI_RE)]
    for ip, g in hits.groupby("src_ip"):
        alerts.append(_mk(n(), "sql_injection", ip, "web-01", "rule",
                          f"{len(g)} requests containing SQL-injection payloads", g, threat_ip=ip))

    allowed = df[(df.source == "firewall") & (df.action == "allow")]
    # C2 beaconing: >=15 connections to one external IP with near-constant interval and small payloads
    for (src, dst), g in allowed.groupby(["src_ip", "dst_ip"]):
        if len(g) < 15:
            continue
        gaps = g.sort_values("timestamp").timestamp.diff().dt.total_seconds().dropna()
        if gaps.mean() > 0 and gaps.std() / gaps.mean() < 0.1 and g.bytes_out.median() < 5_000:
            alerts.append(_mk(n(), "c2_beaconing", src, "fw-edge", "rule",
                              f"{len(g)} connections to {dst}:{g.dst_port.iloc[0]} every ~{gaps.mean():.0f}s "
                              f"(jitter {gaps.std():.1f}s)", g, threat_ip=dst))

    # Data exfiltration: > 100 MB uploaded to one external destination
    for (src, dst), g in allowed.groupby(["src_ip", "dst_ip"]):
        total = g.bytes_out.sum()
        if total > 100_000_000:
            alerts.append(_mk(n(), "data_exfiltration", src, "fw-edge", "rule",
                              f"{total/1e6:.0f} MB sent to {dst} in {len(g)} flows", g, threat_ip=dst))

    # Privilege escalation: suspicious privilege-change commands
    pc = df[(df.action == "privilege_change") & df.request.str.contains(PRIVESC_RE)]
    for ip, g in pc.groupby("src_ip"):
        alerts.append(_mk(n(), "privilege_escalation", ip, g.host.iloc[0], "rule",
                          f"{len(g)} suspicious privilege commands by user '{g.user.iloc[0]}'", g))
    return alerts


def _features(df: pd.DataFrame, window: str = "5min") -> pd.DataFrame:
    d = df.copy()
    d["win"] = d.timestamp.dt.floor(window)
    g = d.groupby(["src_ip", "win"])
    feat = pd.DataFrame({
        "n_events": g.size(),
        "n_failed": g.apply(lambda x: (x.status.isin(["failure", "blocked"])).sum(), include_groups=False),
        "n_ports": g.dst_port.nunique(),
        "bytes_out": g.bytes_out.sum(),
        "n_targets": g.dst_ip.nunique(),
    })
    return feat


def anomaly_detect(df: pd.DataFrame, contamination: float = 0.002, seed: int = SEED,
                   exclude_events: set | None = None) -> list[Alert]:
    """IsolationForest over per-(source IP, 5-min window) behaviour; flags unexplained outliers."""
    feat = _features(df)
    X = np.log1p(feat.values.astype(float))
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=seed).fit(X)
    flagged = feat[model.predict(X) == -1]
    alerts, exclude = [], exclude_events or set()
    for (ip, win), _ in flagged.iterrows():
        ev = df[(df.src_ip == ip) & (df.timestamp.dt.floor("5min") == win)]
        if set(ev.event_id) <= exclude:
            continue  # already explained by a rule alert
        alerts.append(_mk(len(alerts) + 1, "anomalous_activity", ip, ev.host.iloc[0], "anomaly",
                          f"Statistically anomalous behaviour: {len(ev)} events, "
                          f"{ev.dst_port.nunique()} ports, {ev.bytes_out.sum()/1e3:.0f} KB out", ev))
    return alerts


def detect_all(df: pd.DataFrame, use_anomaly: bool = True) -> list[Alert]:
    """Run rules, then anomaly detection on whatever the rules did not explain."""
    alerts = rule_detect(df)
    if use_anomaly:
        covered = {e for a in alerts for e in a.event_ids}
        extra = anomaly_detect(df, exclude_events=covered)
        for a in extra:
            a.alert_id = f"ALERT-{len(alerts) + 1:03d}"
            alerts.append(a)
    return alerts


def alerts_to_frame(alerts: list[Alert]) -> pd.DataFrame:
    cols = ["alert_id", "attack_type", "severity", "src_ip", "host", "method", "mitre_id", "event_count", "description"]
    return pd.DataFrame([a.to_dict() for a in alerts], columns=cols + ["first_seen", "last_seen", "event_ids"])[cols]
