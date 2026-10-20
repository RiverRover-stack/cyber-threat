"""Synthetic, labelled security telemetry (auth, firewall and web logs).

All sources share one schema so that detection code stays simple:

    event_id, timestamp, source, src_ip, dst_ip, dst_port, host, user,
    action, bytes_out, request, status, label

``label`` is ``benign`` or the injected attack type (ground truth for evaluation).
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .config import SEED

ATTACK_TYPES = [
    "ssh_brute_force",
    "port_scan",
    "sql_injection",
    "c2_beaconing",
    "data_exfiltration",
    "privilege_escalation",
]

COLUMNS = [
    "event_id", "timestamp", "source", "src_ip", "dst_ip", "dst_port",
    "host", "user", "action", "bytes_out", "request", "status", "label",
]

HOSTS = {"web-01": "10.0.1.10", "db-01": "10.0.2.20", "app-01": "10.0.1.30", "files-01": "10.0.3.40"}
USERS = ["alice", "bob", "carol", "dave", "erin", "svc_backup"]
WORKSTATIONS = [f"10.0.5.{i}" for i in range(11, 31)]
BENIGN_PATHS = ["/", "/index.html", "/products", "/products?id=12", "/login", "/about", "/api/v1/items", "/static/app.js"]
SQLI_PAYLOADS = [
    "/products?id=1' OR '1'='1", "/products?id=1 UNION SELECT username,password FROM users--",
    "/login?user=admin'--", "/products?id=1; DROP TABLE users;--",
    "/api/v1/items?id=1 AND SLEEP(5)", "/products?id=1 UNION SELECT table_name FROM information_schema.tables",
]
BASE_TIME = pd.Timestamp("2026-03-01 08:00:00")


def _row(ts, source, src_ip, dst_ip, dst_port, host, user, action, bytes_out, request, status, label):
    return dict(timestamp=ts, source=source, src_ip=src_ip, dst_ip=dst_ip, dst_port=int(dst_port),
                host=host, user=user, action=action, bytes_out=int(bytes_out), request=request,
                status=status, label=label)


def _benign(rng: np.random.RandomState, n: int, span_s: int) -> list[dict]:
    rows = []
    for _ in range(n):
        ts = BASE_TIME + pd.Timedelta(seconds=int(rng.randint(0, span_s)))
        kind = rng.choice(["auth", "web", "fw"], p=[0.25, 0.4, 0.35])
        host = rng.choice(list(HOSTS))
        if kind == "auth":
            ok = rng.rand() > 0.04
            rows.append(_row(ts, "auth", rng.choice(WORKSTATIONS), HOSTS[host], 22, host, rng.choice(USERS),
                             "login_success" if ok else "login_failed", rng.randint(100, 900),
                             "sshd: session opened" if ok else "sshd: authentication failure",
                             "success" if ok else "failure", "benign"))
        elif kind == "web":
            rows.append(_row(ts, "web", f"192.0.2.{rng.randint(1, 200)}", HOSTS["web-01"], 443, "web-01", "-",
                             "http_request", rng.randint(500, 40_000), "GET " + rng.choice(BENIGN_PATHS),
                             str(rng.choice([200, 200, 200, 304, 404])), "benign"))
        else:
            src = rng.choice(WORKSTATIONS)
            port = int(rng.choice([80, 443, 443, 53, 8080]))
            ext = f"93.184.{rng.randint(1, 50)}.{rng.randint(1, 250)}"
            rows.append(_row(ts, "firewall", src, ext, port, "fw-edge", "-", "allow",
                             rng.randint(500, 2_000_000), f"tcp/{port}", "allowed", "benign"))
    return rows


def _ssh_brute_force(rng, start: pd.Timestamp) -> list[dict]:
    ip, host, rows = "203.0.113.45", "web-01", []
    for i in range(70):
        rows.append(_row(start + pd.Timedelta(seconds=i * 1.5), "auth", ip, HOSTS[host], 22, host,
                         rng.choice(["root", "admin", "alice", "test", "oracle", "ubuntu"]), "login_failed",
                         200, "sshd: authentication failure", "failure", "ssh_brute_force"))
    rows.append(_row(start + pd.Timedelta(seconds=110), "auth", ip, HOSTS[host], 22, host, "alice",
                     "login_success", 300, "sshd: session opened", "success", "ssh_brute_force"))
    return rows


def _port_scan(rng, start: pd.Timestamp) -> list[dict]:
    ip, host = "198.51.100.77", "db-01"
    ports = rng.choice(np.arange(1, 10000), 60, replace=False)
    return [_row(start + pd.Timedelta(seconds=i * 0.4), "firewall", ip, HOSTS[host], p, host, "-", "deny", 60,
                 f"tcp/{p} SYN", "blocked", "port_scan") for i, p in enumerate(ports)]


def _sql_injection(rng, start: pd.Timestamp) -> list[dict]:
    ip = "203.0.113.99"
    return [_row(start + pd.Timedelta(seconds=i * 6), "web", ip, HOSTS["web-01"], 443, "web-01", "-",
                 "http_request", rng.randint(2_000, 90_000), "GET " + SQLI_PAYLOADS[i % len(SQLI_PAYLOADS)],
                 str(rng.choice([200, 500])), "sql_injection") for i in range(12)]


def _c2_beaconing(rng, start: pd.Timestamp) -> list[dict]:
    src, c2 = "10.0.5.23", "185.220.101.7"
    return [_row(start + pd.Timedelta(seconds=i * 60 + rng.uniform(-1, 1)), "firewall", src, c2, 4444,
                 "fw-edge", "-", "allow", rng.randint(180, 260), "tcp/4444", "allowed", "c2_beaconing")
            for i in range(40)]


def _exfiltration(rng, start: pd.Timestamp) -> list[dict]:
    src, dst = "10.0.3.40", "45.133.1.88"
    return [_row(start + pd.Timedelta(seconds=i * 30), "firewall", src, dst, 443, "fw-edge", "-", "allow",
                 rng.randint(25_000_000, 60_000_000), "tcp/443 upload", "allowed", "data_exfiltration")
            for i in range(8)]


def _priv_esc(rng, start: pd.Timestamp) -> list[dict]:
    host, ip = "app-01", HOSTS["app-01"]
    cmds = ["sudo: bob : COMMAND=/bin/bash", "chmod u+s /bin/bash",
            "echo 'bob ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers", "usermod -aG sudo bob", "su root"]
    return [_row(start + pd.Timedelta(seconds=i * 20), "auth", "10.0.5.14", ip, 22, host, "bob",
                 "privilege_change", 150, c, "success", "privilege_escalation") for i, c in enumerate(cmds)]


def generate_logs(n_benign: int = 2500, span_s: int = 3 * 3600, seed: int = SEED) -> pd.DataFrame:
    """Return a time-sorted DataFrame of benign noise plus one injected incident per attack type."""
    rng = np.random.RandomState(seed)
    rows = _benign(rng, n_benign, span_s)
    injectors = [_ssh_brute_force, _port_scan, _sql_injection, _c2_beaconing, _exfiltration, _priv_esc]
    for k, inj in enumerate(injectors):
        start = BASE_TIME + pd.Timedelta(minutes=15 + k * 22)
        rows.extend(inj(rng, start))
    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    df.insert(0, "event_id", np.arange(len(df)))
    return df[COLUMNS]
