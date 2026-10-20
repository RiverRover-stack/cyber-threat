# Agents, Tasks and Tools

Process: `Process.sequential`; each task receives earlier outputs via `context=[...]`.

| # | Agent | Goal | Tools | Task output |
|---|---|---|---|---|
| 1 | SOC Log Analyst / Threat Detector | Detect malicious or anomalous events with few false positives | `log_analysis`, `anomaly_detection` | Numbered alert list |
| 2 | Cyber Threat Intelligence Analyst | Enrich alerts with ATT&CK/CVE/IOC context | `threat_intel_search` (RAG), `ioc_lookup` | Technique, tactic, IOC match per alert |
| 3 | Incident Response Engineer | Contain incidents following playbooks | `playbook_search` (RAG), `response_action` | Actions taken per alert |
| 4 | Security Report Writer | Executive-ready incident report | none | Markdown report |

## Tools
| Tool | Input | Behaviour |
|---|---|---|
| `log_analysis` | none | Runs rule detectors on the shared logs; stores and returns alerts (JSON) |
| `anomaly_detection` | none | IsolationForest on per-source 5-min windows; skips events already explained by rules |
| `threat_intel_search` | `query` | Top-2 ATT&CK + top-1 CVE chunks from ChromaDB with similarity scores |
| `ioc_lookup` | `ip` | Matches `knowledge_base/ioc_feed.json` and summarises log history |
| `playbook_search` | `query` | Finds the best playbook and returns it in full |
| `response_action` | `action`, `target`, `reason` | **Simulated**; allowed: `block_ip`, `isolate_host`, `disable_account`, `reset_credentials`, `enable_waf_rule`, `create_ticket` |

## Detection rules
| Attack | Rule | MITRE | Severity |
|---|---|---|---|
| SSH brute force | >= 10 failed logins from one IP within 5 min (flags a later success) | T1110 | High |
| Port scan | >= 20 distinct denied destination ports from one IP | T1046 | Medium |
| SQL injection | Regex for `UNION SELECT`, `OR 1=1`, `DROP TABLE`, `SLEEP(`, `information_schema` ... | T1190 | High |
| C2 beaconing | >= 15 connections to one external IP, interval CV < 0.1, median payload < 5 KB | T1071 | Critical |
| Data exfiltration | > 100 MB sent to one external IP | T1041 | Critical |
| Privilege escalation | `privilege_change` events matching setuid/sudoers/sudo-group patterns | T1548 | Critical |
| Anomaly | IsolationForest outlier not covered by a rule (contamination 0.002) | T1595 | Low |

## Adding an agent or tool
1. Write the logic as a plain function in `tools.py` and wrap it in a `BaseTool` with an `args_schema`.
2. Attach it to an agent in `agents.py`; add or extend a task in `tasks.py`.
3. Add a unit test that calls the plain function (no API key needed).
