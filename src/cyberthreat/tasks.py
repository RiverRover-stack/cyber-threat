"""CrewAI task definitions (sequential pipeline: detect -> enrich -> respond -> report)."""
from crewai import Task


def build_tasks(agents: dict) -> list[Task]:
    detect = Task(
        description=("Call the log_analysis tool, then the anomaly_detection tool. List every alert with its "
                     "ID, attack type, severity, source IP, host and a one-line evidence summary."),
        expected_output="A numbered list of all alerts (ID, type, severity, src_ip, host, evidence).",
        agent=agents["detector"])
    intel = Task(
        description=("For EACH alert from the previous task: call threat_intel_search with a description of the "
                     "behaviour to get the MITRE technique, and ioc_lookup on the source IP. Report technique ID/name, "
                     "tactic, IOC reputation and confidence per alert."),
        expected_output="Per alert: MITRE technique ID and name, tactic, IOC match, and confidence.",
        agent=agents["intel"], context=[detect])
    respond = Task(
        description=("For EACH alert: call playbook_search for the attack type, then apply the containment steps "
                     "with response_action (valid actions: block_ip, isolate_host, disable_account, reset_credentials, "
                     "enable_waf_rule, create_ticket). Block external attackers, isolate infected internal hosts, "
                     "disable compromised accounts. Summarise actions taken per alert."),
        expected_output="Per alert: playbook followed, actions executed (simulated), and recommended follow-ups.",
        agent=agents["responder"], context=[detect, intel])
    report = Task(
        description=("Write a Markdown incident report with sections: Executive Summary, Incident Table "
                     "(ID, type, severity, MITRE, source), Detailed Findings per incident, Response Actions Taken, "
                     "Recommendations. Use only facts from the prior tasks."),
        expected_output="A complete Markdown incident report.",
        agent=agents["reporter"], context=[detect, intel, respond])
    return [detect, intel, respond, report]
