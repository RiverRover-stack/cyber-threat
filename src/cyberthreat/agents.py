"""CrewAI agent definitions."""
from crewai import Agent

from .tools import (AnomalyDetectionTool, IOCLookupTool, LogAnalysisTool, PlaybookRAGTool,
                    ResponseActionTool, ThreatIntelRAGTool)


def build_agents(llm=None) -> dict[str, Agent]:
    common = dict(llm=llm, verbose=False, allow_delegation=False, max_iter=8)
    return {
        "detector": Agent(
            role="SOC Log Analyst / Threat Detector",
            goal="Detect every malicious or anomalous event in the security logs with few false positives.",
            backstory="A Tier-1/2 SOC analyst who triages SIEM data using detection rules and anomaly models.",
            tools=[LogAnalysisTool(), AnomalyDetectionTool()], **common),
        "intel": Agent(
            role="Cyber Threat Intelligence Analyst",
            goal="Enrich each alert with MITRE ATT&CK mapping, CVE context and IOC reputation.",
            backstory="A CTI specialist who grounds every conclusion in the retrieved knowledge base, never guessing.",
            tools=[ThreatIntelRAGTool(), IOCLookupTool()], **common),
        "responder": Agent(
            role="Incident Response Engineer",
            goal="Contain and remediate each incident by following the retrieved response playbooks.",
            backstory="An IR lead who applies proportionate, playbook-driven containment. All actions are simulated.",
            tools=[PlaybookRAGTool(), ResponseActionTool()], **common),
        "reporter": Agent(
            role="Security Report Writer",
            goal="Produce a clear, accurate incident report for security management.",
            backstory="A security communicator who turns technical findings into an executive-ready report.",
            tools=[], **common),
    }
