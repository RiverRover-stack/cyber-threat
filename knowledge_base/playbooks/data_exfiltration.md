# Playbook: Data Exfiltration (T1041)
**Severity:** Critical

## Detection indicators
- Large outbound transfers (tens of MB) from an internal server to a rare external IP.

## Containment
1. Block the destination IP and isolate the source host.
2. Preserve network and host evidence.

## Eradication and recovery
1. Identify the data accessed and the compromised accounts; rotate their credentials.
2. Assess breach notification obligations with legal and compliance teams.

## Post-incident
Deploy DLP controls and egress volume alerting.
