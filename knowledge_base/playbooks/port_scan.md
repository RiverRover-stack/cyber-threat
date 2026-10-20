# Playbook: Port Scan / Network Reconnaissance (T1046)
**Severity:** Medium

## Detection indicators
- One source IP probing many distinct destination ports, mostly denied by the firewall.

## Containment
1. Block the scanning source IP at the firewall.
2. Check whether any probe was allowed, and verify the exposed services.

## Recovery
1. Close unnecessary open ports and restrict services to required networks.
2. Watch for follow-up exploitation attempts from the same source.

## Post-incident
Add the source to threat intelligence blocklists and tune IDS thresholds.
