# Playbook: Command-and-Control Beaconing (T1071)
**Severity:** Critical

## Detection indicators
- A host connects to the same external IP at near-constant intervals with small payloads.

## Containment
1. Isolate the infected host from the network immediately.
2. Block the C2 IP address and domain at the firewall and DNS.

## Eradication and recovery
1. Capture memory and disk evidence, then reimage the host.
2. Hunt for the same indicators on other hosts and rotate credentials used on the host.

## Post-incident
Share indicators of compromise with threat intelligence and review egress filtering.
