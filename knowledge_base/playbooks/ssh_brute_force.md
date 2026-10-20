# Playbook: SSH Brute Force (T1110)
**Severity:** High

## Detection indicators
- Many failed SSH logins from one source IP in a short period, across multiple usernames.
- A successful login following the failures indicates possible account compromise.

## Containment
1. Block the offending source IP at the perimeter firewall.
2. If a login succeeded, disable the affected account and terminate its active sessions.

## Eradication and recovery
1. Reset credentials of the affected account and review it for persistence (authorized_keys, cron).
2. Enforce MFA or key-only SSH authentication; deploy fail2ban rate limiting.

## Post-incident
Review auth logs for other sources, document lessons learned.
