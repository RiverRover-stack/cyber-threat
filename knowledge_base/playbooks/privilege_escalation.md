# Playbook: Privilege Escalation (T1548)
**Severity:** Critical

## Detection indicators
- chmod u+s on shells, edits to /etc/sudoers with NOPASSWD, usermod -aG sudo, sudo to /bin/bash.

## Containment
1. Disable the user account and kill its sessions.
2. Isolate the host if root compromise is suspected.

## Eradication and recovery
1. Revert sudoers and setuid changes; audit for backdoor accounts and persistence.
2. Patch local privilege escalation vulnerabilities such as sudo CVE-2021-3156.

## Post-incident
Enforce least privilege and enable auditd rules for privilege changes.
