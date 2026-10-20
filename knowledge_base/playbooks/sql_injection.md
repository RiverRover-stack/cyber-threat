# Playbook: SQL Injection (T1190)
**Severity:** High

## Detection indicators
- Web requests containing UNION SELECT, OR 1=1, DROP TABLE, SLEEP() or information_schema.

## Containment
1. Block the attacking IP on the web application firewall.
2. Check database logs to determine whether data was read or modified.

## Eradication and recovery
1. Patch the vulnerable endpoint with parameterised queries and input validation.
2. Rotate database credentials and restore data from backup if it was modified.

## Post-incident
Run a vulnerability scan on the application and notify stakeholders if personal data was exposed.
