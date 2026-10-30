# Security policy

Cerato Network is in active development, **not production hardened**.

## Reporting a vulnerability

Please report vulnerabilities privately using GitHub's **Report a vulnerability** / private vulnerability reporting feature if enabled, or contact the project maintainers through a private channel. **Do not post exploits, server credentials, IP allowlists, WireGuard keys, session cookies, enrollment tokens or crash dumps publicly.**

No guaranteed response window or active bug-bounty program is currently offered.

## Threat model and guidelines

- Gateways may have public IPs and privileged network management capabilities. Assume API misuse can cause a production outage.
- Run the frontend behind TLS; the application binds to loopback and has least-privilege service permissions.
- Keep the root-only command bridge restricted to an allowlist, with strict argument validation and independent authorization.
- Secrets and signing keys are never committed, logged or transmitted to unauthenticated clients.
- Default account setup must require a short-lived secret generated from the host SSH console.
- Permission checks must be performed by every API handler and serialization must remove sensitive fields for read-only users.
- All updates require signature/integrity verification and a verified rollback path.
- Do not enable privileged updater, network rule application or bootstrap APIs on a public service before external security review.

## Supported versions

No stable version is available yet. No security support contract applies to development snapshots.

## Safety for contributors

Use documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and sample names in tests, NEVER real deployment addresses or user credentials. Do not include production configuration files when making a pull request.
