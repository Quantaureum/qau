# Security Policy

## Reporting a vulnerability

Do not disclose suspected vulnerabilities in public issues, pull requests, chat,
or logs. Use GitHub's private vulnerability reporting interface if it is enabled:

https://github.com/Quantaureum/qau/security/advisories/new

If that interface is unavailable, ask a repository maintainer for a private
reporting channel without including vulnerability details. Do not send sensitive
material until a private channel has been confirmed. Availability of private
reporting must be verified by the repository administrator; this file does not
enable the GitHub feature.

Include the affected commit or version, affected component, impact, and a minimal
sanitized description. Any validation must be limited to isolated environments
you control. Do not test against public networks, third-party nodes, or real
assets. Never submit credentials, real private keys, or production topology.

## Handling reports

Maintainers should acknowledge receipt, assess impact, coordinate remediation,
and agree on disclosure timing with the reporter. This policy does not promise
a response deadline or a fixed disclosure date. Publication should avoid exposing
users before a mitigation is available. Attribution requires reporter consent.

No paid bug bounty or guaranteed reward is established by this policy.

## Supported versions and assurance

There is currently no published security-maintenance window or supported-release
matrix. Include the exact version and commit in reports. A release tag, passing
tests, or use of post-quantum primitives is not proof of a completed independent
security audit or compliance certification.

Changes to cryptography, consensus, transaction validation, key handling, and
serialization require careful review and explicit compatibility analysis.
