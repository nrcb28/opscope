# Security policy

## Scope

opscope is a local, read-only diagnostics tool. It launches only fixed operating-system utilities with argument arrays; it does not invoke a shell, change services, alter firewall rules or transmit telemetry.

Support bundles deliberately omit process command lines and redact host, user, network-address and filesystem-root identifiers. Treat snapshots and bundles as sensitive operational evidence before sharing them.

## Reporting a vulnerability

Please open a private security report through GitHub for vulnerabilities that could expose credentials, execute an unintended command, overwrite an unintended path, or cause unbounded resource consumption. Include the affected version, platform, command line and a minimal reproduction. Do not publish credentials or sensitive host data in a public issue.

