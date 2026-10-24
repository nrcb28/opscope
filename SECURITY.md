# Security policy

## Scope

opscope is a local, read-only diagnostics tool. It launches only fixed operating-system utilities with argument arrays; it does not invoke a shell, change services, alter firewall rules or transmit telemetry.

Support bundles deliberately omit process command lines and redact host, user, network-address and filesystem-root identifiers. Treat snapshots and bundles as sensitive operational evidence before sharing them.

For output that may leave the machine, use `opscope snapshot --redact --json --out safe-snapshot.json`. The detailed default snapshot is intentionally more verbose for local incident response and can contain command lines, service metadata and filesystem information.

The collector bounds child-process output, limits imported baseline snapshots to 16 MiB and a bounded JSON depth/collection size, writes generated artifacts atomically with private temporary-file permissions, resolves built-in tools from trusted system locations without falling back to `PATH`, verifies Unix ownership and parent-directory permissions, checks Windows ACLs and reparse points, and refuses to launch a utility that fails validation. Linux elevation is read from the effective OS user ID rather than an environment variable. GitHub Actions dependencies are pinned to commit SHAs.

There is no elevation path in the application: it does not invoke `sudo`, `runas`, `su`, `pkexec`, service creation, scheduled tasks, permission-changing APIs or firewall-mutating commands. It runs with the caller's existing token. When an operator runs it as Administrator/root, `--out` and the baseline path must still be treated as trusted input because they intentionally select filesystem locations. Firewall reports distinguish an enabled state from verified rules and effective inbound filtering by family and scope; output-only, loopback-only or otherwise unverified rules do not suppress exposure warnings. Redaction preserves sanitized collection warnings and marks doctor output as incomplete when collection was partial.

## Reporting a vulnerability

Please open a private security report through GitHub for vulnerabilities that could expose credentials, execute an unintended command, overwrite an unintended path, or cause unbounded resource consumption. Include the affected version, platform, command line and a minimal reproduction. Do not publish credentials or sensitive host data in a public issue.

