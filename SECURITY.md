# Security policy

## Scope

opscope is a read-only diagnostics tool with optional cloud collection and an authenticated loopback UI. It launches fixed trusted utilities with argument arrays; it does not invoke a shell, change services, alter firewall rules, elevate privileges or transmit telemetry. Explicit cloud queries and confirmed external delivery are separate optional paths.

Support bundles deliberately omit process command lines and redact host, user, network-address and filesystem-root identifiers. Treat snapshots and bundles as sensitive operational evidence before sharing them.

For output that may leave the machine, use `opscope snapshot --redact --json --out safe-snapshot.json`. The detailed default snapshot is intentionally more verbose for local incident response and can contain command lines, service metadata and filesystem information.

The collector bounds child-process output and lifetime, accepts only regular input files, limits imported snapshots to 16 MiB with depth/field/collection/complexity checks, writes generated artifacts atomically with private temporary-file permissions, resolves built-in tools from trusted system locations without falling back to `PATH`, verifies Unix ownership and parent-directory permissions, checks Windows ACLs and reparse points, and refuses to launch a utility that fails validation. Linux elevation is read from the effective OS user ID rather than an environment variable. GitHub Actions dependencies are pinned to commit SHAs.

There is no elevation path in the application: it does not invoke `sudo`, `runas`, `su`, `pkexec`, service creation, scheduled tasks, changes to existing host access policy or firewall-mutating commands. It runs with the caller's existing token. When an operator runs it as Administrator/root, `--out` and the baseline path must still be treated as trusted input because they intentionally select filesystem locations. Firewall reports distinguish an enabled state from verified rules and effective inbound filtering by family and scope; output-only, loopback-only or otherwise unverified rules do not suppress exposure warnings. Redaction preserves sanitized collection warnings and marks doctor output as incomplete when collection was partial.

## Added modules

The local API listens only on 127.0.0.1 and uses a fresh session token, exact Host/Origin/referrer checks, Fetch Metadata checks, strict CSP and no CORS grant. Tokens are scrubbed from collected evidence, including full views. UI policy editing is preview/download only. History is private, bounded, retained by age/count and redacted before storage; uploaded baselines/fleets are validated and not saved. Metrics/SSE/HTTP MCP require authentication; stdio MCP has only narrow snapshot/finding tools.

Cloud helpers use a separate read-operation allowlist and existing official CLI sessions. They never start login, install extensions, enable services, retrieve secret values, run commands on cloud hosts or patch resources. Azure child telemetry/dynamic installation/auto-upgrade and AWS interactive prompts are disabled. Authentication caches remain controlled by those CLIs and are never copied to evidence. Metadata is explicit, identity-only and bounded; AWS always uses IMDSv2 with no credential-path fallback.

Notification/log delivery requires explicit confirmation, a configured existing destination and appropriate separate credentials. Preview is the default; only bounded redacted summaries can be sent. No notification path is exposed in the web UI. Paid services are not enabled automatically.

Policies and packs reject arbitrary commands, unknown/duplicate keys, tags, anchors, aliases and escaping/cyclic inheritance. Bundles have bounded entry validation, SHA-256 manifests/checksums, optional RSA-PSS authentication with an independently trusted public key, and optional AES-GCM/RSA-OAEP encryption. Keys are not included. Hashes alone do not authenticate the origin. Keep selected input, output, key, history and configuration paths trusted when operating as Administrator/root.

Redaction minimizes known identifiers and secret patterns, not every context-specific meaning. Counts, timing, package/runtime versions and retained operational context may still be sensitive. Coverage gaps are explicit; a password-required flag does not prove a blank password, and enabled firewall state does not prove every listener protected.

## Reporting a vulnerability

Please open a private security report through GitHub for vulnerabilities that could expose credentials, execute an unintended command, overwrite an unintended path, or cause unbounded resource consumption. Include the affected version, platform, command line and a minimal reproduction. Do not publish credentials or sensitive host data in a public issue.

