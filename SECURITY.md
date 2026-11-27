# Security Policy

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, report vulnerabilities privately through GitHub Security Advisories:

- <https://github.com/timReynolds/custodian/security/advisories/new>

When submitting a report, please include:

- The affected binary, package, or endpoint (for example, `custodian-api`, `custodian-publisher`, `custodian-git-gateway`, or `custodian-worker`).
- Clear steps to reproduce or a proof-of-concept test case.
- The potential security impact (such as credential leakage, policy bypass, path traversal, or privilege escalation).

## Security Design Principles

Custodian is built around defense-in-depth controls so that untrusted workspaces, coding agents, and developer pushes cannot reach sensitive credentials or bypass review:

- **Credentialless Workspaces**: Repository source is delivered without GitHub tokens, SSH keys, or credential helpers.
- **Isolated Publisher**: `custodian-publisher` is a separate binary holding write-only GitHub App credentials and runs Git in a hardened environment without hooks, filters, or user configuration.
- **Fail-Closed Policy Enforcement**: Policy parsing, compilation, or runtime errors default to blocking egress (`DENY`).
- **Redacted Observability**: Logs record resource IDs and SHA-256 digests rather than raw source code, diffs, or secrets.

See [docs/architecture.md](docs/architecture.md) for more details on the security model.
