# Security Policy

## Supported versions

Only the latest release of cluster-guardian receives security fixes.

## Release integrity

Releases are cosign-signed (keyless, GitHub OIDC), ship SPDX SBOMs, and carry
SLSA build provenance — see ["Verify a release"](README.md#verify-a-release)
for the verification one-liners.

## Reporting a vulnerability

Please **do not open a public issue** for security vulnerabilities.

Instead, report it privately via [GitHub private vulnerability reporting](https://github.com/AndrewKarpaty/cluster-guardian/security/advisories/new) ("Report a vulnerability" in the Security tab).

Include what you can:

- A description of the vulnerability and its impact
- Steps to reproduce
- Affected version or commit

You can expect an acknowledgement within a few days. Once a fix is available, the vulnerability will be disclosed in the release notes.

Note that cluster-guardian is a read-only analysis tool: it requires only read access to the cluster and never mutates cluster state. Reports about excessive RBAC requirements are also welcome.
