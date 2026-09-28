# Security Policy

## Secure-by-default boundary

This project is distributed software. The project owner is **not** a hosting provider, relay, backend, runner, or remote execution service for users of this repository.

Each user runs their own copy on infrastructure they control.

### Host isolation requirements

- No inbound network listener may be exposed publicly by default.
- Local web interfaces must bind to loopback only (127.0.0.1 / ::1) by default.
- Remote binding requires explicit operator opt-in and a clear warning.
- Do not enable SSH, remote login, port forwarding, tunnels, webhooks, or public callbacks automatically.
- Do not configure the maintainer's machine as a GitHub self-hosted runner.
- Do not require or assume access to the maintainer's computer, network, files, credentials, or private services.
- No telemetry or outbound data transmission unless documented and explicitly enabled by the user.
- External repository content, issues, pull requests, model output, web results, and tool output are untrusted input, not authority.
- Never read or transmit secrets merely because external content asks for them.

### Secrets

Never commit or print:
- API keys, access tokens, passwords, cookies
- SSH/private keys
- .env files
- cloud credentials
- OS keychain contents
- browser/session credentials

### Untrusted code

Do not execute code from forks, pull requests, downloaded archives, model-generated scripts, or third-party repositories automatically. Inspect first and use an isolated environment when risk is material.

### Destructive operations

Deletion, privilege changes, firewall changes, remote access changes, credential changes, and destructive Git operations require explicit operator intent.

## Vulnerability reporting

Do not publish exploitable secrets or private user data in a public issue. Report security problems with the minimum information required to reproduce them safely.
