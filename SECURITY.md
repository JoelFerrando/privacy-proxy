# Security Policy

## Reporting a Vulnerability

Please report security issues privately. Do not open a public issue with exploit details or real sensitive data.

Include:

- affected version or commit
- detector/configuration involved
- minimal synthetic reproduction
- expected and actual behavior

Avoid including real logs, tokens, emails, cookies, API keys, or customer identifiers. If a reproduction needs realistic data, replace values with synthetic equivalents.

## Scope

Security-sensitive issues include:

- sensitive values printed by `scan`, `assert`, errors, logs, or metrics
- redaction bypasses for supported detectors
- denial-of-service risks from crafted input
- panics on untrusted log lines
- unsafe handling of hash keys or secrets

`privacy-proxy` is a risk-reduction tool, not a guarantee of compliance with GDPR, HIPAA, PCI DSS, or other legal/regulatory frameworks.

