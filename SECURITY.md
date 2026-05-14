# Security Policy

apisniff captures and analyzes HTTP traffic. Raw captures can contain cookies, bearer tokens, API keys, request bodies, and other sensitive data.

## Reporting a vulnerability

Please report security issues with a private GitHub security advisory, if available. If private advisories are not available, open a public issue asking for a secure contact path, but do not include exploit details, captured credentials, or private traffic in the issue.

Include:

- A description of the issue and affected command or file.
- Steps to reproduce.
- The impact you believe it has.
- Any suggested fix, if you have one.

## Scope

Security reports are especially relevant for:

- Raw capture storage and file permissions.
- Redaction in reports, specs, and `apisniff share` output.
- Replay behavior that could send unsafe requests unexpectedly.
- Proxy and certificate handling.
- Handling of cookies, auth headers, API keys, and request bodies.

## Safe use

Run apisniff only against systems you own, administer, or have explicit permission to test. Do not share raw capture bundles. Use `apisniff share` when you need a derived export for another person or repository.
