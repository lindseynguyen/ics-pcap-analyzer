# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems in the analyzer
itself (for example a crafted capture that causes code execution, a crash
used for denial of service, or credential leakage).

Instead, use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on the repository page.
Include a description, the affected version and, if possible, a minimal
reproducer. We aim to acknowledge reports within 7 days.

## Scope notes

- The analyzer parses untrusted capture files. Parser crashes or excessive
  CPU/memory use on crafted input are in scope.
- Missed detections or false positives in the analysed traffic are **not**
  security vulnerabilities of this project — please open a normal issue.
- Never attach captures containing real credentials, customer data or
  sensitive plant information to public issues.

## Supported versions

Security fixes are made on the latest release on `main`.
