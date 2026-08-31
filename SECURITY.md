# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately via GitHub's [private vulnerability
reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
(Security → Report a vulnerability on this repository).

Please include: what you found, how to reproduce it, and what an attacker could
do with it. A response should be expected within a few days; this is a personal
project maintained in spare time, so please be patient.

## What counts as a vulnerability here

This is an OSINT tool, so the interesting failure modes are not only the usual
ones:

- **Credential leakage** — anything that writes an API key, token or session to
  disk outside `.env`, into a report, into `memory/`, or into a log.
- **Guardrail bypass** — anything that makes the tool fetch a `.onion` service,
  download a file, follow a result link, or reach a host outside the allow-list.
  These are hard boundaries, not preferences.
- **Unauthorised outbound data** — anything that transmits an input image, a
  target's details, or local file contents to a service the user did not
  configure.
- **Face-based identification** — the vision pass must never map a face to a
  name. A prompt or code path that induces it to do so is a bug, and one I care
  about more than most.
- **Injection through fetched content** — search results and page text are
  untrusted input. Anything that lets a fetched page steer the agent's tooling
  or exfiltrate data is in scope.

## Not vulnerabilities

- The tool finding public information about a person. That is its purpose;
  see the Responsible use section of the README for the boundaries.
- Rate limits, quota exhaustion, or an upstream engine blocking automated
  queries. Black Noir does not attempt evasion by design.
- Missing results. An empty result is a statement about an index, not a defect.

## Handling secrets in this repository

`.env` is gitignored and must never be committed. `.env.example` contains blank
placeholders only — if you ever find a real value in it, that is a reportable
issue.

If you believe a credential has been exposed, rotate it first, then report.
