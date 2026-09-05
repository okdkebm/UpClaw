# Security Policy

## Reporting a vulnerability

UpClaw is an offensive-security tool — but the tool itself must be safe too.
If you find a security issue in the UpClaw codebase, **please disclose it
responsibly**:

1. **Do NOT** open a public Issue describing the vulnerability.
2. Report privately via **GitHub Security Advisory**
   (repo page → *Security* → *Report a vulnerability*) — preferred.
3. Or email the maintainer / reach admins in the QQ group `917335721`.

Include, if possible:
- Affected version(s) and the file/line if known
- A minimal reproduction (target can be any authorized/local lab)
- Suggested fix, if you have one

## Response timeline

| Step | Timeframe |
|---|---|
| Acknowledgment of receipt | within **48 hours** |
| Initial triage / severity assessment | within **3 days** |
| Fix released | **critical/high**: as soon as possible (target ≤ 7 days) · medium/low: next release |
| Public disclosure | after a fix is released and users have had time to update |

If the report is accepted, you will be credited in the release notes (unless you
prefer to stay anonymous).

## Supported versions

| Version | Status |
|---|---|
| latest (master) | ✅ actively supported |
| previous minor (v0.6.x and older tags) | ⚠️ best-effort — update to latest |

## Scope

This policy covers vulnerabilities **in the UpClaw code itself** — e.g. command
injection / path traversal in UpClaw's own request handling, unsafe parsing of
untrusted scan output, or a bypass of the authorization gate
(`require_authorization`).

**Out of scope:** vulnerabilities of external tools that UpClaw merely
orchestrates (nuclei / nmap / sqlmap / …); misuse of UpClaw against systems
without authorization — that is on the operator, not the code.

## Authorized-use reminder

UpClaw is **for authorized security testing, CTF, security education and
red-team exercises only**. Scanning, probing or exploiting systems without
written authorization is illegal in most jurisdictions; operators are solely
responsible for their actions.
