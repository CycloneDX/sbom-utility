# Security Policy

`sbom-utility` is an [OWASP Foundation](https://owasp.org) project under the
[CycloneDX](https://cyclonedx.org) community. We take security reports seriously
and follow coordinated disclosure.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.** Public reports expose users before a fix is
available.

Report vulnerabilities by following the OWASP Foundation's security reporting
process:

- https://owasp.org/security

That page describes the current process for all OWASP projects, including how
to submit a report through the **OWASP Vulnerability Disclosure Program (VDP)**
and the terms that apply. The VDP is a disclosure program, not a paid bug
bounty.

When you submit, please ask for **@mrutkows** (Matt Rutkowski), the project
owner, to be copied or notified — either through the VDP submission itself or
out-of-band via a private Slack direct message. Do not describe the issue in
any public Slack channel.

## What to include

A short, reproducible write-up is more useful than a long theory. Please
include:

1. The affected repository, command, and version (`sbom-utility version`).
2. A clear description of the issue and why it matters.
3. Steps another person can follow to reproduce it.
4. What an attacker could do if the issue is real.
5. Whether the finding is already public, and any related CVE or advisory.

## What to expect

1. **Triage.** OWASP Foundation staff review incoming reports and route valid
   issues to the project maintainers.
2. **Assessment.** Maintainers confirm the impact and determine affected
   versions.
3. **Fix.** A patch is prepared and released, and we agree with you on when it
   is safe to discuss the issue publicly.
4. **Disclosure.** Once users have a way to update, the fix is published in a
   release and, where warranted, a GitHub Security Advisory. Reporters who want
   credit are named unless they ask otherwise.

Please keep the report confidential until disclosure has been coordinated.

## Supported versions

Security fixes are applied to `main` and shipped in a new release. Only the most
recent release is supported — please upgrade to the
[latest release](https://github.com/CycloneDX/sbom-utility/releases/latest)
before reporting an issue, and confirm the problem still reproduces there.

Advisories, affected versions, and fixed versions are published with the
release that contains the fix rather than in a separate catalogue.

## Scope

This policy covers the `sbom-utility` CLI, its libraries, its optional GUIs, and
this repository's build and release tooling.

It does not cover vulnerabilities in the software described *by* a BOM that the
utility processes. Report those to the vendor or project that produces the
affected component.

## Please do not

- Open a public issue or pull request describing an unfixed vulnerability.
- Run denial-of-service tests, spam, or automated scanning that overwhelms a
  service.
- Access, copy, or change data that is not yours.
- Report missing security headers, version banners, or similar low-signal
  findings unless the VDP terms explicitly ask for them.

OWASP has committed that good-faith research following the VDP terms will not
be treated as a hostile act. The VDP terms, reached from
https://owasp.org/security, govern scope and safe-harbour language.

## Questions

Questions about the OWASP disclosure process that are **not** vulnerability
reports can go to <security@owasp.org>. Please do not send exploit details by
email — those belong in the VDP submission.

For non-security bugs and feature requests, use the
[issue tracker](https://github.com/CycloneDX/sbom-utility/issues).
