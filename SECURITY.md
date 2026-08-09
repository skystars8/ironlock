# Security Policy

## Supported versions

Security fixes are applied to the latest release line. Reports are welcome for
every version and for the current `main` branch, even when the affected version
is no longer eligible for a patch.

| Version | Supported |
| --- | --- |
| 0.2.x and current `main` | Yes |
| 0.1.x and earlier | No |

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use
[GitHub private vulnerability reporting](https://github.com/christurgeon/ironlock/security/advisories/new).
If that form is unavailable, email the maintainer address listed in
`Cargo.toml` with the subject `Ironlock security report`.

Include the affected version, operating system, impact, reproduction steps, and
any suggested mitigation. Do not attach real passwords, plaintext, private
keys, or irreplaceable encrypted files; use disposable test data.

The project aims to acknowledge a report within seven calendar days and will
coordinate validation, remediation, release timing, and credit with the
reporter. Please allow a reasonable remediation window before public disclosure
and notify the maintainer before publishing details. Active exploitation or
immediate user harm may require an accelerated disclosure and release schedule.

## Security scope

Reports about authentication bypasses, plaintext disclosure, file corruption or
loss, path traversal, unsafe link handling, denial of service from hostile
encrypted files, cryptographic misuse, and dependency vulnerabilities are in
scope.

The documented limitations of best-effort `--shred`, password guessing, and
legacy v1 filename metadata are not vulnerabilities by themselves. Reports that
show a materially worse outcome than the documented limitation are welcome.
