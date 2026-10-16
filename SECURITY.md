# Security Policy

## Supported versions

RTNP is pre-1.0. Only the latest commit on `main` receives security fixes.

| Version | Supported |
| ------- | --------- |
| `main`  | Yes       |
| Older   | No        |

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub: go to the repository's **Security** tab and choose
**Report a vulnerability**
(https://github.com/evaneyou/RTN_PackGen/security/advisories/new).

If you cannot use GitHub, email evanyou@gmail.com with "RTNP security" in the subject.

Include the version or commit, how to reproduce the problem, and what you think the impact is.

You can expect an acknowledgement within 7 days and a status update within 30 days. If the report
is accepted, a fix is released and you are credited unless you prefer otherwise. If it is declined,
you will get an explanation.

## Scope

Of particular interest: authentication and TLS on the control and log channels, the remote-launch
agent, SRTP and SIP handling, and anything that lets a remote party read files, bypass the shared
key, or cause unbounded resource use. RTNP generates test traffic by design, so sending traffic
to a host you chose is not a vulnerability; see the Security section of the README for the known
limits.
