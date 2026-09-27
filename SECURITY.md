# Reporting a vulnerability

Please do **not** open a public issue for security problems.

Use GitHub's private vulnerability reporting ("Report a vulnerability" under
the repository's Security tab). Include the version (`nknguard version`), what
you did, what happened, and — if you have one — a proof of concept. A
diagnostics bundle (`nknguard diagnostics export`) is redacted and safe to
attach; please still review it first.

You will get an acknowledgement within 7 days. Fixes are released as a patch
version with a GitHub security advisory crediting the reporter unless you ask
otherwise.

The threat model — what NKNGuard does and does not defend against — is in
[docs/SECURITY.md](docs/SECURITY.md).
