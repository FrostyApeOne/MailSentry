# Security and public releases

MailSentry uses delegated personal-account Microsoft authentication. There are no client secrets or application permissions. Authentication records and operational snapshots use Windows DPAPI under the running user's profile; Azure.Identity's persistent token cache permits no plaintext fallback. Run the console and scheduled scanner under the same Windows account and protect configuration, data, signatures and backups with Windows ACLs.

The Web console always requires a unique admin password of at least 16 characters, including localhost. The username is `admin`. Set `Admin:Password` in your private configuration or `MAILSENTRY_Admin__Password` in protected process settings. No password is bundled or generated in logs. Basic authentication requires HTTPS for network access. Only authenticated direct loopback requests can use HTTP. Forwarded headers are not trusted; HTTP requests with forwarding headers are rejected. Reverse proxies must use HTTPS both to clients and to MailSentry. Host allow lists, CSRF checks and security headers also apply to account, signature and cleanup endpoints. This is a single-administrator console, not a multi-user mail service.

New installations default to DryRun. Unknown or invalid signatures stop scoring safely. Trusted senders/domains take precedence. Quarantine cleanup requires preview and confirmation and moves current direct contents to Deleted Items; it never permanently deletes messages. Keep the quarantine folder dedicated to MailSentry.

Email authentication evidence is accepted only from recognised Microsoft receiver header layouts above ingress; sender-supplied, ambiguous and unrecognised results supply no evidence. This relies on Microsoft transport headers and Graph preserving their order. MailSentry does not independently verify DKIM or perform SPF/DMARC DNS checks. Authentication failures can occur on legitimate forwarded mail, and passing authentication does not prove that a financial display name is authentic. The bundled rules require corroboration and leave either signal alone for review. Only finite result codes are retained: raw headers, sender IPs, diagnostics and authentication service identifiers are not stored, exported or logged. Unicode lookalike matching is opt-in for sender names and never changes address/domain allow-list comparisons. See [signature safety and limits](signatures.md).

## Before publishing source

1. Run `git status --short` and inspect `git diff --cached` before committing. Include source, example configuration, signatures, docs and tests only. Ignore rules do not remove files already committed; inspect history if adding this to an existing repository.
2. Never include local `appsettings.json`, environment-specific configuration, `.env`, client IDs belonging to your installation, real mailbox addresses/content, authentication records, token caches, `data/`, certificates/private keys, logs or existing deployment folders. Test identities and sample addresses must be synthetic.
3. On Windows with the current .NET 10 SDK, run `dotnet build MailSentry.sln` and `dotnet test MailSentry.sln --no-build`. A clean checkout needs no private configuration or live Microsoft login for tests. DPAPI tests need a loaded Windows user profile.
4. Run `dotnet list MailSentry.sln package --vulnerable --include-transitive` and review any findings. Package auditing does not audit the bundled .NET runtime.
5. Build fresh Windows packages using `scripts/Publish-Windows.ps1`. It checks current Microsoft runtime metadata and rejects outdated bundled .NET/ASP.NET Core runtimes or private output files. It never overwrites an existing deployment. Publish only the newly verified ZIP, checksum and source, not an older configured installation.

Self-contained applications must be republished and redeployed for runtime security updates. Keep the servicing SDK current. The public-source review and automated tests reduce risk; they are not a guarantee against every vulnerability. Test delegated sign-in and DryRun on your deployment before enabling writes.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting if enabled for the published repository. Do not post tokens, passwords, private configuration or mailbox contents in a public issue. If private reporting is unavailable, open an issue requesting a private contact without including exploit details or private data.
