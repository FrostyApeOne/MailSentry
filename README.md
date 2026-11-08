# MailSentry

Your email provider decides what's Junk. MailSentry decides what's safe to remove.

An open-source, signature-driven email spam cleaner that filters high-confidence spam from your Junk folder while preserving uncertain messages for review.

MailSentry reads only Outlook's `junkemail` folder. SPAM moves to a dedicated quarantine folder, REVIEW and explicitly TRUSTED mail stay untouched. There is no permanent-delete operation. New installations default to DryRun, which performs no mailbox writes.

## Repository structure

- `src/MailSentry.Core`: provider-neutral classification, signature validation/loading, models and operational storage.
- `src/MailSentry.MicrosoftGraph`: delegated authentication, Junk reading and quarantine actions; references Core.
- `src/MailSentry.Web`: administration UI and scan coordination; references Core and MicrosoftGraph.
- `tests/MailSentry.Tests`: regression and integration tests.
- `signatures`: shared JSON signature packs linked into application/test output and publishing.

`AGENTS.md`, the solution, documentation and example configuration remain at the repository root. Local `appsettings.json` and legacy `auth-record.json` also remain there, ignored by Git. The Web project links local configuration into its build output and excludes it from publishing. Application output remains at the repository's `bin/Debug/net8.0` (or Release) to preserve existing relative data paths and the executable name `MailSentry`.

## Setup

Requires Windows, the current .NET 10 LTS SDK (10.0.403 or later, as selected by `global.json`) for development, and one or more personal Outlook/Hotmail mailboxes. Self-contained Windows packages include the runtime. Framework-dependent deployments require the current ASP.NET Core 10 runtime.

1. In Microsoft Entra, register an application supporting **personal Microsoft accounts** (or organisational and personal accounts).
2. Add the **Mobile and desktop applications** platform and `http://localhost` redirect URI for the existing delegated cache flow. Enable **Allow public client flows** for device-code sign-in.
3. Add Microsoft Graph **delegated** permissions `Mail.ReadWrite` and `User.Read`. Do not configure application permissions or a client secret. Microsoft supplies consent during login; delegated public clients use no application secret.
4. Copy `appsettings.example.json` to `appsettings.json`. Set `MicrosoftGraph:ClientId` to your application's client ID. Set `Admin:Password` to a unique password of at least 16 characters, or supply `MAILSENTRY_Admin__Password` through protected process/service settings. Keep `DryRun: true` while reviewing results. Never commit the configured file or password.
5. Build and test, then launch the operational console:

```powershell
dotnet build MailSentry.sln
dotnet test MailSentry.sln --no-build
dotnet run --project src/MailSentry.Web/MailSentry.Web.csproj --no-build -- --web --urls http://localhost:5080
```

Open `http://localhost:5080`, log in with username **admin** and your configured admin password, then select **Add Microsoft Account** (or **Re-authenticate** for an existing mailbox), follow Microsoft's device-code link and enter the displayed code. Sign in with the intended personal mailbox. The console never displays tokens or authentication records. Select **Scan Now** after authentication.

A scheduled scan never opens a browser or starts device-code authentication. Missing/expired/revoked credentials mark only that account as requiring authentication. Other enabled mailboxes are still scanned. Recover with that account's Re-authenticate action in the Web UI.

```powershell
dotnet run --project src/MailSentry.Web/MailSentry.Web.csproj --no-build -- --scan
```

No mode flag also runs one scan and exits. Exit codes: 0 all enabled mailboxes succeeded; 1 partial success, failed/cancelled scan, no enabled accounts or concurrent scan; 2 invalid configuration/startup failure. Web requests report safe error messages.

## Multiple Microsoft accounts

Use one existing Entra Client ID with independently authenticated Hotmail/Outlook accounts. Add, re-authenticate, enable/disable and remove mailboxes from the Dashboard. Scan Now and the single scheduled `--scan` task scan all enabled accounts sequentially. Signatures and DryRun remain global; quarantine folders are local to each mailbox.

See [multi-account setup, migration and security](docs/multi-account.md). Existing authentication migrates automatically when the same Windows identity, computer, Client ID and data directory are retained.

## Configuration and migration

Configuration loads from `appsettings.json` beside the executable, followed by optional `appsettings.<Environment>.json` (normally `appsettings.Production.json`). Existing environment-variable formats remain supported: `Admin__Password`, `ASPNETCORE_Admin__Password`, `ASPNETCORE_Kestrel__Certificates__Default__Path` and the corresponding certificate password setting continue to work. `__` represents nesting. Precedence, from lowest to highest: base JSON, environment-specific JSON, `ASPNETCORE_` variables, `DOTNET_` variables, ordinary environment variables, `MAILSENTRY_` variables, then command-line settings. New installations can use `MAILSENTRY_Admin__Password` and `MAILSENTRY_MailSentry__DryRun=true`; existing installations do not need to rename their variables. An explicit `--configuration-file` replaces the JSON files with the selected file; environment and command-line overrides still apply. Configuration changes require restart; signatures reload for every scan and preview without restart. Relative data/signature paths resolve beside the executable. During development this is `bin/Debug/net8.0`; use absolute configured paths if editing signature packs directly in the checkout.

The rename retains the existing local DryRun setting, quarantine folder name, and encrypted token-cache name `JunkCleanerV2` deliberately for migration. A legacy `auth-record.json` in the working directory (or beside the executable) is read only as a migration fallback. Authentication records and operational state now live in DPAPI-encrypted `data/accounts/<stable-id>/account.bin` documents, indexed by an encrypted catalog. Existing single-account data is imported automatically and retained for recovery. New sign-ins use the same encrypted token cache and a separate authentication record for each account. The legacy file is never published. Once re-authentication works, archive/remove the old record locally if desired. Existing local installations with DryRun disabled remain in live quarantine mode.

`SpamThreshold` must be at least 7. Exact sender/domain allow lists precede all scoring. Domains match exactly, including no implicit subdomains. Broad brand domains are not automatically trusted; From addresses can be spoofed. The maximum scan batch defaults to 500; messages beyond the limit wait for a later scan.

MailSentry also reads Microsoft's SPF/DKIM/DMARC results and detects common Unicode lookalikes in financial-brand sender names. Bundled packs `007-authentication.json` and `008-financial-impersonation.json` add supporting scores; neither signal alone reaches the default SPAM threshold. No address, including your own, is automatically blocked. Unmatched Junk and copied exports include safe authentication results and lookalike comparison text. Existing stored messages acquire authentication evidence on their next scan. See [signature fields, examples and detection limits](docs/signatures.md).

Signature loading reuses validated packs by content hash. Dashboard polls receive a compact cached summary; scans, previews and activation still verify current file contents, including edits that preserve timestamps. See [cache behavior and performance measurements](docs/signature-loading.md).

## Operational console

- Dashboard: account management, masked per-mailbox status, last successful scans, aggregate statistics, partial-success results, signature count and Scan Now. Each mailbox also has **Wipe quarantine mails**, which previews and confirms moving its quarantine contents to Deleted Items, respecting global DryRun.
- Unmatched Junk: REVIEW messages from enabled accounts, masked source mailboxes, scores/reasons, body previews, account-specific selection and sanitised copy. Copied text contains sender identity needed for classification, but omits internal IDs and strips links and incidental email addresses from text. Review exports before sharing; automatic redaction cannot identify every personal detail.
- Signatures: loaded files and validation errors, JSON file upload or pasted JSON with an automatically generated filename, impact per enabled mailbox on the current unmatched snapshot, cancel, and explicit Install & Activate. Preview installs nothing. Changed signatures, messages, account registrations or authentication state invalidate the preview; upload again to review fresh impact. Previews expire after 15 minutes and disappear on restart. Activation re-evaluates unmatched messages; actual quarantine occurs on the next scan in live mode.

Preview is based on the last completed scan, not a fresh mailbox read. Scan first for current results. Trusted messages are excluded from unmatched messages. The UI is an operational console, not a mail client.

Click a saved filename on the Signatures page to view its JSON in a read-only text area (up to 1 MB). **Delete signature file** asks for confirmation and removes that file's rules from the shared repository for every mailbox. Malformed packs are listed too, so they can be inspected and removed. Changed files must be reopened before deletion; scan locks and administrative/CSRF checks also apply. Deletion cancels pending activation previews and reloads the remaining packs without a restart. Existing emails are untouched; run a new scan to refresh unmatched results. Deleting the last pack leaves no spam rules. Bundled packs may be copied back by a subsequent source build or deployment, so manage your deployed repository separately when upgrading.

## Windows deployment

For a self-contained Windows ZIP (no separate .NET install on the server), run from the repository root:

```powershell
.\scripts\Publish-Windows.ps1
```

The script creates a new timestamped folder and ZIP under `publish/`, including safe starter configuration, launch scripts, and [server setup instructions](deployment/windows/START-HERE.md). It excludes local credentials and operational data. See the included `START-HERE.md` for authentication and Task Scheduler setup.

For a framework-dependent publish instead:

```powershell
dotnet publish src/MailSentry.Web/MailSentry.Web.csproj -c Release -o publish/MailSentry
```

Publishing includes the executable, web assets and bundled signatures. It deliberately excludes local configuration, authentication records and runtime data. Copy `appsettings.example.json` to `appsettings.json` in the deployment directory and configure it there. Do not overwrite deployed signature packs with older bundled packs during an upgrade; preserve custom packs and use a backup. Preserve the configured data directory.

Run `MailSentry.exe --web --urls http://localhost:5080` as an always-on process. In Windows Task Scheduler, create a periodic task running the full path to `MailSentry.exe` with argument `--scan` and Start in set to the deployment directory. Use the **same Windows account and loaded user profile** for web and scanner; both must use the same absolute data/signature paths. DPAPI and the encrypted Azure.Identity cache are user-bound. Select �Do not start a new instance� in Task Scheduler as an additional precaution. The application also uses a file lock shared by scanners and signature activation.

Every Web console requires an admin password of at least 16 characters, including localhost. Startup fails safely if it is missing; scheduled `--scan` does not require it. For mobile access, configure HTTPS on the Windows host, exact hostnames in both `Admin:AllowedHosts` and `AllowedHosts`, and private-network/VPN access. Direct HTTP is permitted only on loopback, with authentication. Forwarded headers never grant trust: HTTP requests carrying `Forwarded` or `X-Forwarded-*` headers are rejected. A reverse proxy must use HTTPS on its connection to MailSentry as well as on the browser-facing connection; HTTP proxy termination is unsupported. Do not publish the loopback HTTP binding through a proxy or port forward. Protect the configured password, certificate and configuration with Windows ACLs; do not commit them.

The .NET 10 upgrade deliberately retains the historical `bin/Debug/net8.0` development directory (and Release equivalent) to preserve existing relative authentication, data and signature paths. The folder name does not indicate the runtime version. Production upgrades likewise retain the configured data directory, Windows identity, Client ID and token-cache name; changing the runtime does not require a Microsoft sign-in.

## Signatures and safety

See [signature format](docs/signatures.md). Six numbered packs migrate the original rules and include conservative corroborated campaign patterns. Generated senders and emoji alone stay REVIEW. Emoji in body text alone does not score. Generic �congratulations + bonus� was narrowed to stronger gambling terms. Allow-list precedence fixes the original implementation's unused allow-list settings. These deliberate safety changes reduce false positives.

Malformed JSON, unknown fields/operators, invalid scores/conditions/regexes, duplicate properties and duplicate IDs are rejected. Any invalid pack disables scoring for the entire repository snapshot; scans stop safely and UI/logs show the failure. Regex evaluation has a timeout; evaluation failure returns REVIEW. Uploads are capped at 1 MB. Validation cannot prove semantic accuracy: review every signature and its impact before activation. Only trusted administrators should write signature files. Manually adding a valid file to the configured directory makes it available next scan; use the UI for preview and confirmation.

## State, security and maintenance

Daily `data/audit-YYYY-MM-DD.log` files record scan boundaries, classifications/scores, signature failures, quarantine actions, authentication events, failures and summaries. They exclude credentials and message content. `data/accounts/<stable-id>/account.bin` contains each account's encrypted authentication record and operational/review state. `data/accounts/catalog.bin` indexes registered accounts and migration state, and `data/scan-run.bin` records aggregate outcomes. The old `data/scan-state.bin` is only read for legacy migration. Authentication records use DPAPI; token caches use Azure.Identity encrypted persistence, with no plaintext fallback. Protect data/signature/config directory ACLs and backups. Keep logs only as long as needed; rotate/archive old daily logs yourself. The scanner has a five-minute timeout; interactive sign-in has a ten-minute timeout.

`.gitignore` excludes local configuration, environment files, private certificates/keys, authentication files, caches, generated build/publish outputs and operational data. No local `appsettings.json` or live mailbox access is needed for tests; HTTP tests select an isolated synthetic file using `--configuration-file`, and Graph tests use an in-memory HTTP handler. Windows CI builds, tests and publishes from a clean checkout. Build/test verification cannot replace a real delegated login and a DryRun trial on your own mailbox. Do those before enabling live quarantine. MailSentry never permanently deletes messages.

The publisher checks Microsoft's .NET 10 release metadata online and verifies both bundled runtimes before creating an archive. Use the latest servicing SDK and republish when security updates arrive; an installed system runtime cannot patch a self-contained package. See [security and public-release checks](docs/security.md).

## License

MIT; see [LICENSE](LICENSE).
