# MailSentry on an always-on Windows server

This package targets 64-bit Windows (win-x64). It includes the .NET and ASP.NET Core runtime: no SDK, IIS or separate .NET installation is required. Keep the entire extracted folder together; MailSentry.exe needs its accompanying files. The server needs outbound HTTPS to Microsoft sign-in and Microsoft Graph.

## First run

1. Extract the ZIP to a permanent directory writable by the Windows account that will run MailSentry. Avoid running from inside the ZIP or from a temporary directory.
2. Edit the included `appsettings.json`. Replace `MicrosoftGraph:ClientId` with the client ID from your existing working configuration, or register an application as described below. Set `Admin:Password` to a unique password containing at least 16 characters; the Web console will not start without it, including on localhost. Alternatively provide `MAILSENTRY_Admin__Password` through protected settings for the process/task. Restrict configuration and directory permissions to the running Windows account and administrators. The package contains a safe starter configuration, not your development configuration. Keep `DryRun` set to `true` initially. If you already use a quarantine folder, set `QuarantineFolderName` to its existing name.
3. Sign into Windows on the server as the Windows account that will run both the UI and scheduled scans. Run `Run-Web.cmd`.
4. Open `http://localhost:5080` **on the server** (for example through Remote Desktop). Log in with username **admin** and the admin password you configured. Select **Add Microsoft Account** (or **Re-authenticate** on an existing account). Follow Microsoft's device-code link and enter the displayed code. You can complete the Microsoft login in another browser/device, but access the MailSentry console on the server for this initial setup.
5. Choose **Scan Now** and review the results in DryRun mode. It classifies but makes no mailbox changes. Use the Signatures page to upload or paste additional packs, review their impact, and confirm installation. Only the bundled packs are included; custom packs installed in your development instance must be transferred separately.
6. Once satisfied, stop the console with Ctrl+C, change `DryRun` to `false`, and restart it. SPAM then moves to the configured quarantine folder. REVIEW and TRUSTED messages remain in Junk. Nothing is permanently deleted.

Do not copy token caches, `auth-record.json`, or encrypted `data/` from your development computer. Authenticate on the server instead: DPAPI and cached credentials are tied to the Windows account/machine. Both scheduled tasks must use the same Windows account and application directory as the interactive setup. Do not use SYSTEM or a different service account for scheduled scans.

## If you need an Entra application

Register an application supporting personal Microsoft accounts. Add the Mobile and desktop applications platform with `http://localhost` redirect URI, enable **Allow public client flows**, and add Microsoft Graph **delegated** `Mail.ReadWrite` and `User.Read` permissions. No client secret is required. If your existing client ID already works with MailSentry's device-code flow, reuse it.

## Keep the UI running after reboot

In Windows **Task Scheduler**, choose **Create Task**:

- Name: `MailSentry Web`.
- Run as the same Windows account used for authentication.
- Select **Run whether user is logged on or not**, and supply that Windows account's password in Task Scheduler. Leave **Do not store password** unchecked so the task can use encrypted user credentials and network access. Ensure this account has a loaded user profile.
- Trigger: **At startup**, optionally with a 30-second delay.
- Action: start the full path to `MailSentry.exe`.
- Arguments: `--web --urls http://localhost:5080`.
- Start in: the directory containing `MailSentry.exe`.
- Settings: restart after failure (for example after one minute); **Do not start a new instance**; disable **Stop the task if it runs longer than** for this always-on task.
- On machines with power conditions, disable the AC-power restrictions if appropriate for your server.

Stop a manually started `Run-Web.cmd` instance before starting this task, otherwise port 5080 will already be in use. Start the task once and check the console in a browser. The executable is a console application managed by Task Scheduler, not a registered Windows Service.

## Scan automatically

Create a second task named `MailSentry Scan` using the **same account**:

- Trigger: daily, repeat every five minutes for an indefinite duration.
- Action: full path to `MailSentry.exe`.
- Arguments: `--scan`.
- Start in: the application directory.
- Settings: **Do not start a new instance**; run as soon as possible after a missed start.
- Use the same logon/password/profile settings as the Web task.

The Web UI staying open does not scan periodically by itself; this second task performs scheduled scans of every enabled Microsoft account, sequentially. You do not need a task per mailbox. Each scan exits when finished. A shared file lock prevents overlapping scans or signature activation. Start scheduled scans only after the initial DryRun review. Authentication expiry stops scanning safely; use the UI to re-authenticate.

Scan exit codes: 0 all enabled accounts succeeded; 1 partial success, account failure, no enabled accounts, cancellation or an overlapping scan; 2 invalid configuration/startup failure. A failed account does not stop the others. Daily audit logs are under `data/`. Check Task Scheduler history and the dashboard if a task fails.

## Access from your PC or phone

The supplied launcher binds only to localhost. `localhost` on your laptop/phone points to that device, not the server. The simplest initial access is a browser on the server via Remote Desktop. For network access, configure an HTTPS endpoint/certificate, exact hostnames in both `AllowedHosts` and `Admin:AllowedHosts`, and private-network/VPN firewall access. The admin password is always required. Remote HTTP is rejected. Forwarded headers never establish trust; HTTP requests carrying proxy-forwarding headers are rejected even on loopback. A reverse proxy must connect to MailSentry over HTTPS and serve browser clients over HTTPS. Do not proxy or port-forward the local HTTP binding.

## Updating and backups

Stop both scheduled tasks and any manual Web instance before updating. Back up `appsettings.json`, your `signatures/` directory and `data/`. Extract a new package into a separate directory, then restore your server configuration and chosen signature packs rather than overwriting them with the starter files. Preserve the Windows account and data directory. Review signature ID duplicates if combining packs. Start the tasks again and verify the dashboard.

This release upgrades the bundled runtime to .NET 10 LTS. Existing Microsoft authentication can be retained on the same machine and Windows profile. Add an admin password to your preserved settings before starting the new Web console. Replace the old bundled `006-emoji-spam.json` with the corrected copy from this release: earlier copies contained literal question marks instead of emoji and could match ordinary questions. Preserve your custom packs, avoid duplicate IDs, and review the updated results in DryRun before enabling live scanning. Do not reuse old self-contained executables/runtime DLLs.

The runtime is bundled: republish/redeploy when .NET runtime updates are needed. Backups may contain private mail previews and encrypted credentials; restrict access to the application directory and backups. Audit logs contain operational events, not full message bodies. Archive old daily logs according to your retention needs.

## Environment settings and startup troubleshooting

Existing `Admin__Password`, `ASPNETCORE_Admin__Password` and `ASPNETCORE_Kestrel__Certificates__Default__Path`/`Password` environment variables are supported; they do not need renaming. The `MAILSENTRY_` format is also supported and takes precedence if both forms exist. Optional `appsettings.Production.json` settings are loaded after base settings; retain any such private settings files when updating. Restart the process/task after changing environment variables and make sure they are available to the Windows account running MailSentry.

Startup errors identify the failing phase without printing configuration or exception values. A configuration error means checking JSON validity, settings file access and variable names. A storage error means checking the configured data path, permissions and original Windows account/profile used for DPAPI. A listener error means checking HTTP/HTTPS endpoints and certificate path, password and private-key access. Binding an `https://` URL requires a certificate; it does not provision one. Prefer an absolute certificate path. Preserve existing encrypted data and token caches while investigating startup errors.

Publishing reference: https://learn.microsoft.com/en-us/dotnet/core/deploying/

## Upgrading from the single-account version

See `docs/multi-account.md` for the migration and adding-account guide. Preserve your existing server appsettings.json, data/ and signatures/ when upgrading, and use the same Windows account, computer and Client ID. Automatic migration copies the legacy authentication record into encrypted account storage and keeps the existing encrypted Azure.Identity cache. It does not replace your configuration or reset DryRun. The original credentials remain as a recovery copy until you explicitly remove the migrated account. New installations or deployments to a different Windows account/computer need a fresh sign-in.
