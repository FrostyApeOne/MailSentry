# Multiple Microsoft mailboxes

MailSentry connects multiple independently authenticated personal Hotmail/Outlook accounts using one Entra public-client registration and the existing global `MicrosoftGraph:ClientId`. The permissions remain delegated `Mail.ReadWrite` and `User.Read`. There are no client secrets or application permissions.

## Upgrade an existing installation

1. Stop the Web UI and the scheduled scan task. Do not run the old and new application versions together.
2. Back up the existing installation, especially `appsettings.json`, `data/`, and `signatures/`. Keep that backup private.
3. Extract the new package into a separate directory. Restore the **existing server** `appsettings.json`, data directory and chosen signature packs into it; do not replace your settings with the packaged starter configuration. Alternatively deploy updated program/runtime/web files in place while preserving those three items. Review absolute paths in configuration and update scheduled task paths if the installation directory changes.
4. Run the upgraded Web UI under the **same Windows account on the same machine**, with the same Client ID and data directory.
5. Migration automatically reads `data/auth-record.bin` when present, otherwise the legacy `auth-record.json` in the working/executable directory. It validates the client/authority and record identity, copies that record into encrypted account storage, and records a migration marker. Existing scan/review state is imported into that account. Source files are retained for recovery.
6. The Dashboard initially shows the migrated mailbox with authentication **Not checked**. Its next scan uses the exact migrated record to acquire tokens silently from the existing encrypted `JunkCleanerV2` cache. Microsoft Graph `/me` verifies and binds its Graph user ID before any mail is read or moved; status becomes **Connected** on success.
7. Resume the existing Web and scan tasks. Continue using **one** scheduled `MailSentry.exe --scan` task: it scans all enabled mailboxes.

Migration is idempotent. A completed migration is not repeated, even if the migrated mailbox is later removed. The marker prevents old recovery files from re-registering a removed mailbox. An interrupted migration can retry without overwriting an already registered identity. No Graph calls or interactive login are needed to import a valid record.

A fresh sign-in is needed if the Windows identity/machine has changed, the cache is missing/revoked, or the old record cannot be decrypted/validated. A safe migration error is shown rather than selecting an arbitrary cached account. Use Add Microsoft Account for the missing mailbox; use Re-authenticate when the account already exists. Do not copy DPAPI state or token caches between machines/users.

## Add your second Hotmail account

1. Open the upgraded MailSentry Dashboard.
2. Select **Add Microsoft Account**.
3. Wait for the Microsoft sign-in code and select **Open Microsoft sign-in**.
4. Enter the code and sign in with your **second** Hotmail/Outlook account. If Microsoft offers the first account, select **Use another account**. A private browser window can help choose a different identity. Consent to the delegated permissions if Microsoft requests it.
5. Return to MailSentry. Status refreshes automatically. The second masked mailbox appears as **Connected**, **Enabled**. The first account remains registered with its own authentication and state.
6. Keep/re-enable global DryRun for the first multi-account trial if you want to inspect results without moving mail. Select **Scan Now**: every enabled account is scanned sequentially.
7. Check each mailbox's result and Unmatched Junk. When ready for live quarantine, set global `MailSentry:DryRun` to `false` and restart the Web UI. Scheduled processes read configuration on each launch.

Adding an already registered Microsoft identity updates that account's authentication instead of duplicating it. A disabled account stays disabled during re-authentication or duplicate sign-in.

## Manage accounts

- **Re-authenticate**: use the action on the affected account and sign in to that same Microsoft identity. Signing in as another account is rejected; its record cannot replace the target's record. Use Add Microsoft Account to register a different mailbox.
- **Disable / Enable**: retain authentication and previous state while excluding/including that mailbox in aggregate scans, review exports and previews.
- **Remove**: explicitly confirm the account's removal. Its registration, encrypted authentication and operational document are removed. For the migrated account, matching legacy authentication and old single-account state are also cleaned up. Other accounts are untouched. Emails, folders and Microsoft consent are not deleted/revoked.

Account changes and signature operations cannot modify state during an aggregate scan. Retry when it completes. Authentication/device-code waiting does not hold the scan lock; after sign-in it waits for the lock before committing the account update. Only one device-code flow runs per installation at a time, including across processes.

## Clear one mailbox's quarantine

Each Dashboard mailbox card has **Wipe quarantine mails**. It first counts the messages in that mailbox's configured quarantine folder, then asks you to confirm the mailbox, folder and count. Confirmation moves those messages to that mailbox's **Deleted Items**; it does not permanently delete them. Global DryRun reports what would happen and performs no mailbox writes.

This clears the current direct contents of the dedicated quarantine folder, including messages manually placed there. MailSentry has no historical per-message ledger to distinguish earlier automated moves from manual additions. Keep that folder dedicated to quarantine. Child folders are untouched. A missing folder is treated as empty and is never created by cleanup.

The operation uses the shared scan/account/signature lock, checks standard folder identities to protect Inbox/Junk/Deleted Items and other default folders, collects all pages before moving anything, and rejects confirmation if the account or folder contents changed since preview. Previews expire after five minutes. Messages restored elsewhere during cleanup are skipped. Failures stop the operation and report partial progress; preview again to retry. Cleanup is bounded to 100,000 messages and five minutes per operation. It is an explicitly confirmed manual action and is also available for disabled accounts; disabling still prevents aggregate scans.

## Identity and storage boundaries

- Stable random GUIDs identify MailSentry registrations and storage directories; raw email addresses are not filenames.
- `data/accounts/catalog.bin` is a versioned, DPAPI-encrypted catalog with registration IDs and migration state.
- `data/accounts/<id>/account.bin` is one atomically replaced, DPAPI-encrypted document containing that account's Microsoft identity association, serialized Azure.Identity AuthenticationRecord, enabled/authentication state and scan/review state. Registration and record updates cannot expose a partly written document.
- `data/scan-run.bin` stores encrypted aggregate outcomes. Legacy `scan-state.bin` is retained only for migration/recovery until its account is removed.
- Tokens remain in Azure.Identity's existing encrypted `JunkCleanerV2` cache, not in account documents. Plaintext fallback is disabled. This cache supports multiple identities; an explicit AuthenticationRecord selects the identity for every silent credential. Removing an account never clears the shared cache, which could invalidate unrelated accounts. Unreferenced cached tokens are managed by the SDK; MailSentry cannot use them through a removed registration.
- Authentication checks both the record's HomeAccountId and, once verified, Graph's stable `/me` user ID. A session is bound to one registration. Messages carry that registration ID; a session rejects quarantine requests for another account before making any request.
- A shared process/file lock serializes scanning, account mutations, migration and signature activation. Mailboxes are scanned sequentially, with a five-minute timeout per mailbox. A failure marks only that account and processing continues. Corrupt account documents are reported separately while healthy accounts continue. A damaged catalog remains a global storage failure requiring restoration.
- API responses and audits expose safe account identifiers/masked mailboxes, not AuthenticationRecords, HomeAccountIds, Graph user IDs or tokens. Unmatched selections use account ID plus message ID so equal Graph IDs in different mailboxes cannot cross-select. Existing copy redaction is preserved.

## Shared signatures and operational results

Signatures, allow lists, threshold, DryRun and quarantine folder **name** remain global. Each mailbox has its own mailbox-local quarantine folder. Global DryRun prevents all mailbox writes across every account.

Signature preview evaluates the latest unmatched snapshot from every enabled mailbox and reports tested/new-SPAM counts and subjects per masked mailbox. It never moves mail. Confirmation installs the shared pack and re-evaluates enabled review snapshots. Actual quarantine waits for a live scan. Any account registration, enabled state, authentication/scan state, message or signature change invalidates the old preview; preview again before confirming.

The Dashboard's message totals combine the latest successful scan per enabled mailbox. A failed mailbox can still display its prior successful scan alongside its current failure status. Aggregate outcomes distinguish Success, Partial success, Failed and No enabled accounts. Exit code 0 means every enabled mailbox completed; 1 includes partial failure, cancellation, no enabled accounts or a busy scan; 2 means invalid startup/configuration. Audit events use the stable safe account ID.

## Security controls and limitations

The same HTTPS, admin-password, allowed-host, CSRF, security-header, DPAPI, encrypted-cache, signature-validation and no-permanent-delete controls still apply. Account endpoints have the same administrative access checks as existing operations. There is no global mutable current account or current Graph client.

The Web UI and scheduled scanner must run as the same Windows user with its profile loaded. Account management is administrative; there is no separate per-mailbox administrator/role model. Parallel mailbox scans, Gmail/IMAP and a quarantine browser are not part of this change. Preview uses stored review snapshots, not a fresh mailbox read. Live Microsoft login/consent and server-profile behavior still need a manual check on your deployment; automated tests use synthetic credentials and fake Graph responses.

SDK references used to verify cache/record behavior:

- https://learn.microsoft.com/en-us/dotnet/api/azure.identity.tokencachepersistenceoptions
- https://github.com/Azure/azure-sdk-for-net/blob/f7400e4471111bf7f2154834022786119acbdd77/sdk/core/Azure.Core/src/Identity/Credentials/InteractiveBrowserCredential.cs
- https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/core/Azure.Core/src/Identity/MsalPublicClient.cs

## Emoji signature correction

The bundled `006-emoji-spam.json` now uses explicit JSON Unicode escapes for the intended emoji. Earlier copies contained literal `?`/`??` values that could match ordinary question marks. Replace that bundled pack when upgrading, retain custom packs and review results in DryRun. Regression tests cover ordinary questions, every supported emoji, corroborating generated domains, allow-list precedence and body-only emoji.
