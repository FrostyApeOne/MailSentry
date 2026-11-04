# MailSentry

## Project Overview

MailSentry is an open-source, configurable second-stage email spam filter.

Its purpose is not to replace an email provider's existing spam detection.

Instead:

> Your email provider decides what's Junk. MailSentry decides what's safe to remove.

Microsoft Outlook/Hotmail is the first supported provider.

Microsoft's spam filtering places suspected messages into the Junk Email folder.
MailSentry performs a second, deliberately conservative classification pass over
those messages and identifies high-confidence spam that can safely be quarantined.

The primary safety principle is:

> False negatives are acceptable. False positives are not.

If MailSentry is uncertain, the message must remain in Junk for manual review.


# Technology

Current technology:

- .NET 10 LTS
- C#
- Microsoft Graph SDK
- Azure.Identity
- ASP.NET Core for the administration UI
- JSON-based signature files
- Microsoft personal Outlook/Hotmail accounts
- Delegated Microsoft authentication

Current deployment target:

- Always-on Windows machine/server
- Background scanning triggered periodically
- Initially Windows Task Scheduler
- Mobile-friendly administration UI

The architecture should not unnecessarily couple the classification engine to
Microsoft Graph. Other providers such as Gmail or generic IMAP may be supported
in the future.


# Repository / Naming

The product name is:

    MailSentry

Use MailSentry consistently for:

- solution
- projects
- namespaces
- executable
- configuration
- documentation

Suggested repository structure:

    MailSentry/
    ├── src/
    │   ├── MailSentry.Core/
    │   ├── MailSentry.MicrosoftGraph/
    │   └── MailSentry.Web/
    │
    ├── tests/
    │   └── MailSentry.Tests/
    │
    ├── signatures/
    │   ├── 001-core.json
    │   ├── 002-casino.json
    │   ├── 003-health-scams.json
    │   ├── 004-prize-scams.json
    │   ├── 005-generated-senders.json
    │   └── 006-emoji-spam.json
    │
    ├── AGENTS.md
    ├── README.md
    ├── LICENSE
    └── MailSentry.sln

Do not introduce unnecessary projects or architectural layers simply to match
this suggested structure. Prefer the smallest clean architecture that achieves
the required separation.


# Current Processing Model

MailSentry currently reads messages only from the Microsoft Outlook well-known:

    junkemail

folder.

Messages are classified as:

- SPAM
- REVIEW
- TRUSTED

Behaviour:

SPAM:
    Move to MailSentry quarantine.

REVIEW:
    Leave untouched in Junk.

TRUSTED:
    Leave untouched.

Permanent deletion must NOT be introduced by default.

The existing DryRun behaviour must be preserved.

DryRun should default to true for new installations.


# Authentication

Microsoft personal Outlook/Hotmail accounts require delegated authentication.

Current implementation uses Azure.Identity and Microsoft Graph.

Do not replace delegated authentication with:

- client credentials
- Managed Identity
- application-only Graph permissions

unless support for personal Microsoft mailboxes has been explicitly verified.


## Authentication Architecture

Interactive authentication must NOT be initiated by the scheduled/background
scanner.

This is important.

A background execution must never hang waiting for an interactive browser login.

The desired flow is:

    Background Scanner
           |
           +-- valid cached credentials --> continue
           |
           +-- authentication required
                    |
                    +--> record authentication-required state
                    |
                    +--> stop scan safely
                    |
                    +--> Web UI displays authentication required

The MailSentry Web UI is responsible for interactive authentication.

The user should be able to open MailSentry from a desktop or mobile browser and
select:

    Authenticate

or:

    Re-authenticate

This should initiate the Microsoft authorization flow.

On successful authentication:

- persist/cache the authentication state securely
- allow background scans to authenticate silently
- update provider status in the UI

Never expose:

- access tokens
- refresh tokens
- authentication records
- secrets

through the UI or logs.


# Classification Architecture

The current SpamClassifier contains hard-coded scoring rules.

These must be externalised.

The long-term classifier should consist primarily of:

    Email Message
          |
          v
    Signature Engine
          |
          v
    Score / Classification
          |
       +--+--+
       |     |
     SPAM  REVIEW

Allow-list/trusted behaviour must take precedence over spam scoring.


# Signature System

Spam knowledge must live outside the compiled application.

MailSentry must automatically load JSON signature packs from a configured
signature directory.

Example:

    signatures/
        001-core.json
        002-casino.json
        003-health-scams.json
        004-prize-scams.json
        005-generated-senders.json
        006-emoji-spam.json

Adding a signature must NOT require:

- recompilation
- republishing
- application restart where reasonably possible


## Signature Fields

Rules should support at least:

- senderName
- senderAddress
- senderDomain
- subject
- body
- content


## Signature Operators

Support at least:

- contains
- containsAny
- containsAll
- startsWith
- endsWith
- equals
- regex


## Compound Rules

Rules must support compound conditions.

At minimum:

- ALL / AND
- ANY / OR

Example concept:

    generated sender domain
    AND
    known spam emoji in subject
    =
    high confidence spam


## Signature Scoring

Rules contribute scores.

Example:

    Generated campaign domain       +4
    Spam emoji                      +5
    Spam urgency language           +4
                                   ---
                                    13

The configured spam threshold determines SPAM classification.

Weak signals should normally corroborate stronger signals.


# Current Spam Knowledge

Existing hard-coded behaviour should be migrated into signatures where
practical.

Observed spam families include:

- casino
- gambling
- free spins
- deposit bonuses
- welcome bonuses
- player rewards
- fake cloud storage
- fake billing failures
- fake subscription renewals
- GLP-1 scams
- miracle weight-loss campaigns
- male performance / ED campaigns
- miracle medical treatments
- nerve pain remedies
- fake FedEx rewards
- fake festival/Glastonbury prizes
- fake solar grants
- housing compensation scams
- Cash4Gold campaigns
- prize/claim scams
- emergency/survival prize campaigns


# Generated Sender Patterns

Observed spam campaigns frequently use generated sender identities.

Examples include:

- domains beginning with `--`
- domains beginning with `---`
- domains containing `-----mail.`
- random alphanumeric local parts
- unusual/emoji domains

A generated sender/domain is strong supporting evidence but should not normally
be sufficient by itself to classify a message as SPAM.


# Emoji Rules

Observed campaigns frequently use spam-style emoji in:

- sender display name
- sender address/domain
- subject

Examples include:

    🚨
    🎁
    🏆
    💰
    🔥
    🎉
    💥
    💎
    📩
    ⚠️
    🥹
    🫶
    🚩
    ❗

MailSentry only evaluates messages already classified as Junk by the email
provider.

Therefore emoji in sender identity or subject can be treated as a substantially
stronger signal than it would be for general Inbox filtering.

Avoid treating emoji in the HTML/body alone as automatically malicious because
legitimate marketing email commonly contains emoji.


# Classification Safety Rules

Do NOT classify a message as SPAM merely because:

- it contains "offer"
- it contains "discount"
- it contains "bonus"
- it contains "congratulations"
- it is from a no-reply address
- it has an unusual TLD
- its sender looks random
- it contains generic marketing language

These are supporting indicators.

The system should favour:

    REVIEW

when confidence is insufficient.


# Allow List

Allow-list behaviour must take precedence over all spam signatures.

Support:

- exact sender address
- explicitly configured trusted domains

Be conservative with domain allow-listing.

Broad domains belonging to services such as Microsoft, Amazon, PayPal, banks,
etc. should not automatically be considered proof of authenticity based only on
the From address.

Future improvements may inspect authentication headers such as SPF, DKIM and
DMARC.

Safety invariant:

> A trusted/allow-listed message must never become SPAM because of signature
> scoring.


# Signature Validation

Signature files are executable classification configuration and must therefore
be treated carefully.

Before activating a signature:

1. Parse JSON.
2. Validate schema.
3. Validate rule fields.
4. Validate operators.
5. Validate scoring.
6. Validate compound conditions.
7. Detect duplicate signature IDs where applicable.
8. Reject malformed or unsupported rules.

An invalid signature must never cause MailSentry to accidentally classify mail
as spam.

Fail safely.

Invalid signatures should be reported clearly in logs and the Web UI.


# MailSentry Web UI

The first version of the Web UI should remain deliberately small.

It is an operational console, NOT a mail client.

The initial UI has three primary areas:

1. Dashboard / Authentication
2. Unmatched Junk
3. Signatures

The UI must be responsive and usable from a mobile phone.


# Dashboard

The dashboard should show:

- provider
- authentication state
- partially masked mailbox identity where appropriate
- last successful scan
- number scanned
- spam matched
- unmatched/review count
- loaded signature count
- scanner status

Example:

    MailSentry                              Running

    Email Provider

    Microsoft Outlook              Authenticated
    fa****@hotmail.com

                              [ Re-authenticate ]

    Last scan          09:31
    Junk scanned       14
    Spam matched       11
    Unmatched           3
    Signatures         47

                              [ Scan Now ]


# Authentication UI

If authentication has expired, been revoked, or otherwise requires user
interaction, show clearly:

    Microsoft Outlook

    Authentication required

    MailSentry can no longer access this mailbox.

                              [ Authenticate ]

Selecting Authenticate should initiate the interactive provider login.

On success:

- securely update authentication cache/state
- background scans should work silently again
- provider state should change to authenticated

Do not make the user edit configuration files to recover authentication.


# Unmatched Junk UI

The UI should display Junk messages that have NOT reached the SPAM threshold.

These are effectively REVIEW messages.

Show enough information to understand why the classifier did not match.

For example:

    Important Message for farshad

    Riverbend Ranch
    no-reply@--example.org

    Score: 4

    Matched:
    - Generated campaign-style domain

    Body preview:
    ...

                              [ Copy ]

Support:

    [ Select All ]
    [ Copy Selected ]


# Copy for Signature Generation

This is an important MailSentry workflow.

The user should be able to select unmatched messages and copy a structured,
sanitised representation suitable for sending to ChatGPT, Codex, or another AI
assistant for signature generation.

Example output:

    MailSentry unmatched messages
    Generated: 2026-11-02T09:42:12Z

    --- MESSAGE 1 ---

    Sender name:
    Riverbend Ranch

    Sender:
    no-reply@--example.org

    Subject:
    Important Message for farshad

    Body preview:
    ...

    Existing score:
    4

    Matched signatures:
    - Generated campaign-style domain

    --- MESSAGE 2 ---

    ...

Do not include:

- authentication tokens
- Graph internal secrets
- unnecessary headers
- unnecessary personal information

The copied representation should contain only the information useful for
classification/signature generation.


# Signature Management UI

Provide a simple Signatures page.

Example:

    Signatures

    Active  001-core.json
    Active  002-casino.json
    Active  003-health-scams.json
    Active  004-prize-scams.json
    Active  005-generated-senders.json
    Active  006-emoji-spam.json

                              [ Upload Signature ]

The first version does NOT require a visual rule editor.


# Signature Upload

The user must be able to upload a JSON signature file from:

- desktop
- mobile phone

On upload:

1. Receive file.
2. Parse JSON.
3. Validate signature schema.
4. Validate fields/operators.
5. Check duplicate IDs.
6. Run safety validation.
7. Test against currently unmatched Junk messages.
8. Show the impact BEFORE activation.


# Signature Preview / Impact Analysis

Before activating an uploaded signature, evaluate it against the current
unmatched Junk messages.

Example:

    Signature validation successful

    Messages tested:       6
    New SPAM matches:      5
    Still unmatched:       1

    Messages that would become SPAM:

    - Fake FedEx reward
    - Solar Grant Alert
    - Male Wellness
    - Cash4Gold
    - Festival Prize

                  [ Cancel ]
                  [ Install & Activate ]

This is an important safety feature.

Do not activate an uploaded signature until the user confirms activation.


# Signature Activation

After confirmation:

- save the signature into the configured signature repository
- reload signatures
- do not require recompilation
- avoid requiring application restart
- re-evaluate unmatched messages

Show a result such as:

    Signature installed

    007-campaign-20261102.json

    Rules:       8
    Conditions:  17
    Status:      Active

    Previously unmatched:  6
    Now matched as spam:   5
    Still unmatched:       1


# Future UI Features

Do NOT implement these until the initial UI and signature engine are stable:

- visual signature editor
- create-signature-from-message wizard
- quarantine browser
- full email viewer
- multiple mailbox management
- Gmail support
- IMAP support
- signature marketplace
- automatic AI-generated signatures

The initial UI should remain simple.


# Background Processing

The background scanner should:

1. Authenticate silently.
2. Read Junk.
3. Load current signatures.
4. Classify messages.
5. Quarantine high-confidence SPAM.
6. Leave REVIEW untouched.
7. Leave TRUSTED untouched.
8. Record audit information.
9. Exit cleanly if running as a scheduled process.

Prevent concurrent scans.

A second scan must not process the same message concurrently.


# Logging

MailSentry needs persistent operational logging.

Log at least:

- scan start
- scan end
- authentication failures
- Graph failures
- signature loading
- invalid signatures
- classifications
- quarantine actions
- scan summary

Example:

    2026-11-02 09:30:00 | START
    2026-11-02 09:30:01 | SPAM | 11 | Generated sender + emoji
    2026-11-02 09:30:01 | QUARANTINED
    2026-11-02 09:30:02 | REVIEW | 4
    2026-11-02 09:30:03 | SUMMARY | Scanned=8 Spam=7 Review=1
    2026-11-02 09:30:03 | END

Do not log:

- access tokens
- refresh tokens
- authentication records
- secrets
- complete message bodies by default


# Architecture Expectations

Keep MailSentry simple.

Potential components:

    MailSentry.Core
        Classification
        Signatures
        Models

    MailSentry.MicrosoftGraph
        Authentication
        MailReader
        MailActions

    MailSentry.Web
        Dashboard
        Authentication
        Unmatched
        Signatures

The exact project structure may differ if a simpler structure is more
appropriate.

Avoid unnecessary DDD/Clean Architecture ceremony.

However:

- classification logic should be independently testable
- signature logic must not depend directly on the Web UI
- Graph integration should not leak throughout the application
- Web UI and background scanner should use the same classification/signature
  services


# Internal Mail Model

Where practical, classification should operate on an internal provider-neutral
mail model rather than directly on Microsoft.Graph.Models.Message.

For example:

    MailMessage
        Id
        SenderName
        SenderAddress
        SenderDomain
        Subject
        BodyPreview
        ReceivedDateTime
        Importance

This makes:

- testing easier
- future Gmail support easier
- future IMAP support easier


# Testing

Add unit tests for the signature engine.

Tests must include:

- contains
- containsAny
- containsAll
- startsWith
- endsWith
- equals
- regex
- AND conditions
- OR conditions
- score accumulation
- threshold behaviour
- Unicode matching
- emoji matching
- sender-domain extraction
- malformed signatures
- unsupported operators
- duplicate signatures
- allow-list precedence

Add regression tests representing observed spam campaigns.

Important safety test:

    allow-listed message
    +
    multiple matching spam signatures
    =
    TRUSTED

not SPAM.


# Public/Open-Source Considerations

MailSentry is intended for publication on GitHub.

Never commit:

- Client IDs belonging to the developer
- authentication records
- token caches
- email addresses
- real message content
- secrets
- local paths
- production configuration

Provide:

- appsettings.example.json
- setup documentation
- Microsoft Entra application registration instructions
- required Graph permissions
- local development instructions
- deployment instructions
- security notes

Ensure `.gitignore` protects authentication/cache files.


# Product Description

Suggested GitHub description:

> An open-source, signature-driven email spam cleaner that filters
> high-confidence spam from your Junk folder while preserving uncertain
> messages for review.

Suggested explanation:

> Your email provider decides what's Junk. MailSentry decides what's safe to
> remove.


# Immediate Implementation Plan

Before making significant changes:

1. Read this AGENTS.md completely.
2. Inspect the entire existing repository.
3. Understand the existing working Graph authentication.
4. Understand existing mail reading.
5. Understand quarantine behaviour.
6. Understand current SpamClassifier rules.
7. Understand configuration.
8. Run the existing application/tests where practical.

Do not immediately rewrite working code.


## Phase 1 - Rename

Rename the existing JunkCleaner solution/application to:

    MailSentry

Update:

- solution
- projects
- namespaces
- configuration sections
- executable naming
- documentation

Preserve behaviour.


## Phase 2 - Signature Engine

Implement the generic JSON signature engine.

Then:

- migrate existing hard-coded rules
- create numbered signature packs
- validate signatures
- add tests
- build
- test


## Phase 3 - Authentication Refactor

Separate:

    silent background authentication

from:

    interactive Web UI authentication

A background scan must never hang waiting for interactive login.


## Phase 4 - Web UI

Implement the minimal responsive MailSentry Web UI:

- Dashboard
- Authentication
- Unmatched Junk
- Copy Selected
- Signature list
- Signature upload
- signature validation
- impact preview
- activation


## Phase 5 - Production Hardening

Add:

- persistent logging
- concurrency protection
- configuration validation
- graceful Graph failures
- graceful authentication failures
- signature reload
- audit information


# Development Behaviour

When working on MailSentry:

- inspect before changing
- preserve existing working behaviour
- make incremental changes
- build frequently
- run tests after meaningful changes
- fix warnings/errors introduced by changes
- do not silently weaken safety behaviour
- do not introduce permanent deletion
- do not expose credentials
- do not over-engineer

If a design decision could materially increase the risk of deleting legitimate
email, stop and favour the safer behaviour.

# Multi-Account Microsoft Mailbox Support

## Objective

Extend MailSentry from a single-mailbox application into a multi-account application.

A single MailSentry installation must be able to connect to and scan multiple personal Microsoft Outlook/Hotmail accounts.

MailSentry must continue to use the existing Microsoft Entra application registration and Client ID.

Do NOT create or require separate Entra application registrations for each mailbox.

Each Microsoft account must authenticate and consent independently using the existing delegated Microsoft Graph authentication model.

The intended architecture is:

MailSentry
├── Microsoft Account 1
│   ├── AuthenticationRecord
│   ├── token/cache association
│   └── Junk mailbox
├── Microsoft Account 2
│   ├── AuthenticationRecord
│   ├── token/cache association
│   └── Junk mailbox
├── Microsoft Account 3
│   ├── AuthenticationRecord
│   ├── token/cache association
│   └── Junk mailbox
└── Shared signature repository

All configured mailboxes must use the same classifier and signature packs.

---

## Important Existing Behaviour

Before making changes:

1. Inspect the existing authentication implementation.
2. Inspect the existing Azure.Identity token cache configuration.
3. Inspect how AuthenticationRecord is currently persisted.
4. Inspect GraphAuthentication and Graph client creation.
5. Inspect the scan coordinator.
6. Inspect the Web UI authentication workflow.
7. Inspect the existing DPAPI protection/storage implementation.
8. Inspect tests covering authentication and scanning.

Do not replace working security behaviour unnecessarily.

Preserve backwards compatibility with an existing single-account MailSentry installation.

Existing users must not lose their current authenticated mailbox after upgrading.

---

# Authentication Model

MailSentry uses Microsoft Graph delegated authentication.

Existing Graph permissions remain:

- Mail.ReadWrite
- User.Read

Do NOT introduce Microsoft Graph application permissions.

Do NOT introduce client secrets.

Do NOT introduce application-only authentication.

The Entra application is a public client supporting personal Microsoft accounts.

The same Entra Client ID must be used for every configured mailbox.

Each mailbox owner authenticates independently.

Example:

MailSentry Entra App
        |
        +-- account1@hotmail.com -> consent
        |
        +-- account2@hotmail.com -> consent
        |
        +-- account3@outlook.com -> consent

Each authenticated account must have its own persisted identity/authentication state.

Authenticating a new account MUST NOT replace, overwrite or invalidate another configured account.

---

# Account Model

Introduce a first-class account/mailbox model.

The exact class names may follow the existing architecture, but conceptually an account requires:

- stable internal account ID
- Microsoft account identity information
- masked/display mailbox address
- authentication record
- authentication state
- enabled/disabled state
- last successful scan
- last scan status
- last authentication failure
- optional operational statistics

Do not use the email address itself as the primary storage identifier.

Use a stable internal identifier.

After successful authentication, use Microsoft Graph User.Read to identify the authenticated Microsoft account.

Do not expose unnecessary Microsoft identity information through the UI or logs.

---

# Account Storage

Move from effectively:

data/
    authentication-record
    token-cache

towards an account-aware structure such as:

data/
    accounts/
        <account-id-1>/
            auth-record.bin

        <account-id-2>/
            auth-record.bin

        <account-id-3>/
            auth-record.bin

The exact structure should fit the existing storage abstractions.

Authentication records must remain protected using the existing secure mechanism.

Continue using DPAPI/encrypted Azure.Identity token persistence.

Never introduce plaintext token storage.

Never write:

- access tokens
- refresh tokens
- authentication secrets

to logs.

Do not use raw email addresses as directory names.

---

# Token Cache

Investigate the existing Azure.Identity persistent token cache implementation before changing it.

Support multiple Microsoft identities safely.

AuthenticationRecord must be associated with the correct configured MailSentry account.

When creating credentials for an existing account, MailSentry must select the correct AuthenticationRecord so Azure.Identity acquires tokens for that account.

Do not assume that "the last authenticated Microsoft account" is the account to use.

Account selection must be explicit.

If a shared encrypted Azure.Identity token cache can safely support multiple identities, prefer retaining it rather than unnecessarily creating completely independent token cache implementations.

The MailSentry account record must still identify which Microsoft identity/authentication record belongs to that mailbox.

---

# Add Account Workflow

Replace the single-account-centric authentication experience with account management.

The UI should provide:

Microsoft Accounts

far****@hotmail.com       Connected
old****@hotmail.com       Connected
xyz****@outlook.com       Re-authentication required

[ Add Microsoft Account ]

Selecting:

Add Microsoft Account

must initiate the existing Microsoft authentication/device-code flow.

After authentication:

1. obtain the authenticated user's identity using Microsoft Graph User.Read
2. determine whether this Microsoft account already exists in MailSentry
3. if it is new, create a new MailSentry account record
4. persist its AuthenticationRecord securely
5. associate it with the correct token-cache identity
6. display the account in the account list
7. do not affect any existing accounts

If the authenticated Microsoft account already exists, do not create a duplicate.

Instead, treat the operation as re-authentication/update of that account where appropriate.

---

# Re-authentication

Each account must support independent re-authentication.

Example:

Account A        Connected
Account B        Re-authentication required
Account C        Connected

Re-authenticating Account B must not modify authentication state for A or C.

Provide a clear action such as:

Re-authenticate

against the affected account.

Scheduled scans must NEVER initiate interactive authentication.

If authentication is unavailable or revoked, mark only that account as requiring authentication.

---

# Remove Account

Provide an account removal operation.

Removing an account must:

1. require explicit confirmation
2. remove the MailSentry account registration
3. remove its persisted AuthenticationRecord
4. remove account-specific operational state where appropriate
5. stop future scans of that mailbox

Do NOT delete email from the mailbox.

Do NOT revoke unrelated Microsoft accounts.

Be careful with shared Azure.Identity token caches: removing one MailSentry account must not corrupt authentication for other configured accounts.

---

# Enabled / Disabled Accounts

Prefer supporting an Enabled flag.

An administrator should be able to temporarily disable scanning for a mailbox without deleting its authentication configuration.

Example:

far****@hotmail.com       Connected       Enabled
old****@hotmail.com       Connected       Disabled

Disabled accounts must not be scanned by scheduled or manual aggregate scans.

---

# Scanner Changes

The scanner must process all enabled configured accounts.

Conceptually:

foreach account in enabledAccounts
{
    try
    {
        create Graph client for account

        read account Junk folder

        classify messages using shared signatures

        quarantine SPAM when not DryRun

        update account scan state
    }
    catch AuthenticationRequired
    {
        mark THIS account as requiring authentication
    }
    catch Exception
    {
        record THIS account failure safely
    }
}

One mailbox failure MUST NOT abort scanning of the remaining mailboxes.

For example:

Account A -> Success
Account B -> Authentication required
Account C -> Success
Account D -> Graph failure

Accounts A and C must still complete normally.

---

# Scan Concurrency

Preserve the existing scanner locking/concurrency protections.

Do not allow multiple scheduled scans to corrupt shared operational state.

Initially prefer scanning mailboxes sequentially unless the existing architecture makes bounded parallelism clearly safe.

Correctness, Graph throttling behaviour and account isolation are more important than scan speed.

A handful of personal mailboxes does not require aggressive parallelism.

---

# Signature Engine

Signatures remain global/shared.

Do NOT create separate copies of signature packs for every mailbox.

The architecture is:

Multiple Mailboxes
        |
        v
Shared MailSentry Classifier
        |
        v
Shared Signature Repository

Installing a new signature pack should immediately apply to every configured mailbox on subsequent preview/scan operations.

Existing signature safety behaviour must remain unchanged.

---

# Unmatched Junk

Update Unmatched Junk so every message is associated with its source mailbox.

The UI should show a masked mailbox/account identifier.

Example:

Mailbox              Sender             Subject             Score

far****@hotmail.com   ...                ...                 4
old****@hotmail.com   ...                ...                 0

When copying unmatched messages for analysis, include the mailbox only if useful and keep it masked.

Do not expose unnecessary personal information.

The existing sanitisation/redaction behaviour must remain.

---

# Signature Preview

Signature preview should work across unmatched messages from all configured/enabled accounts.

The preview should clearly show which mailbox a matched message belongs to, using the masked mailbox identity.

A signature activation remains global.

Example:

New signature impact

3 messages would become SPAM

far****@hotmail.com       1
old****@hotmail.com       2

Install & Activate

Do not automatically quarantine messages during preview.

Preserve the existing rule that actual quarantine happens during a live scan.

---

# Dashboard

Update the dashboard for multiple mailboxes.

Provide aggregate statistics such as:

Mailboxes             4
Connected             3
Authentication needed 1
Messages scanned      83
Spam matched          50
Review                 6

Also provide per-mailbox status.

Example:

Mailbox                 Status             Last Scan      Spam

far****@hotmail.com      Connected          06:50          12
old****@hotmail.com      Connected          06:50           7
xyz****@outlook.com      Re-auth required   01:20           -
abc****@hotmail.com      Disabled           22:10           -

Actions should include, as appropriate:

- Add Account
- Re-authenticate
- Enable
- Disable
- Remove

Keep the UI simple and mobile-friendly.

MailSentry is an operational console, not a mail client.

---

# Manual Scan

"Scan Now" should normally scan all enabled accounts.

If appropriate for the existing UI architecture, optionally provide a per-account scan action as well.

A manual aggregate scan must have the same failure isolation as a scheduled scan.

One broken account must not stop other accounts being processed.

---

# Scheduled Scan

The existing:

MailSentry.exe --scan

must scan every enabled configured mailbox.

Do NOT require separate Windows Scheduled Tasks for every mailbox.

There should remain one scheduled MailSentry scan.

Architecture:

Windows Task Scheduler
        |
        v
MailSentry.exe --scan
        |
        +-- Account A
        +-- Account B
        +-- Account C
        +-- Account D
        |
        v
Shared signatures

Preserve the existing process/file locking behaviour.

---

# DryRun

DryRun remains global unless there is a compelling architectural reason to change it.

When:

DryRun = true

NO mailbox writes may occur for ANY account.

When:

DryRun = false

SPAM may be moved to the configured MailSentry quarantine folder for each account.

Never permanently delete messages.

---

# Quarantine

Each mailbox should use its own mailbox-local quarantine folder using the existing configured name:

MailSentry Quarantine

Example:

Account A
    Junk Email
    MailSentry Quarantine

Account B
    Junk Email
    MailSentry Quarantine

Account C
    Junk Email
    MailSentry Quarantine

Do not attempt to create one shared Microsoft mailbox folder across accounts.

---

# Audit Logging

Audit entries must identify the relevant MailSentry account using a safe/masked identifier.

Example:

[account: far****@hotmail.com] scan started
[account: far****@hotmail.com] messages scanned: 25
[account: far****@hotmail.com] spam: 7
[account: far****@hotmail.com] scan completed

Never log:

- access tokens
- refresh tokens
- authentication records
- passwords
- complete message bodies

Preserve existing logging safety.

---

# Authentication Failure Behaviour

Authentication failure must be isolated per account.

For example:

Account A -> token valid
Account B -> token revoked
Account C -> token valid

Expected behaviour:

Account A scanned
Account B marked Authentication Required
Account C scanned

The process should not stop merely because Account B needs authentication.

The aggregate result should indicate partial success where appropriate.

---

# Backwards Compatibility / Migration

This is critical.

Existing MailSentry installations already contain a working single-account authentication record and encrypted token cache.

The upgrade MUST attempt to preserve that authentication.

Do not force existing users to re-authenticate unless technically unavoidable.

Implement migration from the legacy/single-account authentication state into the new account model.

Migration should be:

- automatic where safe
- idempotent
- recoverable
- logged without exposing sensitive data

Do not delete the legacy authentication data until migration has succeeded.

If migration cannot safely determine the existing account, fail safely and provide a clear re-authentication path.

Existing configuration such as:

MicrosoftGraph:ClientId

remains global.

Do not duplicate ClientId per account.

---

# Security Requirements

Multi-account support must not weaken existing MailSentry security.

Preserve:

- DPAPI protection
- Azure.Identity encrypted persistence
- HTTPS requirements for remote administration
- Admin authentication
- AllowedHosts
- Admin:AllowedHosts
- signature validation
- scan locking
- safe logging
- DryRun safety
- quarantine rather than permanent deletion

Never expose Microsoft tokens through:

- UI
- API responses
- logs
- exception messages
- JavaScript
- HTML
- audit files

Do not persist credentials in plaintext.

---

# Data Isolation

Although all mailboxes use shared signatures, operational and authentication state must remain account-aware.

A bug or failure involving Account A must not:

- overwrite Account B authentication
- cause Account B to be marked unauthenticated
- use Account A's Graph client against Account B
- mix Account A messages into Account B actions
- quarantine a message using the wrong Graph identity

Treat account identity as an explicit boundary throughout the Graph layer.

---

# Tests

Add comprehensive tests for multi-account behaviour.

At minimum test:

1. adding first account
2. adding second account
3. duplicate account authentication
4. independent AuthenticationRecords
5. account-specific Graph client creation
6. scanning multiple accounts
7. one account authentication failure does not stop others
8. one account Graph failure does not stop others
9. disabled accounts are skipped
10. removing one account does not affect another
11. re-authenticating one account does not affect another
12. shared signatures apply to every account
13. unmatched messages retain account identity
14. signature preview spans multiple accounts
15. DryRun prevents writes across every account
16. live mode quarantines using the correct account
17. legacy single-account migration
18. account state survives restart
19. audit logs use safe account identifiers
20. no tokens/authentication records appear in logs or UI

Use the existing in-memory/fake Graph HTTP infrastructure where possible.

No live mailbox access should be required for automated tests.

---

# Implementation Approach

Do NOT perform this as one large uncontrolled rewrite.

Implement incrementally.

Suggested phases:

## Phase 1 - Domain and Storage

Introduce:

- account model
- account repository/storage abstraction
- secure per-account AuthenticationRecord storage
- migration from existing single-account state

Build and run tests.

## Phase 2 - Authentication

Refactor authentication so credentials and Graph clients are explicitly created for a specific account.

Implement:

- Add Account
- duplicate detection
- Re-authenticate Account
- Remove Account
- Enable/Disable Account

Build and run tests.

## Phase 3 - Scanner

Change scan coordination from one mailbox to all enabled accounts.

Implement account-level failure isolation.

Build and run tests.

## Phase 4 - Web UI

Add account management and per-account status.

Update dashboard.

Update Unmatched Junk.

Build and run tests.

## Phase 5 - Signature Preview and Operational State

Make preview/state account-aware while keeping signatures global.

Build and run tests.

## Phase 6 - Regression / Security Review

Verify:

- existing single-account installations migrate
- existing signatures still work
- DryRun still prevents writes
- quarantine still works
- scheduled --scan works
- interactive authentication is never launched by scheduled scans
- remote administration security remains unchanged
- no credentials or tokens leak

Run the complete test suite.

---

# Architectural Principle

Do not solve multi-account support by introducing global mutable "current account" state.

Avoid patterns such as:

CurrentGraphClient
CurrentMailbox
CurrentAuthenticationRecord

that can accidentally cross account boundaries.

Prefer explicit account context:

ScanAsync(account)
CreateGraphClientAsync(account)
ReadJunkAsync(account)
MoveToQuarantineAsync(account, message)

Account identity should flow explicitly through operations where it matters.

This is especially important if MailSentry later introduces parallel mailbox scanning.

---

# Definition of Done

Multi-account support is complete when:

1. One MailSentry installation can connect to multiple personal Outlook/Hotmail accounts.
2. All accounts use the same Entra Client ID.
3. Each Microsoft account authenticates independently.
4. Adding an account does not replace another account.
5. Authentication state persists securely across restart.
6. Existing single-account users migrate safely.
7. One scheduled `MailSentry.exe --scan` processes all enabled accounts.
8. Failure of one mailbox does not prevent other mailboxes being scanned.
9. Signatures are shared globally.
10. Unmatched messages identify their source mailbox safely.
11. Dashboard displays aggregate and per-mailbox status.
12. Accounts can be added, re-authenticated, disabled and removed.
13. DryRun and quarantine safety behaviour remain intact.
14. No permanent deletion is introduced.
15. Existing HTTPS/admin security remains intact.
16. Automated tests cover multi-account isolation and migration.
17. `dotnet build MailSentry.sln` succeeds.
18. `dotnet test MailSentry.sln --no-build` succeeds.

Before implementation, inspect the existing codebase and produce a concise implementation plan identifying the classes/components that need modification.

Then implement the work incrementally, running build/tests after each significant phase.

Do not remove or weaken existing working behaviour merely to simplify multi-account support.
