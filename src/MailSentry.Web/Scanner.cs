namespace MailSentry;

public sealed class Scanner(IMailboxSessionFactory sessions, MailSentryOptions options, SignatureRepository signatures,
    OperationalStore store, AccountRepository accounts)
{
    private IReadOnlyList<StoredMailbox> _snapshot = [];
    private IReadOnlyList<AccountStorageError> _storageErrors = [];
    public AccountRepository Repository => accounts;
    public SemaphoreSlim Gate { get; } = new(1, 1);
    public string Status { get; private set; } = "Idle";
    public string DisplayStatus => Status == "Running" || store.IsBusy ? "Running" : "Idle";
    public string? Error { get; private set; }
    public ScanRunSummary? LastRun { get; private set; }
    public IReadOnlyList<MailboxAccountView> AccountViews => _snapshot.Select(x => new MailboxAccountView(x.Account.Id,
        x.Account.MaskedMailbox, x.Account.Enabled, x.Account.AuthenticationState, x.Account.LastAuthenticationFailure,
        x.Scan.LastSuccessfulScan, x.Scan.Status == "Running" && !store.IsBusy ? "Interrupted" : x.Scan.Status, x.Scan.Error, x.Scan.LastAttempt)).Concat(_storageErrors.Select(e =>
        new MailboxAccountView(e.AccountId, "Account unavailable", false, "Storage unavailable", null, null, "Failed", e.Error, null))).ToArray();
    public IReadOnlyList<ReviewMessage> Unmatched => _snapshot.Where(x => x.Account.Enabled).SelectMany(x => x.Scan.Unmatched.Select(m =>
        m with { AccountId = x.Account.Id, Mailbox = x.Account.MaskedMailbox })).ToArray();
    public ScanSummary? LastScan
    {
        get
        {
            var summaries = _snapshot.Where(x => x.Account.Enabled).Select(x => x.Scan.LastSuccessfulScan).OfType<ScanSummary>().ToArray();
            return summaries.Length == 0 ? null : new(summaries.Max(x => x.Completed), summaries.Sum(x => x.Scanned),
                summaries.Sum(x => x.Spam), Unmatched.Count, summaries.Sum(x => x.Trusted), options.DryRun);
        }
    }
    public void Refresh(bool whileLocked = false)
    {
        if (Status != "Idle" || (!whileLocked && Gate.CurrentCount == 0)) return;
        var snapshot = accounts.ReadSnapshot(); _snapshot = snapshot.Accounts; _storageErrors = snapshot.Errors; LastRun = store.LoadRun();
        Error = LastRun?.Failed > 0 ? $"{LastRun.Failed} account scan(s) failed. Other accounts were processed; see their individual status." : null;
    }
    public async Task<bool> ScanAsync(CancellationToken ct = default)
    {
        if (!await Gate.WaitAsync(0, ct)) return false;
        AccountRepository.Transaction? transaction = null;
        var succeeded = 0; var failed = 0; var enabled = 0; var skipped = 0;
        try
        {
            transaction = accounts.TryBegin();
            if (transaction is null) { Error = "Another scan or account/signature update is running."; return false; }
            Refresh(true); Status = "Running"; Error = null;
            store.Audit("START | All enabled accounts");
            var pack = signatures.Load();
            store.Audit($"SIGNATURES | Loaded={pack.Rules.Count} Invalid={pack.Errors.Count}");
            foreach (var error in pack.Errors) store.Audit("INVALID_SIGNATURE | " + error);
            var snapshot = transaction.Snapshot(); var entries = snapshot.Accounts;
            failed = snapshot.Errors.Count; enabled = entries.Count(x => x.Account.Enabled) + failed; skipped = entries.Count(x => !x.Account.Enabled);
            foreach (var error in snapshot.Errors) store.Audit($"[account:{error.AccountId:N}] FAILURE | {error.Error}");
            foreach (var original in entries.Where(x => x.Account.Enabled))
            {
                var entry = original;
                var attempted = DateTimeOffset.UtcNow;
                var state = entry.Scan with { Status = "Running", Error = null, Unmatched = [], LastAttempt = attempted };
                try
                {
                    transaction.Save(entry with { Scan = state }); // Test storage before any mailbox action.
                    store.Audit($"[account:{entry.Account.Id:N}] START");
                    if (pack.Errors.Count > 0) throw new InvalidDataException("Invalid signature repository.");
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromMinutes(5));
                    using var session = await sessions.OpenAsync(entry, timeout.Token);
                    if (session.AccountId != entry.Account.Id || string.IsNullOrWhiteSpace(session.MicrosoftUserId) ||
                        (entry.Account.GraphUserId != null && session.MicrosoftUserId != entry.Account.GraphUserId))
                        throw new MailboxAuthenticationException();
                    entry = entry with
                    {
                        Account = entry.Account with
                        {
                            GraphUserId = session.MicrosoftUserId,
                            MaskedMailbox = session.MaskedMailbox,
                            AuthenticationState = "Connected"
                        }
                    };
                    transaction.Save(entry with { Scan = state });
                    var messages = await session.ReadJunkAsync(options.MaximumMessages, timeout.Token);
                    if (messages.Any(x => x.AccountId != entry.Account.Id)) throw new InvalidDataException("Cross-account messages were rejected.");
                    var classifier = new SpamClassifier(options); var review = new List<ReviewMessage>(); var spam = 0; var trusted = 0;
                    foreach (var message in messages)
                    {
                        timeout.Token.ThrowIfCancellationRequested();
                        var result = classifier.Classify(message.Message, pack.Rules);
                        store.Audit($"[account:{entry.Account.Id:N}] CLASSIFICATION | {result.Classification} | Score={result.Score}");
                        if (result.Reasons.Contains("Signature evaluation failed safely")) store.Audit($"[account:{entry.Account.Id:N}] SIGNATURE_EVALUATION_FAILED | REVIEW");
                        if (result.Classification == Classification.Spam)
                        {
                            spam++;
                            if (!options.DryRun) await session.QuarantineAsync(message, timeout.Token);
                            store.Audit($"[account:{entry.Account.Id:N}] {(options.DryRun ? "DRY_RUN | Would quarantine" : "QUARANTINED")}");
                        }
                        else if (result.Classification == Classification.Trusted) trusted++;
                        else review.Add(new(message.Message, result, entry.Account.Id, entry.Account.MaskedMailbox));
                    }
                    state = new(new(DateTimeOffset.UtcNow, messages.Count, spam, review.Count, trusted, options.DryRun), "Success", null, review, attempted);
                    transaction.Save(entry with { Scan = state }); succeeded++;
                    store.Audit($"[account:{entry.Account.Id:N}] SUMMARY | Scanned={messages.Count} Spam={spam} Review={review.Count} Trusted={trusted} DryRun={options.DryRun}");
                }
                catch (Exception e)
                {
                    failed++;
                    var error = e switch
                    {
                        MailboxAuthenticationException => "Authentication required. Re-authenticate this Microsoft account.",
                        MailboxProviderException => "Microsoft Graph request failed. Remaining messages were left untouched.",
                        OperationCanceledException => "Scan cancelled or timed out. Remaining messages were left untouched.",
                        InvalidDataException => "Signature or account validation failed. Remaining messages were left untouched.",
                        _ => "Scan failed. Check account status, connectivity and storage permissions. Remaining messages were left untouched."
                    };
                    if (e is MailboxAuthenticationException) entry = entry with
                    {
                        Account = entry.Account with
                        {
                            AuthenticationState = "Authentication required",
                            LastAuthenticationFailure = DateTimeOffset.UtcNow
                        }
                    };
                    try { transaction.Save(entry with { Scan = state with { Status = "Failed", Error = error, Unmatched = [] } }); }
                    catch (Exception storageError) when (storageError is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException) { }
                    store.Audit($"[account:{entry.Account.Id:N}] FAILURE | {error}");
                }
                finally { store.Audit($"[account:{original.Account.Id:N}] END"); }
                if (ct.IsCancellationRequested) break;
            }
            LastRun = new(DateTimeOffset.UtcNow, enabled, succeeded, failed, skipped + enabled - succeeded - failed,
                failed > 0 ? (succeeded > 0 ? "Partial success" : "Failed") : enabled == 0 ? "No enabled accounts" : "Success");
            store.SaveRun(LastRun);
            Error = enabled == 0 ? "No enabled Microsoft accounts. Add or enable an account in the Web UI." :
                failed > 0 ? $"{failed} account scan(s) failed. Other enabled accounts were processed." : null;
            store.Audit($"SUMMARY | Accounts={enabled} Succeeded={succeeded} Failed={failed} Outcome={LastRun.Outcome}");
            return enabled > 0 && failed == 0 && !ct.IsCancellationRequested;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException or InvalidDataException)
        { Error = "Account or operational storage is unavailable. No further accounts were processed."; return false; }
        finally
        {
            try { if (transaction != null) { var snapshot = transaction.Snapshot(); _snapshot = snapshot.Accounts; _storageErrors = snapshot.Errors; store.Audit("END | Aggregate scan"); } }
            finally { transaction?.Dispose(); Status = "Idle"; Gate.Release(); }
        }
    }
    public void Reevaluate(IReadOnlyList<Signature> rules, AccountRepository.Transaction transaction)
    {
        var classifier = new SpamClassifier(options);
        foreach (var entry in transaction.Snapshot().Accounts.Where(x => x.Account.Enabled))
        {
            var review = entry.Scan.Unmatched.Select(x => x with
            {
                Result = classifier.Classify(x.Message, rules),
                AccountId = entry.Account.Id,
                Mailbox = entry.Account.MaskedMailbox
            }).Where(x => x.Result.Classification == Classification.Review).ToArray();
            transaction.Save(entry with { Scan = entry.Scan with { Unmatched = review } });
        }
        var snapshot = transaction.Snapshot(); _snapshot = snapshot.Accounts; _storageErrors = snapshot.Errors;
    }
}
