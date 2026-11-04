using System.Collections.Concurrent;

namespace MailSentry;

public sealed record QuarantineCleanupPreview(string Token, Guid AccountId, string Mailbox, string FolderName, int Count, bool DryRun);
public sealed record QuarantineCleanupResult(Guid AccountId, int Matched, int Moved, int Skipped, bool DryRun, bool Completed, string Message);
public sealed record QuarantineCleanupRequest(string Token, bool Confirmed);

public sealed class QuarantineCleanupService(IMailboxSessionFactory sessions, AccountRepository accounts, MailSentryOptions options, OperationalStore store)
{
    private sealed record Pending(Guid AccountId, string Fingerprint, QuarantineSnapshot Snapshot, bool DryRun, DateTimeOffset Expires);
    private readonly ConcurrentDictionary<string, Pending> _pending = new(StringComparer.Ordinal);
    public async Task<QuarantineCleanupPreview> PreviewAsync(Guid accountId, CancellationToken ct = default)
    {
        using var transaction = accounts.Begin();
        var entry = transaction.Get(accountId);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromMinutes(5));
        try
        {
            using var session = await sessions.OpenAsync(entry, timeout.Token);
            var cleanup = Verify(entry, session);
            var snapshot = await cleanup.ReadQuarantineAsync(timeout.Token);
            if (snapshot.AccountId != accountId) throw new InvalidDataException("Quarantine belongs to a different account.");
            foreach (var expired in _pending.Where(x => x.Value.Expires <= DateTimeOffset.UtcNow || x.Value.AccountId == accountId).Select(x => x.Key)) _pending.TryRemove(expired, out _);
            if (_pending.Count >= 20) throw new InvalidDataException("Too many pending cleanup previews. Wait for them to expire before retrying.");
            var token = Guid.NewGuid().ToString("N");
            _pending[token] = new(accountId, accounts.AccountFingerprint(accountId), snapshot, options.DryRun, DateTimeOffset.UtcNow.AddMinutes(5));
            store.Audit($"[account:{accountId:N}] QUARANTINE_CLEANUP_PREVIEW | Count={snapshot.MessageIds.Count} DryRun={options.DryRun}");
            return new(token, accountId, entry.Account.MaskedMailbox, snapshot.FolderName, snapshot.MessageIds.Count, options.DryRun);
        }
        catch (MailboxAuthenticationException)
        {
            RequireAuthentication(transaction, entry); throw new InvalidDataException("Re-authenticate this mailbox before clearing its quarantine.");
        }
        catch (Exception e) when (e is MailboxProviderException or HttpRequestException) { throw new InvalidDataException("Microsoft Graph could not read this mailbox's quarantine. Try again later."); }
        catch (OperationCanceledException) { throw new InvalidDataException("Quarantine preview was cancelled or timed out. No messages were moved."); }
    }
    public async Task<QuarantineCleanupResult> ExecuteAsync(Guid accountId, string token, bool confirmed, CancellationToken ct = default)
    {
        if (!confirmed) throw new InvalidDataException("Explicit confirmation is required to clear quarantine.");
        using var transaction = accounts.Begin();
        var entry = transaction.Get(accountId);
        if (string.IsNullOrWhiteSpace(token) || !_pending.TryGetValue(token, out var pending) || pending.AccountId != accountId)
            throw new InvalidDataException("Cleanup preview does not belong to this account. Preview its quarantine again.");
        if (!_pending.TryRemove(token, out _) || pending.Expires <= DateTimeOffset.UtcNow || pending.DryRun != options.DryRun || pending.Snapshot.FolderName != options.QuarantineFolderName || pending.Fingerprint != accounts.AccountFingerprint(accountId))
            throw new InvalidDataException("Cleanup preview expired or the account changed. Preview again before confirming.");
        var moved = 0; var skipped = 0;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromMinutes(5));
        try
        {
            using var session = await sessions.OpenAsync(entry, timeout.Token);
            var cleanup = Verify(entry, session);
            var current = await cleanup.ReadQuarantineAsync(timeout.Token);
            if (current.AccountId != accountId || current.FolderId != pending.Snapshot.FolderId ||
                !current.MessageIds.Order(StringComparer.Ordinal).SequenceEqual(pending.Snapshot.MessageIds.Order(StringComparer.Ordinal), StringComparer.Ordinal))
                throw new InvalidDataException("Quarantine contents changed. Preview again before confirming.");
            store.Audit($"[account:{accountId:N}] QUARANTINE_CLEANUP_START | Count={current.MessageIds.Count} DryRun={options.DryRun}");
            if (!options.DryRun)
                foreach (var id in current.MessageIds)
                {
                    timeout.Token.ThrowIfCancellationRequested();
                    if (await cleanup.MoveQuarantinedToDeletedItemsAsync(current, id, timeout.Token)) moved++; else skipped++;
                    store.Audit($"[account:{accountId:N}] QUARANTINE_CLEANUP_PROGRESS | Moved={moved} Skipped={skipped}");
                }
            store.Audit($"[account:{accountId:N}] QUARANTINE_CLEANUP_END | Matched={current.MessageIds.Count} Moved={moved} Skipped={skipped} DryRun={options.DryRun}");
            return new(accountId, current.MessageIds.Count, moved, skipped, options.DryRun, true, options.DryRun
                ? $"DryRun: would move {current.MessageIds.Count} quarantined messages to Deleted Items. No mailbox changes were made."
                : $"Moved {moved} quarantined messages to Deleted Items; skipped {skipped} already moved or restored messages.");
        }
        catch (InvalidDataException) { throw; }
        catch (Exception e)
        {
            try
            {
                if (e is MailboxAuthenticationException) RequireAuthentication(transaction, entry);
                store.Audit($"[account:{accountId:N}] QUARANTINE_CLEANUP_STOPPED | Moved={moved} Skipped={skipped}");
            }
            catch (Exception storageError) when (storageError is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException) { }

            return new(accountId, pending.Snapshot.MessageIds.Count, moved, skipped, options.DryRun, false,
                $"Cleanup stopped after moving {moved} messages to Deleted Items. Remaining messages were left untouched. Check authentication, connectivity and storage permissions, then preview again to retry.");
        }
    }
    private static IQuarantineMailboxSession Verify(StoredMailbox entry, IMailboxSession session)
    {
        if (session.AccountId != entry.Account.Id || string.IsNullOrWhiteSpace(session.MicrosoftUserId) ||
            (entry.Account.GraphUserId != null && session.MicrosoftUserId != entry.Account.GraphUserId)) throw new MailboxAuthenticationException();
        return session as IQuarantineMailboxSession ?? throw new InvalidDataException("This provider does not support quarantine cleanup.");
    }
    private static void RequireAuthentication(AccountRepository.Transaction transaction, StoredMailbox entry) =>
        transaction.Save(entry with { Account = entry.Account with { AuthenticationState = "Authentication required", LastAuthenticationFailure = DateTimeOffset.UtcNow } });
}
