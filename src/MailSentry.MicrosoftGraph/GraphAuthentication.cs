using Azure.Core;
using Azure.Identity;
using Microsoft.Graph;
using Microsoft.Kiota.Abstractions;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace MailSentry;

public sealed record AccountAuthenticationOperation(Guid Id, Guid? TargetAccountId, bool Running,
    string Status, AuthenticationPrompt? Prompt = null, Guid? CompletedAccountId = null, string? Error = null);

public sealed class GraphAuthentication : IMailboxSessionFactory
{
    private readonly AccountRepository _accounts;
    private readonly OperationalStore _store;
    private readonly MailSentryOptions _options;
    private readonly LegacyAccountMigration _migration;
    private readonly IAccountCredentialFactory _credentials;
    private readonly Func<TokenCredential, GraphServiceClient> _clientFactory;
    private readonly ConcurrentDictionary<Guid, AccountAuthenticationOperation> _operations = new();
    public GraphAuthentication(string clientId, AccountRepository accounts, OperationalStore store, MailSentryOptions options,
        LegacyAccountMigration migration, IAccountCredentialFactory? credentials = null, Func<TokenCredential, GraphServiceClient>? clientFactory = null)
    {
        _accounts = accounts; _store = store; _options = options; _migration = migration;
        _credentials = credentials ?? new AzureAccountCredentialFactory(clientId);
        _clientFactory = clientFactory ?? (credential => new GraphServiceClient(credential, AzureAccountCredentialFactory.Scopes));
    }
    public IReadOnlyList<AccountAuthenticationOperation> Operations => _operations.Values.ToArray();
    public Guid Start(Guid? targetAccountId, CancellationToken ct)
    {
        if (targetAccountId is { } id) _ = _accounts.Get(id);
        foreach (var finished in _operations.Where(x => !x.Value.Running).Select(x => x.Key)) _operations.TryRemove(finished, out _);
        if (_operations.Count >= 20) throw new InvalidDataException("Too many sign-in attempts. Complete the current sign-in first.");
        var operationId = Guid.NewGuid();
        _operations[operationId] = new(operationId, targetAccountId, true, "Starting Microsoft sign-in");
        _ = RunOperationAsync(operationId, targetAccountId, ct);
        return operationId;
    }
    private async Task RunOperationAsync(Guid operationId, Guid? targetAccountId, CancellationToken ct)
    {
        try
        {
            var id = await AuthenticateAsync(targetAccountId, prompt =>
            {
                _operations[operationId] = new(operationId, targetAccountId, true, "Waiting for Microsoft sign-in", prompt);
                return Task.CompletedTask;
            }, ct);
            _operations[operationId] = new(operationId, targetAccountId, false, "Connected", CompletedAccountId: id);
        }
        catch (Exception)
        {
            // Never expose provider exception messages: they can contain identity or authentication details.
            _operations[operationId] = new(operationId, targetAccountId, false, "Sign-in was not completed", Error:
                "Sign-in failed, was cancelled, or selected a different Microsoft account. Check account status and retry when scans and other sign-ins finish. Re-authentication must use the same Microsoft identity.");
            try { _store.Audit($"AUTHENTICATION_FAILED | Account={targetAccountId?.ToString("N") ?? "new"}"); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
    }
    public async Task<Guid> AuthenticateAsync(Guid? targetAccountId, Func<AuthenticationPrompt, Task> display, CancellationToken ct = default)
    {
        if (targetAccountId is { } requested) _ = _accounts.Get(requested);
        Directory.CreateDirectory(_store.DirectoryPath);
        using var authLease = new FileStream(Path.Combine(_store.DirectoryPath, "authentication.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromMinutes(10));
        var login = await _credentials.AuthenticateAsync(display, timeout.Token);
        _migration.Validate(login.Record);
        using var client = _clientFactory(login.Credential);
        var user = await client.Me.GetAsync(c => c.QueryParameters.Select = ["id", "mail", "userPrincipalName"], timeout.Token);
        if (string.IsNullOrWhiteSpace(user?.Id)) throw new InvalidDataException("Microsoft identity could not be verified.");
        AccountRepository.Transaction? transaction;
        while ((transaction = _accounts.TryBegin()) is null) await Task.Delay(100, timeout.Token);
        using (transaction)
        {

            StoredMailbox? existing;
            if (targetAccountId is { } target)
            {
                existing = transaction.Get(target);
                if (existing.Account.HomeAccountId != login.Record.HomeAccountId ||
                    (existing.Account.GraphUserId is { } expected && expected != user.Id))
                    throw new InvalidDataException("Re-authentication selected a different Microsoft account. Existing authentication was retained.");
            }
            else
            {
                var matches = transaction.All().Where(x => x.Account.HomeAccountId == login.Record.HomeAccountId || x.Account.GraphUserId == user.Id).ToArray();
                if (matches.Length > 1) throw new InvalidDataException("Microsoft identity has conflicting account registrations.");
                existing = matches.SingleOrDefault();
                if (existing != null && (existing.Account.HomeAccountId != login.Record.HomeAccountId ||
                    (existing.Account.GraphUserId != null && existing.Account.GraphUserId != user.Id)))
                    throw new InvalidDataException("Microsoft identity did not match the stored authentication record.");
            }
            var account = existing?.Account ?? new MailboxAccount(Guid.NewGuid(), login.Record.HomeAccountId, user.Id, "Microsoft mailbox");
            account = account with
            {
                GraphUserId = user.Id,
                MaskedMailbox = MailboxDisplay.Mask(user.Mail ?? user.UserPrincipalName),
                AuthenticationState = "Connected",
                LastAuthenticationFailure = null
            };
            transaction.Save(new(account, AuthenticationRecordCodec.Serialize(login.Record), existing?.Scan ?? AccountScanState.Empty));
            _store.Audit($"[account:{account.Id:N}] AUTHENTICATED");
            return account.Id;
        }
    }
    public async Task<IMailboxSession> OpenAsync(StoredMailbox entry, CancellationToken ct)
    {
        GraphServiceClient? client = null;
        try
        {
            var record = AuthenticationRecordCodec.Parse(entry.AuthenticationRecord);
            _migration.Validate(record);
            if (record.HomeAccountId != entry.Account.HomeAccountId) throw new MailboxAuthenticationException();
            var credential = _credentials.CreateSilent(record);
            client = _clientFactory(credential);
            var user = await client.Me.GetAsync(c => c.QueryParameters.Select = ["id", "mail", "userPrincipalName"], ct);
            if (string.IsNullOrWhiteSpace(user?.Id) || (entry.Account.GraphUserId != null && user.Id != entry.Account.GraphUserId))
                throw new MailboxAuthenticationException();
            var session = new GraphMailboxSession(entry.Account.Id, user.Id, MailboxDisplay.Mask(user.Mail ?? user.UserPrincipalName), client, _options);
            client = null; return session;
        }
        catch (Exception e) when (e is AuthenticationRequiredException or AuthenticationFailedException or InvalidDataException or CryptographicException or System.Text.Json.JsonException or ArgumentException)
        { throw new MailboxAuthenticationException(); }
        catch (ApiException e) when (e.ResponseStatusCode == 401) { throw new MailboxAuthenticationException(); }
        catch (ApiException) { throw new MailboxProviderException(); }
        finally { client?.Dispose(); }
    }
    public void SetEnabled(Guid id, bool enabled)
    {
        using var transaction = _accounts.Begin(); transaction.SetEnabled(id, enabled);
        _store.Audit($"[account:{id:N}] {(enabled ? "ENABLED" : "DISABLED")}");
    }
    public async Task RemoveAsync(Guid id, bool confirmed, CancellationToken ct = default)
    {
        if (!confirmed) throw new InvalidDataException("Explicit confirmation is required to remove an account.");
        using var transaction = _accounts.Begin(); var entry = transaction.Get(id);
        await _migration.RemoveLegacyRecordAsync(entry.Account, ct);
        transaction.Remove(id);
        _store.Audit($"[account:{id:N}] ACCOUNT_REMOVED | Mailbox untouched");
    }
}
