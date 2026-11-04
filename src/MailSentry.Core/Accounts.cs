using System.Security.Cryptography;
using System.Text.Json;

namespace MailSentry;

public sealed record MailboxAccount(Guid Id, string HomeAccountId, string? GraphUserId, string MaskedMailbox,
    bool Enabled = true, string AuthenticationState = "Not checked", DateTimeOffset? LastAuthenticationFailure = null);
public sealed record AccountScanState(ScanSummary? LastSuccessfulScan, string Status, string? Error,
    IReadOnlyList<ReviewMessage> Unmatched, DateTimeOffset? LastAttempt = null)
{
    public static AccountScanState Empty => new(null, "Never scanned", null, []);
}
// Only encrypted storage and authentication services consume this document. API responses use explicit safe projections.
public sealed record StoredMailbox(MailboxAccount Account, byte[] AuthenticationRecord, AccountScanState Scan);
public sealed record AccountStorageError(Guid AccountId, string Error);
public sealed record AccountReadSnapshot(IReadOnlyList<StoredMailbox> Accounts, IReadOnlyList<AccountStorageError> Errors);
public sealed record AccountCatalog(int Version, IReadOnlyList<Guid> AccountIds, bool LegacyMigrationCompleted = false,
    Guid? MigratedAccountId = null);

public static class MailboxDisplay
{
    public static string Mask(string? address)
    {
        if (string.IsNullOrWhiteSpace(address) || address.Any(char.IsControl)) return "Microsoft mailbox";
        var at = address.IndexOf('@');
        return at > 0 && at == address.LastIndexOf('@') && at < address.Length - 1
            ? address[..Math.Min(2, at)] + "****" + address[at..] : "Microsoft mailbox";
    }
}

public sealed class AccountRepository(OperationalStore store)
{
    public string DirectoryPath => Path.Combine(store.DirectoryPath, "accounts");
    private string CatalogPath => Path.Combine(DirectoryPath, "catalog.bin");
    private string AccountPath(Guid id) => Path.Combine(DirectoryPath, id.ToString("N"), "account.bin");
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public AccountCatalog Catalog()
    {
        if (!File.Exists(CatalogPath)) return new(1, [], false);
        var catalog = JsonSerializer.Deserialize<AccountCatalog>(ProtectedFile.Read(CatalogPath), Json)
            ?? throw new InvalidDataException("Account catalog could not be read.");
        if (catalog.Version != 1 || catalog.AccountIds is null || catalog.AccountIds.Any(x => x == Guid.Empty) || catalog.AccountIds.Distinct().Count() != catalog.AccountIds.Count)
            throw new InvalidDataException("Invalid account catalog. Restore the data directory backup.");
        return catalog;
    }

    public IReadOnlyList<StoredMailbox> ReadAll() => Catalog().AccountIds.Select(ReadDocument).ToArray();
    public AccountReadSnapshot ReadSnapshot()
    {
        var entries = new List<StoredMailbox>(); var errors = new List<AccountStorageError>();
        foreach (var id in Catalog().AccountIds)
        {
            try { entries.Add(ReadDocument(id)); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException or JsonException or CryptographicException)
            { errors.Add(new(id, "Account storage is unavailable. Restore this account's data or check its permissions.")); }
        }
        return new(entries, errors);
    }
    public StoredMailbox Get(Guid id)
    {
        if (!Catalog().AccountIds.Contains(id)) throw new InvalidDataException("Account no longer exists.");
        return ReadDocument(id);
    }
    private StoredMailbox ReadDocument(Guid id)
    {
        var entry = JsonSerializer.Deserialize<StoredMailbox>(ProtectedFile.Read(AccountPath(id)), Json)
            ?? throw new InvalidDataException("Account storage could not be read.");
        if (entry.Account is null || entry.Account.Id != id || string.IsNullOrWhiteSpace(entry.Account.HomeAccountId) || entry.AuthenticationRecord is not { Length: > 0 } || entry.Scan is null || entry.Scan.Unmatched is null)
            throw new InvalidDataException("Account storage identity is invalid.");
        return entry;
    }
    public string AccountFingerprint(Guid id)
    {
        _ = Get(id);
        return Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(AccountPath(id))));
    }
    public string Fingerprint()
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        if (File.Exists(CatalogPath)) hash.AppendData(File.ReadAllBytes(CatalogPath));
        foreach (var id in Catalog().AccountIds.Order())
        {
            hash.AppendData(id.ToByteArray());
            hash.AppendData(File.ReadAllBytes(AccountPath(id)));
        }
        return Convert.ToHexString(hash.GetHashAndReset());
    }
    public Transaction? TryBegin()
    {
        var lease = store.TryAcquire();
        return lease is null ? null : new(this, lease);
    }
    public Transaction Begin() => TryBegin() ?? throw new InvalidDataException("A scan or account/signature update is running. Try again when it completes.");

    public sealed class Transaction : IDisposable
    {
        private readonly AccountRepository _repository;
        private readonly FileStream _lease;
        private bool _disposed;
        internal Transaction(AccountRepository repository, FileStream lease) { _repository = repository; _lease = lease; }
        private void Check() => ObjectDisposedException.ThrowIf(_disposed, this);
        public IReadOnlyList<StoredMailbox> All() { Check(); return _repository.ReadAll(); }
        public StoredMailbox Get(Guid id) { Check(); return _repository.Get(id); }
        public AccountCatalog Catalog() { Check(); return _repository.Catalog(); }
        public AccountReadSnapshot Snapshot() { Check(); return _repository.ReadSnapshot(); }
        private void SaveCatalog(AccountCatalog catalog) => ProtectedFile.Write(_repository.CatalogPath, JsonSerializer.SerializeToUtf8Bytes(catalog, Json));
        public void Save(StoredMailbox entry)
        {
            Check();
            if (entry.Account.Id == Guid.Empty || string.IsNullOrWhiteSpace(entry.Account.HomeAccountId) || entry.AuthenticationRecord.Length == 0)
                throw new InvalidDataException("Account identity and authentication record are required.");
            var catalog = Catalog();
            var original = catalog.AccountIds.Contains(entry.Account.Id) ? Get(entry.Account.Id) : null;
            if (original != null && (original.Account.HomeAccountId != entry.Account.HomeAccountId ||
                (original.Account.GraphUserId != null && original.Account.GraphUserId != entry.Account.GraphUserId)))
                throw new InvalidDataException("An existing account cannot be reassigned to a different Microsoft identity.");
            var others = original != null && original.Account.GraphUserId == entry.Account.GraphUserId
                ? Array.Empty<StoredMailbox>() : (original != null ? _repository.ReadSnapshot().Accounts : All()).Where(x => x.Account.Id != entry.Account.Id);
            if (others.Any(x => x.Account.HomeAccountId == entry.Account.HomeAccountId ||
                (entry.Account.GraphUserId != null && x.Account.GraphUserId == entry.Account.GraphUserId)))
                throw new InvalidDataException("This Microsoft account is already registered.");
            ProtectedFile.Write(_repository.AccountPath(entry.Account.Id), JsonSerializer.SerializeToUtf8Bytes(entry, Json));
            if (!catalog.AccountIds.Contains(entry.Account.Id)) SaveCatalog(catalog with { AccountIds = catalog.AccountIds.Append(entry.Account.Id).ToArray() });
        }
        public void CompleteMigration(Guid? id) { Check(); SaveCatalog(Catalog() with { LegacyMigrationCompleted = true, MigratedAccountId = id }); }
        public void SetEnabled(Guid id, bool enabled)
        {
            var entry = Get(id); Save(entry with { Account = entry.Account with { Enabled = enabled } });
        }
        public void Remove(Guid id)
        {
            Check(); _ = Get(id);
            var catalog = Catalog();
            // Commit removal before deleting credentials; interruption cannot re-register this account.
            SaveCatalog(catalog with { AccountIds = catalog.AccountIds.Where(x => x != id).ToArray() });
            File.Delete(_repository.AccountPath(id));
        }
        public void Dispose() { if (!_disposed) { _disposed = true; _lease.Dispose(); } }
    }
}
