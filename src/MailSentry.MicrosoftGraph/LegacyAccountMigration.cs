using Azure.Identity;
using System.Security.Cryptography;

namespace MailSentry;

public sealed class LegacyAccountMigration(string clientId, AccountRepository accounts, OperationalStore store, string legacyJsonPath)
{
    public string? Error { get; private set; }
    public async Task RunAsync(CancellationToken ct = default)
    {
        if (accounts.Catalog().LegacyMigrationCompleted) return;
        using var transaction = accounts.Begin();
        if (transaction.Catalog().LegacyMigrationCompleted) return;
        try
        {
            var record = await ReadAsync(ct);
            if (record is null) { transaction.CompleteMigration(null); return; }
            Validate(record);
            var existing = transaction.All().FirstOrDefault(x => x.Account.HomeAccountId == record.HomeAccountId);
            if (existing != null) { transaction.CompleteMigration(existing.Account.Id); return; }
            await using var memory = new MemoryStream(); await record.SerializeAsync(memory, ct);
            var legacyState = store.Load();
            var account = new MailboxAccount(Guid.NewGuid(), record.HomeAccountId, null, MailboxDisplay.Mask(record.Username));
            transaction.Save(new(account, memory.ToArray(), new(legacyState?.LastScan, "Migrated; identity check pending", legacyState?.Error, legacyState?.Unmatched ?? [])));
            transaction.CompleteMigration(account.Id);
            store.Audit($"[account:{account.Id:N}] LEGACY_AUTHENTICATION_MIGRATED");
        }
        catch (Exception e) when (e is InvalidDataException or IOException or UnauthorizedAccessException or CryptographicException or System.Text.Json.JsonException or ArgumentException)
        {
            Error = "Existing authentication could not be migrated. Legacy files were retained. Add the Microsoft account to authenticate again.";
            store.Audit("LEGACY_MIGRATION_REQUIRED | Legacy files retained");
        }
    }
    public void Validate(AuthenticationRecord record)
    {
        if (!string.Equals(record.ClientId, clientId, StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(record.HomeAccountId) ||
            !string.Equals(record.Authority.TrimEnd('/'), "login.microsoftonline.com", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Authentication record does not belong to this application or Microsoft authority.");
    }
    private async Task<AuthenticationRecord?> ReadAsync(CancellationToken ct)
    {
        var encrypted = Path.Combine(store.DirectoryPath, "auth-record.bin");
        if (File.Exists(encrypted))
        {
            await using var memory = new MemoryStream(ProtectedFile.Read(encrypted));
            return AuthenticationRecordCodec.Parse(memory.ToArray());
        }
        if (File.Exists(legacyJsonPath))
        {
            await using var file = File.OpenRead(legacyJsonPath);
            using var copy = new MemoryStream(); await file.CopyToAsync(copy, ct); return AuthenticationRecordCodec.Parse(copy.ToArray());
        }
        return null;
    }
    public async Task RemoveLegacyRecordAsync(MailboxAccount account, CancellationToken ct = default)
    {
        if (accounts.Catalog().MigratedAccountId != account.Id) return;
        foreach (var path in new[] { Path.Combine(store.DirectoryPath, "auth-record.bin"), legacyJsonPath })
        {
            if (!File.Exists(path)) continue;
            try
            {
                var bytes = path.EndsWith(".bin", StringComparison.OrdinalIgnoreCase) ? ProtectedFile.Read(path) : await File.ReadAllBytesAsync(path, ct);
                await using var memory = new MemoryStream(bytes);
                var record = AuthenticationRecordCodec.Parse(memory.ToArray());
                if (record.HomeAccountId == account.HomeAccountId) File.Delete(path);
            }
            catch (Exception e) when (e is InvalidDataException or IOException or CryptographicException or System.Text.Json.JsonException or ArgumentException)
            { throw new InvalidDataException("Account removal could not clean up its legacy authentication record. Try again after checking storage access."); }
        }
        foreach (var name in new[] { "scan-state.bin", "authentication-status.json" })
        {
            var path = Path.Combine(store.DirectoryPath, name);
            if (File.Exists(path)) File.Delete(path);
        }
    }
}

