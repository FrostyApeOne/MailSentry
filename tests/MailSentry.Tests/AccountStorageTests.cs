using MailSentry;
using System.Text;
using System.Text.Json;
using Xunit;

public class AccountStorageTests
{
    public static byte[] Record(string home, string client = "11111111-1111-1111-1111-111111111111") => Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
    {
        username = "synthetic@example.invalid",
        authority = "login.microsoftonline.com",
        homeAccountId = home,
        tenantId = "9188040d-6c67-4c5b-b112-36a304b66dad",
        clientId = client,
        version = "1.0"
    }));
    [Fact]
    public async Task SecureStorageAndMigrationAreIdempotentAndDoNotResurrectRemovedAccounts()
    {
        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
        try
        {
            var store = new OperationalStore(dir); var repository = new AccountRepository(store);
            var legacy = Path.Combine(dir, "legacy.json"); await File.WriteAllBytesAsync(legacy, Record("account-a.tenant"));
            var migration = new LegacyAccountMigration("11111111-1111-1111-1111-111111111111", repository, store, legacy);
            await migration.RunAsync(); Assert.Null(migration.Error);
            var first = Assert.Single(repository.ReadAll());
            Assert.Equal("account-a.tenant", first.Account.HomeAccountId); Assert.True(File.Exists(legacy));
            await migration.RunAsync(); Assert.Equal(first.Account.Id, Assert.Single(repository.ReadAll()).Account.Id);
            Assert.Equal("sy****@example.invalid", first.Account.MaskedMailbox);
            Assert.DoesNotContain("account-a.tenant", Encoding.UTF8.GetString(File.ReadAllBytes(Path.Combine(repository.DirectoryPath, first.Account.Id.ToString("N"), "account.bin"))));
            using (var tx = repository.Begin())
            {
                tx.Save(new(new(Guid.NewGuid(), "account-b.tenant", "graph-b", "b****@example.invalid"), Record("account-b.tenant"), AccountScanState.Empty));
                tx.SetEnabled(first.Account.Id, false);
            }
            Assert.False(new AccountRepository(store).Get(first.Account.Id).Account.Enabled);
            using (var tx = repository.Begin()) tx.Remove(first.Account.Id);
            await migration.RunAsync(); Assert.Single(repository.ReadAll()); Assert.Equal("account-b.tenant", repository.ReadAll()[0].Account.HomeAccountId);
        }
        finally { Directory.Delete(dir, true); }
    }
    [Fact]
    public async Task EncryptedLegacyRecordIsPreservedAndInvalidClientFailsSafely()
    {
        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
        try
        {
            var store = new OperationalStore(dir); var repo = new AccountRepository(store);
            ProtectedFile.Write(Path.Combine(dir, "auth-record.bin"), Record("account-a.tenant"));
            var migration = new LegacyAccountMigration("22222222-2222-2222-2222-222222222222", repo, store, "missing.json");
            await migration.RunAsync(); Assert.NotNull(migration.Error); Assert.Empty(repo.ReadAll());
            Assert.True(File.Exists(Path.Combine(dir, "auth-record.bin"))); Assert.False(repo.Catalog().LegacyMigrationCompleted);
            migration = new("11111111-1111-1111-1111-111111111111", repo, store, "missing.json");
            await migration.RunAsync(); Assert.Single(repo.ReadAll()); Assert.Null(migration.Error);
        }
        finally { Directory.Delete(dir, true); }
    }
}
