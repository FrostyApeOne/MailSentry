using MailSentry;
using System.Text.Json;
using Xunit;

public class MultiAccountMigrationSecurityTests
{
    [Fact]
    public async Task LegacyCredentialsAndReviewStateMigrateAndScanSilentlyWithoutFreshLogin()
    {
        using var f = new MultiAccountFixture();
        var bytes = AccountStorageTests.Record("legacy.tenant");
        ProtectedFile.Write(Path.Combine(f.DirectoryPath, "auth-record.bin"), bytes);
        var legacyPath = Path.Combine(f.DirectoryPath, "legacy.json"); await File.WriteAllBytesAsync(legacyPath, bytes);
        var originalScan = new ScanSummary(DateTimeOffset.UtcNow.AddMinutes(-5), 2, 1, 1, 0, true);
        f.Store.Save(new(originalScan, "sy****@example.invalid", [new(new("old-review", "Example", "sender@example.invalid", "uncertain", ""), new(Classification.Review, 0, []))], null));
        await f.Migration.RunAsync();
        var entry = Assert.Single(f.Accounts.ReadAll());
        Assert.Equal(bytes, entry.AuthenticationRecord); Assert.Null(entry.Account.GraphUserId); Assert.Equal(originalScan, entry.Scan.LastSuccessfulScan);
        var scanner = new Scanner(f.Authentication, f.Options, f.Signatures, f.Store, f.Accounts); scanner.Refresh();
        Assert.Equal(entry.Account.Id, Assert.Single(scanner.Unmatched).AccountId);
        Assert.True(await scanner.ScanAsync()); Assert.Equal(0, f.Credentials.InteractiveCalls);
        Assert.Equal("legacy.tenant", Assert.Single(f.Credentials.SilentHomes));
        Assert.Equal("graph-legacy.tenant", f.Accounts.Get(entry.Account.Id).Account.GraphUserId);
        Assert.True(File.Exists(legacyPath)); Assert.True(File.Exists(Path.Combine(f.DirectoryPath, "auth-record.bin")));
        await f.Authentication.RemoveAsync(entry.Account.Id, true);
        Assert.False(File.Exists(legacyPath)); Assert.False(File.Exists(Path.Combine(f.DirectoryPath, "auth-record.bin")));
        Assert.False(File.Exists(Path.Combine(f.DirectoryPath, "scan-state.bin")));
        await f.Migration.RunAsync(); Assert.Empty(f.Accounts.ReadAll());
    }
    [Fact]
    public async Task InvalidLegacyRecordAndInterruptedMigrationAreRecoverable()
    {
        using var f = new MultiAccountFixture(); var path = Path.Combine(f.DirectoryPath, "legacy.json");
        await File.WriteAllTextAsync(path, "{}"); await f.Migration.RunAsync();
        Assert.NotNull(f.Migration.Error); Assert.Empty(f.Accounts.ReadAll()); Assert.True(File.Exists(path));
        var bytes = AccountStorageTests.Record("recover.tenant"); await File.WriteAllBytesAsync(path, bytes);
        var id = Guid.NewGuid();
        using (var tx = f.Accounts.Begin()) tx.Save(new(new(id, "recover.tenant", null, "sy****@example.invalid"), bytes, AccountScanState.Empty));
        // Represents interruption after the new account was saved but before migration was marked complete.
        var retry = new LegacyAccountMigration(MultiAccountFixture.ClientId, f.Accounts, f.Store, path);
        await retry.RunAsync(); Assert.Null(retry.Error); Assert.True(f.Accounts.Catalog().LegacyMigrationCompleted);
        Assert.Equal(id, Assert.Single(f.Accounts.ReadAll()).Account.Id);
        Assert.Equal(bytes, f.Accounts.Get(id).AuthenticationRecord);
    }
    [Fact]
    public async Task OneCorruptEncryptedAccountDoesNotPreventOtherAccountsScanning()
    {
        using var f = new MultiAccountFixture(); var a = await f.Add("a.tenant"); var b = await f.Add("b.tenant"); var c = await f.Add("c.tenant");
        File.WriteAllText(Path.Combine(f.Accounts.DirectoryPath, b.ToString("N"), "account.bin"), "corrupt");
        var scanner = new Scanner(f.Authentication, f.Options, f.Signatures, f.Store, f.Accounts);
        f.Requests.Clear(); Assert.False(await scanner.ScanAsync());
        Assert.Equal("Partial success", scanner.LastRun!.Outcome); Assert.Equal(2, scanner.LastRun.Succeeded); Assert.Equal(1, scanner.LastRun.Failed);
        Assert.Equal("Success", f.Accounts.Get(a).Scan.Status); Assert.Equal("Success", f.Accounts.Get(c).Scan.Status);
        Assert.Equal("Storage unavailable", Assert.Single(scanner.AccountViews, x => x.Id == b).Authentication);
        Assert.DoesNotContain(f.Requests, x => x.Home == "b.tenant");
    }
    [Fact]
    public async Task RegistrationIdentityCannotBeReassignedAndAccountRemovalRetainsOtherRecords()
    {
        using var f = new MultiAccountFixture(); var a = await f.Add("a.tenant"); var b = await f.Add("b.tenant");
        using (var tx = f.Accounts.Begin())
        {
            var original = tx.Get(a);
            Assert.Throws<InvalidDataException>(() => tx.Save(original with { Account = original.Account with { HomeAccountId = "b.tenant" } }));
            Assert.Throws<InvalidDataException>(() => tx.Save(original with { Account = original.Account with { GraphUserId = "graph-b.tenant" } }));
        }
        var bFile = Path.Combine(f.Accounts.DirectoryPath, b.ToString("N"), "account.bin"); var protectedB = File.ReadAllBytes(bFile);
        await f.Authentication.RemoveAsync(a, true);
        Assert.Equal(protectedB, File.ReadAllBytes(bFile));
        var json = JsonSerializer.Serialize(f.Accounts.Get(b).Account);
        Assert.DoesNotContain("synthetic-token-never-log", json);
    }
}
