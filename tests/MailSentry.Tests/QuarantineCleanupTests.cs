using MailSentry;
using Xunit;

public class QuarantineCleanupTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ConfirmedCleanupIsAccountBoundAndHonorsDryRun(bool dryRun)
    {
        using var f = new MultiAccountFixture(); f.Options.DryRun = dryRun;
        var a = await f.Add("a.tenant"); var b = await f.Add("b.tenant");
        f.Quarantined["a.tenant"] = ["one", "two"]; f.Quarantined["b.tenant"] = ["one", "two"];
        var cleanup = new QuarantineCleanupService(f.Authentication, f.Accounts, f.Options, f.Store);
        var preview = await cleanup.PreviewAsync(a);
        Assert.Equal(2, preview.Count); Assert.Equal(a, preview.AccountId); Assert.Equal("sy****@example.invalid", preview.Mailbox);
        Assert.DoesNotContain(f.Requests, r => r.Method != "GET");
        var calls = f.Requests.Count;
        await Assert.ThrowsAsync<InvalidDataException>(() => cleanup.ExecuteAsync(a, preview.Token, false));
        await Assert.ThrowsAsync<InvalidDataException>(() => cleanup.ExecuteAsync(b, preview.Token, true));
        Assert.Equal(calls, f.Requests.Count);
        var result = await cleanup.ExecuteAsync(a, preview.Token, true);
        Assert.True(result.Completed); Assert.Equal(dryRun ? 0 : 2, result.Moved);
        Assert.Equal(dryRun ? 2 : 0, f.Quarantined["a.tenant"].Count); Assert.Equal(2, f.Quarantined["b.tenant"].Count);
        var posts = f.Requests.Where(r => r.Method == "POST").ToArray();
        Assert.Equal(dryRun ? 0 : 2, posts.Length);
        Assert.All(posts, r => { Assert.Equal("a.tenant", r.Home); Assert.Contains("/mailFolders/quarantine-a.tenant/messages/", r.Path); Assert.Contains("deleteditems", r.Body); });
        Assert.DoesNotContain(f.Requests, r => r.Method == "DELETE" || r.Path.Contains("permanentDelete"));
        await Assert.ThrowsAsync<InvalidDataException>(() => cleanup.ExecuteAsync(a, preview.Token, true));
    }
    [Fact]
    public async Task StandardFolderCannotBeWipedEvenIfRenamedToQuarantine()
    {
        using var f = new MultiAccountFixture(); f.Options.DryRun = false;
        var a = await f.Add("a.tenant"); f.QuarantineFolderOverrides["a.tenant"] = "protected-inbox-a.tenant";
        var cleanup = new QuarantineCleanupService(f.Authentication, f.Accounts, f.Options, f.Store);
        await Assert.ThrowsAsync<InvalidDataException>(() => cleanup.PreviewAsync(a));
        Assert.DoesNotContain(f.Requests, r => r.Method == "POST");
    }
    [Fact]
    public async Task ChangedContentsAndChangedAccountInvalidateConfirmation()
    {
        using var f = new MultiAccountFixture(); var a = await f.Add("a.tenant");
        f.Quarantined["a.tenant"] = ["one"];
        var cleanup = new QuarantineCleanupService(f.Authentication, f.Accounts, f.Options, f.Store);
        var preview = await cleanup.PreviewAsync(a); f.Quarantined["a.tenant"].Add("new-arrival");
        await Assert.ThrowsAsync<InvalidDataException>(() => cleanup.ExecuteAsync(a, preview.Token, true));
        preview = await cleanup.PreviewAsync(a); f.Authentication.SetEnabled(a, false);
        await Assert.ThrowsAsync<InvalidDataException>(() => cleanup.ExecuteAsync(a, preview.Token, true));
        Assert.DoesNotContain(f.Requests, r => r.Method == "POST");
    }
    [Fact]
    public async Task PartialGraphFailureReportsProgressAndLeavesRemainingMessages()
    {
        using var f = new MultiAccountFixture(); f.Options.DryRun = false; f.FailCleanupAfter = 1;
        var a = await f.Add("a.tenant"); f.Quarantined["a.tenant"] = ["one", "two", "three"];
        var cleanup = new QuarantineCleanupService(f.Authentication, f.Accounts, f.Options, f.Store);
        var preview = await cleanup.PreviewAsync(a); var result = await cleanup.ExecuteAsync(a, preview.Token, true);
        Assert.False(result.Completed); Assert.Equal(1, result.Moved); Assert.Equal(2, f.Quarantined["a.tenant"].Count);
        Assert.DoesNotContain("synthetic-private-error", result.Message);
        var log = File.ReadAllText(Assert.Single(Directory.GetFiles(f.DirectoryPath, "audit-*.log")));
        Assert.Contains("QUARANTINE_CLEANUP_STOPPED", log); Assert.DoesNotContain("synthetic-token-never-log", log);
    }
    [Fact]
    public async Task CleanupSharesScanLockAndAuthenticationFailureAffectsOnlyTarget()
    {
        using var f = new MultiAccountFixture(); var a = await f.Add("a.tenant"); var b = await f.Add("b.tenant");
        var cleanup = new QuarantineCleanupService(f.Authentication, f.Accounts, f.Options, f.Store);
        using (f.Accounts.Begin()) await Assert.ThrowsAsync<InvalidDataException>(() => cleanup.PreviewAsync(a));
        f.AuthFailures.Add("a.tenant");
        await Assert.ThrowsAsync<InvalidDataException>(() => cleanup.PreviewAsync(a));
        Assert.Equal("Authentication required", f.Accounts.Get(a).Account.AuthenticationState);
        Assert.Equal("Connected", f.Accounts.Get(b).Account.AuthenticationState);
    }
}
