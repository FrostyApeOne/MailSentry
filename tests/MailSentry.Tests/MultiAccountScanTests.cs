using MailSentry;
using Xunit;

public class MultiAccountScanTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SharedSignaturesAndQuarantineRemainAccountBound(bool dryRun)
    {
        using var f = new MultiAccountFixture(); f.Options.DryRun = dryRun;
        var a = await f.Add("a.tenant"); var b = await f.Add("b.tenant");
        var scanner = new Scanner(f.Authentication, f.Options, f.Signatures, f.Store, f.Accounts);
        var interactive = f.Credentials.InteractiveCalls;
        Assert.True(await scanner.ScanAsync());
        Assert.Equal(2, scanner.LastRun!.Succeeded); Assert.Equal(0, scanner.LastRun.Failed);
        Assert.Equal(4, scanner.LastScan!.Scanned); Assert.Equal(2, scanner.LastScan.Spam);
        Assert.Equal(2, scanner.Unmatched.Count); Assert.Equal(2, scanner.Unmatched.Select(x => x.SelectionKey).Distinct().Count());
        Assert.Equal(new[] { a, b }.Order(), scanner.Unmatched.Select(x => x.AccountId!.Value).Order());
        Assert.All(scanner.Unmatched, x => Assert.Equal("sy****@example.invalid", x.Mailbox));
        Assert.Equal(interactive, f.Credentials.InteractiveCalls);
        var moves = f.Requests.Where(x => x.Method == "POST").ToArray();
        Assert.Equal(dryRun ? 0 : 2, moves.Length);
        Assert.All(moves, x => Assert.Contains("quarantine-" + x.Home, x.Body));
        Assert.DoesNotContain(f.Requests, x => x.Method == "DELETE");
        var log = File.ReadAllText(Assert.Single(Directory.GetFiles(f.DirectoryPath, "audit-*.log")));
        Assert.Contains(a.ToString("N"), log); Assert.Contains(b.ToString("N"), log);
        foreach (var secret in new[] { "synthetic-token-never-log", "synthetic spam", "a.tenant", "synthetic@example.invalid", "homeAccountId" }) Assert.DoesNotContain(secret, log);
    }
    [Fact]
    public async Task AuthenticationAndGraphFailuresAreIsolatedAndDisabledAccountsAreSkipped()
    {
        using var f = new MultiAccountFixture();
        var a = await f.Add("a.tenant"); var b = await f.Add("b.tenant"); var c = await f.Add("c.tenant"); var d = await f.Add("d.tenant"); var e = await f.Add("e.tenant");
        f.Authentication.SetEnabled(e, false); f.AuthFailures.Add("b.tenant"); f.GraphFailures.Add("d.tenant");
        f.Requests.Clear();
        var scanner = new Scanner(f.Authentication, f.Options, f.Signatures, f.Store, f.Accounts);
        Assert.False(await scanner.ScanAsync());
        Assert.Equal("Partial success", scanner.LastRun!.Outcome); Assert.Equal(2, scanner.LastRun.Succeeded); Assert.Equal(2, scanner.LastRun.Failed); Assert.Equal(1, scanner.LastRun.Skipped);
        Assert.Equal("Authentication required", f.Accounts.Get(b).Account.AuthenticationState);
        Assert.NotNull(f.Accounts.Get(b).Account.LastAuthenticationFailure);
        Assert.All(new[] { a, c }, id => { Assert.Equal("Success", f.Accounts.Get(id).Scan.Status); Assert.Equal("Connected", f.Accounts.Get(id).Account.AuthenticationState); });
        Assert.Equal("Connected", f.Accounts.Get(d).Account.AuthenticationState); Assert.Equal("Failed", f.Accounts.Get(d).Scan.Status);
        Assert.DoesNotContain(f.Requests, x => x.Home == "e.tenant");
        Assert.Equal(2, scanner.Unmatched.Count);
        var restarted = new Scanner(f.Authentication, f.Options, f.Signatures, f.Store, new AccountRepository(f.Store)); restarted.Refresh();
        Assert.Equal(2, restarted.Unmatched.Count); Assert.Equal("Partial success", restarted.LastRun!.Outcome);
        var log = File.ReadAllText(Assert.Single(Directory.GetFiles(f.DirectoryPath, "audit-*.log")));
        Assert.DoesNotContain("synthetic-token-never-log", log); Assert.DoesNotContain("synthetic-private-error", log);
    }
    [Fact]
    public async Task AggregateLockPreventsAnotherScannerAndReleasesAfterCompletion()
    {
        using var f = new MultiAccountFixture(); await f.Add("a.tenant");
        var scanner = new Scanner(f.Authentication, f.Options, f.Signatures, f.Store, f.Accounts);
        using (f.Accounts.Begin()) { Assert.False(await scanner.ScanAsync()); Assert.Contains("running", scanner.Error!); }
        Assert.True(await scanner.ScanAsync());
    }
    [Fact]
    public async Task DisabledAccountsAreExcludedFromReviewAndAllDisabledMeansNoMailboxAccess()
    {
        using var f = new MultiAccountFixture(); var a = await f.Add("a.tenant");
        var scanner = new Scanner(f.Authentication, f.Options, f.Signatures, f.Store, f.Accounts);
        Assert.True(await scanner.ScanAsync()); Assert.Single(scanner.Unmatched);
        f.Authentication.SetEnabled(a, false); scanner.Refresh(); Assert.Empty(scanner.Unmatched);
        f.Requests.Clear(); Assert.False(await scanner.ScanAsync()); Assert.Empty(f.Requests);
    }
}
