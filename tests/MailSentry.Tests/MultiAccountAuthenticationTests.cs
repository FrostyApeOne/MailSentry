using MailSentry;
using Xunit;

public class MultiAccountAuthenticationTests
{
    [Fact]
    public async Task AddDuplicateReauthenticateDisableRemoveAreIsolated()
    {
        using var f = new MultiAccountFixture();
        var a = await f.Add("a.tenant"); var b = await f.Add("b.tenant");
        Assert.NotEqual(a, b); Assert.Equal(2, f.Accounts.ReadAll().Count);
        Assert.Equal(a, await f.Add("a.tenant")); Assert.Equal(2, f.Accounts.ReadAll().Count);
        var originalB = f.Accounts.Get(b).AuthenticationRecord;
        f.Credentials.LoginHome = "b.tenant";
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Authentication.AuthenticateAsync(a, _ => Task.CompletedTask));
        Assert.Equal("a.tenant", f.Accounts.Get(a).Account.HomeAccountId);
        Assert.Equal(originalB, f.Accounts.Get(b).AuthenticationRecord);
        f.Authentication.SetEnabled(b, false); Assert.False(f.Accounts.Get(b).Account.Enabled);
        f.Credentials.LoginHome = "b.tenant";
        Assert.Equal(b, await f.Authentication.AuthenticateAsync(b, _ => Task.CompletedTask));
        Assert.False(f.Accounts.Get(b).Account.Enabled);
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Authentication.RemoveAsync(a, false));
        await f.Authentication.RemoveAsync(a, true);
        Assert.Equal(b, Assert.Single(f.Accounts.ReadAll()).Account.Id);
        Assert.Equal(originalB, f.Accounts.Get(b).AuthenticationRecord);
        Assert.DoesNotContain(f.Requests, r => r.Method == "DELETE");
    }
    [Fact]
    public async Task SilentClientsUseExactRecordsAndVerifyGraphIdentity()
    {
        using var f = new MultiAccountFixture(); var a = await f.Add("a.tenant"); var b = await f.Add("b.tenant");
        var interactiveCount = f.Credentials.InteractiveCalls;
        using var sessionA = await f.Authentication.OpenAsync(f.Accounts.Get(a), default);
        using var sessionB = await f.Authentication.OpenAsync(f.Accounts.Get(b), default);
        Assert.Equal(a, sessionA.AccountId); Assert.Equal(b, sessionB.AccountId);
        Assert.Equal(new[] { "a.tenant", "b.tenant" }, f.Credentials.SilentHomes);
        Assert.Equal(interactiveCount, f.Credentials.InteractiveCalls);
        f.GraphIdentityOverrides["a.tenant"] = "graph-b.tenant";
        await Assert.ThrowsAsync<MailboxAuthenticationException>(() => f.Authentication.OpenAsync(f.Accounts.Get(a), default));
        var wrongRecord = f.Accounts.Get(a) with { AuthenticationRecord = f.Accounts.Get(b).AuthenticationRecord };
        var requests = f.Requests.Count;
        await Assert.ThrowsAsync<MailboxAuthenticationException>(() => f.Authentication.OpenAsync(wrongRecord, default));
        Assert.Equal(requests, f.Requests.Count);
    }
    [Fact]
    public async Task CrossAccountMessagesCannotBeQuarantinedEvenWithIdenticalGraphIds()
    {
        using var f = new MultiAccountFixture(); f.Options.DryRun = false;
        var a = await f.Add("a.tenant"); var b = await f.Add("b.tenant");
        using var sessionA = await f.Authentication.OpenAsync(f.Accounts.Get(a), default);
        using var sessionB = await f.Authentication.OpenAsync(f.Accounts.Get(b), default);
        var message = (await sessionA.ReadJunkAsync(10, default))[0]; var count = f.Requests.Count;
        await Assert.ThrowsAsync<InvalidDataException>(() => sessionB.QuarantineAsync(message, default));
        Assert.Equal(count, f.Requests.Count);
        await sessionA.QuarantineAsync(message, default);
        var action = Assert.Single(f.Requests, x => x.Method == "POST");
        Assert.Equal("a.tenant", action.Home); Assert.Contains("quarantine-a.tenant", action.Body);
    }
    [Fact]
    public void AzureOptionsRetainEncryptedSharedCacheAndDisableInteractiveFallback()
    {
        var a = AuthenticationRecordCodec.Parse(AccountStorageTests.Record("a.tenant"));
        var b = AuthenticationRecordCodec.Parse(AccountStorageTests.Record("b.tenant"));
        var factory = new AzureAccountCredentialFactory(MultiAccountFixture.ClientId);
        var optionsA = factory.SilentOptions(a); var optionsB = factory.SilentOptions(b);
        Assert.Same(a, optionsA.AuthenticationRecord); Assert.Same(b, optionsB.AuthenticationRecord);
        Assert.True(optionsA.DisableAutomaticAuthentication); Assert.True(optionsB.DisableAutomaticAuthentication);
        Assert.Equal("JunkCleanerV2", optionsA.TokenCachePersistenceOptions.Name);
        Assert.Equal(optionsA.TokenCachePersistenceOptions.Name, optionsB.TokenCachePersistenceOptions.Name);
        Assert.False(optionsA.TokenCachePersistenceOptions.UnsafeAllowUnencryptedStorage);
        Assert.Equal("consumers", optionsA.TenantId);
    }
}

