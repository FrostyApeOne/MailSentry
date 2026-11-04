using MailSentry;
using Xunit;
public class AuthenticationTests
{
    [Fact]
    public async Task MissingAccountRecordRequiresAuthenticationWithoutInteraction()
    {
        using var fixture = new MultiAccountFixture();
        var entry = new StoredMailbox(new(Guid.NewGuid(), "missing.tenant", null, "Microsoft mailbox"), [], AccountScanState.Empty);
        await Assert.ThrowsAsync<MailboxAuthenticationException>(() => fixture.Authentication.OpenAsync(entry, default));
        Assert.Equal(0, fixture.Credentials.InteractiveCalls);
        Assert.Empty(fixture.Requests);
        Assert.Empty(fixture.Accounts.ReadAll());
    }
}
