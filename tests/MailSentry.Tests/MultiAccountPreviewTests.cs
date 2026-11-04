using MailSentry;
using System.Text.Json;
using Xunit;

public class MultiAccountPreviewTests
{
    private const string AddedJson = """
        {"version":1,"signatures":[{"id":"review-matcher","name":"Synthetic review","score":7,"when":{"field":"subject","operator":"equals","value":"uncertain"}}]}
        """;
    [Fact]
    public async Task PreviewSpansEnabledAccountsWithMaskedIdentitiesAndActivationMakesNoMailboxWrites()
    {
        using var f = new MultiAccountFixture(); var a = await f.Add("a.tenant"); var b = await f.Add("b.tenant"); var c = await f.Add("c.tenant");
        var scanner = new Scanner(f.Authentication, f.Options, f.Signatures, f.Store, f.Accounts);
        Assert.True(await scanner.ScanAsync()); f.Authentication.SetEnabled(c, false);
        var installer = new SignatureInstaller(f.Signatures, scanner, f.Options, f.Store);
        var before = f.Requests.Count; var preview = installer.PreviewPasted(AddedJson);
        Assert.Equal(2, preview.Tested); Assert.Equal(2, preview.NewSpam); Assert.Equal(2, preview.Accounts.Count);
        Assert.All(preview.Accounts, x => { Assert.Equal(1, x.Tested); Assert.Equal(1, x.NewSpam); Assert.Equal("sy****@example.invalid", x.Mailbox); });
        Assert.Equal(new[] { a, b }.Order(), preview.Matches.Select(x => x.AccountId).Order());
        var text = MessageExport.Create(scanner.Unmatched.Where(x => x.AccountId == b));
        Assert.Contains("Mailbox:\nsy****@example.invalid", text); Assert.DoesNotContain("synthetic@example.invalid", text);
        Assert.DoesNotContain("AuthenticationRecord", JsonSerializer.Serialize(preview));
        installer.Activate(preview.Token);
        Assert.Equal(before, f.Requests.Count); Assert.Empty(scanner.Unmatched);
        Assert.Single(f.Accounts.Get(c).Scan.Unmatched); // Disabled state remains untouched.
        Assert.Empty(f.Accounts.Get(a).Scan.Unmatched); Assert.Empty(f.Accounts.Get(b).Scan.Unmatched);
        Assert.True(await scanner.ScanAsync()); Assert.Empty(scanner.Unmatched);
    }
    [Fact]
    public async Task AccountRegistrationEnablementRemovalAndReauthenticationInvalidatePreview()
    {
        using var f = new MultiAccountFixture(); var a = await f.Add("a.tenant");
        var scanner = new Scanner(f.Authentication, f.Options, f.Signatures, f.Store, f.Accounts); Assert.True(await scanner.ScanAsync());
        var installer = new SignatureInstaller(f.Signatures, scanner, f.Options, f.Store);
        var preview = installer.PreviewPasted(AddedJson); var b = await f.Add("b.tenant");
        Assert.Throws<InvalidDataException>(() => installer.Activate(preview.Token));
        preview = installer.PreviewPasted(AddedJson); f.Authentication.SetEnabled(b, false);
        Assert.Throws<InvalidDataException>(() => installer.Activate(preview.Token));
        preview = installer.PreviewPasted(AddedJson); await f.Authentication.RemoveAsync(b, true);
        Assert.Throws<InvalidDataException>(() => installer.Activate(preview.Token));
        preview = installer.PreviewPasted(AddedJson); await f.Add("a.tenant");
        Assert.Throws<InvalidDataException>(() => installer.Activate(preview.Token));
        Assert.Single(f.Signatures.Load().Rules);
    }
    [Fact]
    public async Task DashboardProjectionAndCopyCannotLeakAuthenticationOrCrossSelectIdenticalMessageIds()
    {
        using var f = new MultiAccountFixture(); var a = await f.Add("a.tenant"); var b = await f.Add("b.tenant");
        var scanner = new Scanner(f.Authentication, f.Options, f.Signatures, f.Store, f.Accounts); Assert.True(await scanner.ScanAsync());
        var selected = Assert.Single(scanner.Unmatched, x => x.AccountId == a);
        var matches = scanner.Unmatched.Where(x => x.SelectionKey == selected.SelectionKey).ToArray();
        Assert.Equal(a, Assert.Single(matches).AccountId);
        var json = JsonSerializer.Serialize(new { accounts = scanner.AccountViews, unmatched = scanner.Unmatched });
        foreach (var privateValue in new[] { "homeAccountId", "HomeAccountId", "AuthenticationRecord", "ClientId", "synthetic-token-never-log", "a.tenant", "graph-a.tenant" })
            Assert.DoesNotContain(privateValue, json);
        Assert.Equal(2, scanner.Unmatched.Select(x => x.SelectionKey).Distinct().Count());
    }
}
