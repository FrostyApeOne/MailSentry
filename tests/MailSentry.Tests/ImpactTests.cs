using MailSentry;
using System.Text.Json;
using Xunit;
public class ImpactTests
{
    [Fact]
    public void PreviewComputesCombinedScoresWithoutMovingMailAndActivationReevaluates()
    {
        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
        try
        {
            var store = new OperationalStore(dir); var repo = new SignatureRepository(dir); var options = new MailSentryOptions();
            var first = new Signature("existing", "Existing", 4, new() { Field = "subject", Operator = "contains", Value = "synthetic" });
            File.WriteAllText(Path.Combine(dir, "existing.json"), JsonSerializer.Serialize(new SignaturePack(1, [first]), SignatureFormat.Json));
            var messages = new[] { new ReviewMessage(new("one", "Example", "x@example.invalid", "synthetic campaign", ""), new(Classification.Review, 4, ["Existing"])), new ReviewMessage(new("two", "Example", "x@example.invalid", "unmatched", ""), new(Classification.Review, 0, [])) };
            var accounts = new AccountRepository(store);
            var accountId = Guid.NewGuid();
            using (var transaction = accounts.Begin()) transaction.Save(new(new(accountId, "synthetic.tenant", "graph-synthetic", "sy****@example.invalid"),
                AccountStorageTests.Record("synthetic.tenant"), new(null, "Success", null, messages)));

            var scanner = TestScanner.Create(dir, options, repo, store);
            var installer = new SignatureInstaller(repo, scanner, options, store);
            var json = JsonSerializer.Serialize(new SignaturePack(1, [first with { Id = "extra", Score = 3 }]), SignatureFormat.Json);
            var preview = installer.Preview("extra.json", json);
            Assert.Equal(2, preview.Tested); Assert.Equal(1, preview.NewSpam); Assert.Equal(1, preview.StillUnmatched); Assert.Equal("synthetic campaign", Assert.Single(preview.Subjects));
            Assert.Equal(2, accounts.Get(accountId).Scan.Unmatched.Count); Assert.False(File.Exists(Path.Combine(dir, "extra.json")));
            installer.Activate(preview.Token); Assert.Equal("two", Assert.Single(accounts.Get(accountId).Scan.Unmatched).Message.Id);
        }
        finally { Directory.Delete(dir, true); }
    }
    [Theory]
    [InlineData("Claim your reward FedEx", true)]
    [InlineData("Glastonbury you have won", true)]
    [InlineData("Solar grant expires today", true)]
    [InlineData("Housing compensation claim now", true)]
    [InlineData("Cash4Gold reward", true)]
    [InlineData("Survival kit you won", true)]
    [InlineData("FedEx delivery tomorrow", false)]
    public void CorroboratedCampaigns(string subject, bool spam)
    {
        var snapshot = new SignatureRepository(Path.Combine(AppContext.BaseDirectory, "signatures")).Load(); Assert.Empty(snapshot.Errors);
        Assert.Equal(spam, new SpamClassifier(new()).Classify(new("id", "Example", "x@--example.invalid", subject, ""), snapshot.Rules).Classification == Classification.Spam);
    }
    [Theory]
    [InlineData("{\"version\":1,\"version\":1,\"signatures\":[]}")]
    [InlineData("{\"version\":1,\"signatures\":[{\"id\":\"x\",\"name\":\"x\",\"score\":7,\"when\":{\"field\":\"subject\",\"operator\":\"regex\",\"value\":\".*\"}}]}")]
    public void AmbiguousOrMatchEverythingRulesRejected(string json) => Assert.ThrowsAny<Exception>(() => SignatureFormat.Parse(json));
}
