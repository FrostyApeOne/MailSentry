using System.Text.Json;
using MailSentry;
using Xunit;

public class SignatureTests
{
    private static MailMessage Message(string subject = "", string address = "sender@example.invalid", string body = "") => new("test", "Example", address, subject, body);
    private static Signature Rule(Condition c, int score = 4, string id = "test") => new(id, id, score, c);
    [Theory]
    [InlineData("contains", "hello")]
    [InlineData("startsWith", "hello")]
    [InlineData("endsWith", "world")]
    [InlineData("equals", "hello world")]
    [InlineData("regex", "^hello.*world$")]
    public void Operators(string op, string value) => Assert.True(SignatureFormat.Matches(new() { Field = "subject", Operator = op, Value = value }, Message("HELLO WORLD")));
    [Theory]
    [InlineData("containsAny", true)]
    [InlineData("containsAll", false)]
    public void MultiValueOperators(string op, bool expected) => Assert.Equal(expected, SignatureFormat.Matches(new() { Field = "subject", Operator = op, Values = ["hello", "absent"] }, Message("hello")));
    [Fact]
    public void Compounds()
    {
        var yes = new Condition { Field = "subject", Operator = "contains", Value = "hello" };
        var no = new Condition { Field = "subject", Operator = "contains", Value = "absent" };
        Assert.False(SignatureFormat.Matches(new() { All = [yes, no] }, Message("hello")));
        Assert.True(SignatureFormat.Matches(new() { Any = [yes, no] }, Message("hello")));
    }
    [Fact]
    public void ScoreAndThreshold()
    {
        var c = new SpamClassifier(new() { SpamThreshold = 7 }); var rule = Rule(new() { Field = "subject", Operator = "contains", Value = "hello" });
        Assert.Equal(Classification.Review, c.Classify(Message("hello"), [rule]).Classification);
        var result = c.Classify(Message("hello"), [rule, rule with { Id = "second", Score = 3 }]);
        Assert.Equal(7, result.Score); Assert.Equal(Classification.Spam, result.Classification);
    }
    [Theory]
    [InlineData("GLP\u20131", "glp-1")]
    [InlineData("\U0001F381", "\U0001F381")]
    [InlineData("CAF\u00c9", "caf\u00e9")]
    public void Unicode(string text, string value) => Assert.True(SignatureFormat.Matches(new() { Field = "subject", Operator = "contains", Value = value }, Message(text)));
    [Theory]
    [InlineData("x@EXAMPLE.invalid", "example.invalid")]
    [InlineData("broken", "")]
    [InlineData("@invalid", "")]
    public void DomainExtraction(string address, string expected) => Assert.Equal(expected, Message(address: address).SenderDomain);
    [Theory]
    [InlineData("{")]
    [InlineData("{\"version\":2,\"signatures\":[]}")]
    public void Malformed(string json) => Assert.ThrowsAny<Exception>(() => SignatureFormat.Parse(json));
    [Theory]
    [InlineData("bogus", "contains", 1)]
    [InlineData("subject", "delete", 1)]
    [InlineData("subject", "contains", -1)]
    [InlineData("subject", "regex", 4)]
    public void InvalidRule(string field, string op, int score)
    {
        var json = JsonSerializer.Serialize(new SignaturePack(1, [Rule(new() { Field = field, Operator = op, Value = op == "regex" ? "[" : "x" }, score)]), SignatureFormat.Json);
        Assert.ThrowsAny<Exception>(() => SignatureFormat.Parse(json));
    }
    [Fact]
    public void DuplicateIdsRejected()
    {
        var r = Rule(new() { Field = "subject", Operator = "contains", Value = "x" });
        Assert.ThrowsAny<Exception>(() => SignatureFormat.Parse(JsonSerializer.Serialize(new SignaturePack(1, [r, r]), SignatureFormat.Json)));
    }
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AllowListAlwaysWins(bool sender)
    {
        var options = new MailSentryOptions(); if (sender) options.AllowedSenders.Add("sender@example.invalid"); else options.AllowedDomains.Add("example.invalid");
        var r = Rule(new() { Field = "subject", Operator = "contains", Value = "spam" }, 100);
        Assert.Equal(Classification.Trusted, new SpamClassifier(options).Classify(Message("spam"), [r, r with { Id = "other" }]).Classification);
        Assert.NotEqual(Classification.Trusted, new SpamClassifier(options).Classify(Message("spam", "x@sub.example.invalid"), [r]).Classification);
    }
    [Theory]
    [InlineData("Casino free spins", "x@example.invalid", true)]
    [InlineData("GLP\u20131 viral drink no shots", "x@example.invalid", true)]
    [InlineData("Cloud storage payment declined", "x@example.invalid", true)]
    [InlineData("Your prize expires today", "x@example.invalid", true)]
    [InlineData("offer discount bonus congratulations", "noreply@example.invalid", false)]
    [InlineData("Hello", "03WJS8SX@--example.invalid", false)]
    [InlineData("Hello", "x@\U0001F381.invalid", false)]
    [InlineData("\U0001F381 Hello", "x@--example.invalid", true)]
    [InlineData("Can we reschedule?", "customer123@example.invalid", false)]
    [InlineData("Hello??", "x@--example.invalid", false)]
    public void CampaignRegressions(string subject, string address, bool spam)
    {
        var snapshot = new SignatureRepository(Path.Combine(AppContext.BaseDirectory, "signatures")).Load();
        Assert.Empty(snapshot.Errors); Assert.NotEmpty(snapshot.Rules);
        Assert.Equal(spam, new SpamClassifier(new()).Classify(Message(subject, address), snapshot.Rules).Classification == Classification.Spam);
        var bodyOnly = new SpamClassifier(new()).Classify(Message(body: "\U0001F381"), snapshot.Rules);
        Assert.Equal(Classification.Review, bodyOnly.Classification);
        Assert.Equal(0, bodyOnly.Score);
    }
    [Theory]
    [InlineData(0x1F6A8)]
    [InlineData(0x1F381)]
    [InlineData(0x1F3C6)]
    [InlineData(0x1F4B0)]
    [InlineData(0x1F525)]
    [InlineData(0x1F389)]
    [InlineData(0x1F4A5)]
    [InlineData(0x1F48E)]
    [InlineData(0x1F4E9)]
    [InlineData(0x26A0)]
    [InlineData(0x1F979)]
    [InlineData(0x1FAF6)]
    [InlineData(0x1F6A9)]
    [InlineData(0x2757)]
    public void BundledEmojiRulesRequireRealEmoji(int codePoint)
    {
        var rules = new SignatureRepository(Path.Combine(AppContext.BaseDirectory, "signatures")).Load().Rules;
        var emoji = char.ConvertFromUtf32(codePoint);
        var classifier = new SpamClassifier(new());
        Assert.Equal(5, classifier.Classify(Message(emoji), rules).Score);
        Assert.Equal(Classification.Review, classifier.Classify(Message(emoji), rules).Classification);
        Assert.Equal(Classification.Spam, classifier.Classify(Message(emoji, "x@--example.invalid"), rules).Classification);
        Assert.Equal(5, classifier.Classify(Message() with { SenderName = emoji }, rules).Score);
        Assert.Equal(5, classifier.Classify(Message(address: "x@" + emoji + ".invalid"), rules).Score);
        Assert.Equal(0, classifier.Classify(Message("Question? Or two??"), rules).Score);
    }
    [Fact]
    public void RepositoryFailsClosedAndReloads()
    {
        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
        try
        {
            var json = JsonSerializer.Serialize(new SignaturePack(1, [Rule(new() { Field = "subject", Operator = "contains", Value = "x" })]), SignatureFormat.Json);
            File.WriteAllText(Path.Combine(dir, "one.json"), json); var repo = new SignatureRepository(dir); Assert.Single(repo.Load().Rules);
            File.WriteAllText(Path.Combine(dir, "two.json"), json); Assert.Empty(repo.Load().Rules); Assert.NotEmpty(repo.Load().Errors);
            File.Delete(Path.Combine(dir, "two.json")); Assert.Single(repo.Load().Rules);
            File.WriteAllText(Path.Combine(dir, "one.json"), "{"); Assert.Empty(repo.Load().Rules);
        }
        finally { Directory.Delete(dir, true); }
    }
}
