using System.Text.Json;
using MailSentry;
using Xunit;

public class SenderNameAnalysisTests
{
    private static MailMessage Message(string sender) => new("synthetic", sender, "sender@example.invalid", "Hello", "");
    [Theory]
    [InlineData("РayРal", "paypal")]
    [InlineData("ΡayΡal", "paypal")]
    [InlineData("Rеvоlut", "revolut")]
    [InlineData("Моnzо", "monzo")]
    [InlineData("ΗЅΒС", "hsbc")]
    [InlineData("Pay\u200bPal", "paypal")]
    [InlineData("Pay\u202ePal", "paypal")]
    [InlineData("ＰａｙＰａｌ", "paypal")]
    [InlineData("\U0001D411evolut", "revolut")]
    public void DetectsSupportedLookalikesAndHiddenFormatCharacters(string name, string brand)
    {
        Assert.True(SenderNameAnalysis.HasConfusables(name));
        Assert.Equal(brand, SenderNameAnalysis.Skeleton(name));
        Assert.True(SignatureFormat.Matches(new() { Field = "senderName", Operator = "confusableEquals", Value = brand }, Message(name)));
        Assert.True(SignatureFormat.Matches(new() { Field = "senderName", Operator = "confusableContains", Value = brand }, Message("Support " + name)));
        // Ordinary operators retain their existing NFKC semantics, including
        // matching fullwidth/mathematical lettering without a special operator.
        Assert.Equal(SignatureFormat.Normalize(name) == brand,
            SignatureFormat.Matches(new() { Field = "senderName", Operator = "equals", Value = brand }, Message(name)));
    }

    [Theory]
    [InlineData("PayPal")]
    [InlineData("PAYPAL")]
    [InlineData("PayPal Мария")]
    [InlineData("José García")]
    [InlineData("Αλέξανδρος")]
    [InlineData("Мария Иванова")]
    [InlineData("山田太郎")]
    [InlineData("مرحبا")]
    [InlineData("🎁 Example")]
    public void OrdinaryBrandsAndInternationalNamesAreNotFinancialSpoofing(string name)
    {
        var snapshot = new SignatureRepository(Path.Combine(AppContext.BaseDirectory, "signatures")).Load();
        var rule = Assert.Single(snapshot.Rules, x => x.Id == "financial-brand-sender-name-lookalike");
        Assert.False(SignatureFormat.Matches(rule.When, Message(name)));
    }

    [Fact]
    public void CompatibilityAndCanonicalNormalizationRemainAvailable()
    {
        Assert.True(SignatureFormat.Matches(new() { Field = "senderName", Operator = "equals", Value = "paypal" }, Message("ＰａｙＰａｌ")));
        Assert.True(SignatureFormat.Matches(new() { Field = "senderName", Operator = "equals", Value = "José" }, Message("Jose\u0301")));
        // Never fold confusable addresses into the explicit allow list.
        var options = new MailSentryOptions { AllowedSenders = ["owner@paypal.invalid"] };
        var result = new SpamClassifier(options).Classify(Message("Example") with { SenderAddress = "owner@раypal.invalid" }, []);
        Assert.Equal(Classification.Review, result.Classification);
    }

    [Fact]
    public void ConfusableRulesAreOptInAndSenderNameOnly()
    {
        foreach (var field in new[] { "subject", "senderAddress", "senderDomain", "body", "content" })
        {
            var rule = new Signature("test", "Test", 4, new() { Field = field, Operator = "confusableContains", Value = "paypal" });
            Assert.Throws<InvalidDataException>(() => SignatureFormat.Parse(JsonSerializer.Serialize(new SignaturePack(1, [rule]), SignatureFormat.Json)));
        }
        var valid = new Signature("test", "Test", 4, new() { Field = "senderName", Operator = "confusableEquals", Value = "paypal" });
        Assert.Single(SignatureFormat.Parse(JsonSerializer.Serialize(new SignaturePack(1, [valid]), SignatureFormat.Json)).Signatures);
        var snapshot = new SignatureRepository(Path.Combine(AppContext.BaseDirectory, "signatures")).Load();
        var result = new SpamClassifier(new()).Classify(Message("Example") with { Subject = "РayРal", BodyPreview = "РayРal" }, snapshot.Rules);
        Assert.Equal(0, result.Score);
    }

    [Fact]
    public void ConfusableBrandAloneRemainsReview()
    {
        var snapshot = new SignatureRepository(Path.Combine(AppContext.BaseDirectory, "signatures")).Load();
        var result = new SpamClassifier(new()).Classify(Message("РayРal"), snapshot.Rules);
        Assert.Equal(4, result.Score); Assert.Equal(Classification.Review, result.Classification);
    }

    [Theory]
    [InlineData("p")]
    [InlineData("раypal")]
    [InlineData(".*")]
    [InlineData("paypal\n")]
    [InlineData("p  ")]
    public void ConfusableTargetsRequireAnExplicitLatinBrand(string brand)
    {
        var rule = new Signature("test", "Test", 4, new() { Field = "senderName", Operator = "confusableContains", Value = brand });
        Assert.Throws<InvalidDataException>(() => SignatureFormat.Parse(JsonSerializer.Serialize(new SignaturePack(1, [rule]), SignatureFormat.Json)));
    }

    [Fact]
    public void InvalidUnicodeCannotRetainAnAlreadyHighScore()
    {
        var rules = new[]
        {
            new Signature("first", "First", 100, new() { Field = "subject", Operator = "equals", Value = "Hello" }),
            new Signature("unicode", "Unicode", 4, new() { Field = "senderName", Operator = "confusableContains", Value = "paypal" })
        };
        var result = new SpamClassifier(new()).Classify(Message("\ud800"), rules);
        Assert.Equal(Classification.Review, result.Classification); Assert.Equal(0, result.Score);
        Assert.False(Message("\ud800").SenderNameHasConfusables);
    }

    [Fact]
    public void CopyIncludesSafeEvidenceAndRedactsTheComparisonText()
    {
        var message = Message("РayРal recipient@example.invalid https://example.invalid/?token=secret") with
        { Authentication = new("fail", "fail", "fail", "microsoft") };
        var text = MessageExport.Create([new(message, new(Classification.Review, 4, []))]);
        Assert.Contains("SPF: fail; DKIM: fail; DMARC: fail", text);
        Assert.Contains("lookalike comparison", text); Assert.Contains("paypal [email removed] [link removed]", text);
        Assert.DoesNotContain("token=secret", text); Assert.DoesNotContain("recipient@example.invalid", text);
    }
}
