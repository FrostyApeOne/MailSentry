using System.Text.Json;
using MailSentry;
using Microsoft.Graph.Models;
using Xunit;

public class EmailAuthenticationTests
{
    private const string Failure = "spf=fail (sender IP is 192.0.2.1) smtp.mailfrom=example.invalid; " +
        "dkim=fail (signature did not verify) header.d=example.invalid; dmarc=fail action=none header.from=example.invalid";
    private static InternetMessageHeader Header(string name, string value) => new() { Name = name, Value = value };
    private static List<InternetMessageHeader> Headers(string value) =>
    [
        Header("Received", "from internal.prod.outlook.com by mailbox.prod.outlook.com with Microsoft SMTP Server; Sun, 8 Nov 2026 09:00:00 +0000"),
        Header("Authentication-Results", value),
        Header("Received", "from sender.example.invalid by ingress.mail.protection.outlook.com with Microsoft SMTP Server via Frontend Transport; Sun, 8 Nov 2026 08:59:59 +0000")
    ];
    private static MailAuthenticationResults Read(string value) => MicrosoftAuthenticationResults.Read(Headers(value), "example.invalid");
    private static IReadOnlyList<Signature> Rules()
    {
        var snapshot = new SignatureRepository(Path.Combine(AppContext.BaseDirectory, "signatures")).Load();
        Assert.Empty(snapshot.Errors); return snapshot.Rules;
    }
    private static MailMessage Message(MailAuthenticationResults authentication, string name = "Example") =>
        new("synthetic", name, "sender@example.invalid", "Hello", "") { Authentication = authentication };

    [Theory]
    [InlineData("")]
    [InlineData("mx.microsoft.com 1; ")]
    [InlineData("outlook.com; ")]
    public void MicrosoftResultsAcceptKnownFormatsAndFoldedHeaders(string prefix)
    {
        var result = Read(prefix + Failure.Replace("; ", ";\r\n\t"));
        Assert.True(result.IsProviderResult);
        Assert.Equal("fail", result.Spf); Assert.Equal("fail", result.Dkim); Assert.Equal("fail", result.Dmarc);
        var serialized = JsonSerializer.Serialize(result);
        Assert.DoesNotContain("192.0.2.1", serialized); Assert.DoesNotContain("example.invalid", serialized);
        Assert.DoesNotContain("signature did not verify", serialized);
    }

    [Theory]
    [InlineData("pass", "pass", "pass")]
    [InlineData("softfail", "none", "fail")]
    [InlineData("temperror", "permerror", "none")]
    [InlineData("neutral", "policy", "bestguesspass")]
    [InlineData("invented", "invented", "invented")]
    public void ResultCodesAreFinite(string spf, string dkim, string dmarc)
    {
        var result = Read($"spf={spf}; dkim={dkim}; dmarc={dmarc} header.from=example.invalid");
        Assert.Equal(spf == "invented" ? "unknown" : spf, result.Spf);
        Assert.Equal(dkim == "invented" ? "unknown" : dkim, result.Dkim);
        Assert.Equal(dmarc == "invented" ? "unknown" : dmarc, result.Dmarc);
    }

    [Fact]
    public void MissingLegacyAndArcHeadersDoNotSupplyEvidence()
    {
        Assert.Equal(MailAuthenticationResults.Unknown, MicrosoftAuthenticationResults.Read(null, "example.invalid"));
        var headers = Headers(Failure); headers[1].Name = "ARC-Authentication-Results";
        Assert.Equal(MailAuthenticationResults.Unknown, MicrosoftAuthenticationResults.Read(headers, "example.invalid"));
        headers[1].Name = "Authentication-Results-Original";
        Assert.Equal(MailAuthenticationResults.Unknown, MicrosoftAuthenticationResults.Read(headers, "example.invalid"));
        var old = JsonSerializer.Deserialize<MailMessage>("""{"Id":"id","SenderName":"Example","SenderAddress":"sender@example.invalid","Subject":"Hello","BodyPreview":""}""");
        Assert.Equal(MailAuthenticationResults.Unknown, old!.Authentication);
    }

    [Theory]
    [InlineData("attacker.invalid; ")]
    [InlineData("outlook.com.attacker.invalid; ")]
    [InlineData("mx.microsoft.com.attacker.invalid; ")]
    public void UntrustedAuthservIdsNeverSupplyEvidence(string prefix)
    {
        var result = Read(prefix + Failure);
        Assert.False(result.IsProviderResult); Assert.Equal("unknown", result.Dmarc);
    }

    [Fact]
    public void ForgedHeadersBelowMicrosoftIngressAreIgnoredEvenWithMicrosoftEhlo()
    {
        var headers = Headers("spf=pass; dkim=pass; dmarc=pass header.from=example.invalid");
        headers[2].Value = headers[2].Value!.Replace("sender.example.invalid", "sender.prod.outlook.com");
        headers.Add(Header("Authentication-Results", "mx.microsoft.com; " + Failure));
        var result = MicrosoftAuthenticationResults.Read(headers, "example.invalid");
        Assert.Equal("pass", result.Dmarc);
        headers.RemoveAt(1);
        result = MicrosoftAuthenticationResults.Read(headers, "example.invalid");
        Assert.False(result.IsProviderResult); Assert.Equal("unknown", result.Dmarc);
    }

    [Theory]
    [InlineData("ingress.mail.protection.outlook.com.attacker.invalid")]
    [InlineData("ingress.attacker.invalid")]
    public void FakeMicrosoftReceiverSuffixIsRejected(string receiver)
    {
        var headers = Headers(Failure); headers[2].Value = $"from external.invalid by {receiver} via Frontend Transport; date";
        Assert.False(MicrosoftAuthenticationResults.Read(headers, "example.invalid").IsProviderResult);
    }

    [Fact]
    public void UnknownOrAmbiguousTransportLayoutIsNotTrusted()
    {
        var headers = Headers(Failure); headers.RemoveAt(2);
        Assert.False(MicrosoftAuthenticationResults.Read(headers, "example.invalid").IsProviderResult);
        headers = Headers(Failure); headers.Insert(2, Header("Authentication-Results", Failure));
        Assert.False(MicrosoftAuthenticationResults.Read(headers, "example.invalid").IsProviderResult);
        headers = Headers(Failure); headers[0].Value = "from sender.invalid by gateway.attacker.invalid; date";
        Assert.False(MicrosoftAuthenticationResults.Read(headers, "example.invalid").IsProviderResult);
    }

    [Fact]
    public void LegacyInternalProtectionHopsDoNotHideIngressResults()
    {
        var headers = Headers(Failure);
        headers[0].Value = "from internal.prod.outlook.com by internal.eop-eur02.prod.protection.outlook.com with Microsoft SMTP Server; date";
        Assert.Equal("fail", MicrosoftAuthenticationResults.Read(headers, "example.invalid").Dmarc);
        headers[2].Value = "from external.invalid by ingress.prod.outlook.com with Microsoft SMTP Server via Frontend Transport; date";
        Assert.Equal("fail", MicrosoftAuthenticationResults.Read(headers, "example.invalid").Dmarc);
    }

    [Theory]
    [InlineData("spf=fail (unterminated")]
    [InlineData("spf=fail\nInjected: header")]
    [InlineData("spf=fail\r\nInjected: header")]
    [InlineData("spf=fail reason=\"unterminated")]
    public void MalformedResultsFailSafely(string value) => Assert.False(Read(value).IsProviderResult);

    [Fact]
    public void DiagnosticsAndCommentsCannotInjectResults()
    {
        var result = Read("spf=pass (nested (spf=fail; dmarc=fail)); dkim=pass reason=\"x; dmarc=fail header.from=example.invalid\"; dmarc=pass header.from=example.invalid");
        Assert.Equal("pass", result.Spf); Assert.Equal("pass", result.Dkim); Assert.Equal("pass", result.Dmarc);
    }

    [Fact]
    public void OversizedHeadersAndDuplicateAssessmentsDoNotAddEvidence()
    {
        Assert.False(Read(new string('x', 16385)).IsProviderResult);
        var result = Read(Failure + "; spf=pass; dmarc=pass header.from=example.invalid");
        Assert.Equal("unknown", result.Spf); Assert.Equal("unknown", result.Dmarc);
        result = Read(Failure + "; dkim=pass header.d=other.invalid");
        Assert.Equal("pass", result.Dkim);
    }

    [Theory]
    [InlineData("different.invalid")]
    [InlineData("example.invalid.attacker.invalid")]
    [InlineData("")]
    public void DmarcMustDescribeTheCurrentFromDomain(string domain)
    {
        var result = Read($"spf=fail; dkim=fail; dmarc=fail header.from={domain}");
        Assert.Equal("unknown", result.Dmarc);
        Assert.Equal(0, new SpamClassifier(new()).Classify(Message(result), Rules()).Score);
    }

    [Theory]
    [InlineData("spf=fail; dkim=pass; dmarc=pass header.from=example.invalid", 0)]
    [InlineData("spf=none; dkim=none; dmarc=none header.from=example.invalid", 0)]
    [InlineData("spf=temperror; dkim=temperror; dmarc=temperror header.from=example.invalid", 0)]
    [InlineData("spf=pass; dkim=pass; dmarc=fail header.from=example.invalid", 0)]
    [InlineData(Failure, 3)]
    public void AuthenticationAloneNeverQuarantinesEvenForOwnAddress(string header, int score)
    {
        var message = Message(Read(header)) with { SenderAddress = "my-own-address@example.invalid" };
        var result = new SpamClassifier(new()).Classify(message, Rules());
        Assert.Equal(score, result.Score); Assert.Equal(Classification.Review, result.Classification);
    }

    [Fact]
    public void SpoofingEvidenceCanCorroborateAnObfuscatedFinancialBrand()
    {
        var result = new SpamClassifier(new()).Classify(Message(Read(Failure), "РayРal"), Rules());
        Assert.Equal(7, result.Score); Assert.Equal(Classification.Spam, result.Classification);
        Assert.Equal(2, result.Reasons.Count);
        var untrusted = Message(new("fail", "fail", "fail", "untrusted"), "РayРal");
        Assert.Equal(Classification.Review, new SpamClassifier(new()).Classify(untrusted, Rules()).Classification);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ExplicitAllowListStillWinsOverSpoofingAndConfusableRules(bool sender)
    {
        var options = new MailSentryOptions();
        if (sender) options.AllowedSenders.Add("sender@example.invalid"); else options.AllowedDomains.Add("example.invalid");
        var result = new SpamClassifier(options).Classify(Message(Read(Failure), "РayРal"), Rules());
        Assert.Equal(Classification.Trusted, result.Classification); Assert.Equal(0, result.Score);
    }
}
