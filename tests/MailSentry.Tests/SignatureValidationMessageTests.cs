using MailSentry;
using Xunit;

public class SignatureValidationMessageTests
{
    [Fact]
    public void StartsWithArrayReportsRuleFieldOperatorAndRequiredProperty()
    {
        const string json = """
            {"version":1,"signatures":[{"id":"known-generated-double-hyphen-domain","name":"Generated domain","score":10,
              "when":{"field":"senderDomain","operator":"startsWith","values":["--"]}}]}
            """;
        var error = Assert.Throws<InvalidDataException>(() => SignatureFormat.Parse(json));
        Assert.Contains("known-generated-double-hyphen-domain", error.Message);
        Assert.Contains("senderDomain", error.Message);
        Assert.Contains("startsWith", error.Message);
        Assert.Contains("'value'", error.Message);
        Assert.Contains("not a 'values' array", error.Message);
        var corrected = json.Replace("\"values\":[\"--\"]", "\"value\":\"--\"");
        var rule = Assert.Single(SignatureFormat.Parse(corrected).Signatures);
        Assert.True(SignatureFormat.Matches(rule.When, new("id", "Example", "x@--example.invalid", "", "")));
        Assert.False(SignatureFormat.Matches(rule.When, new("id", "Example", "x@example.invalid", "", "")));
    }

    [Fact]
    public void NestedErrorIdentifiesConditionAndRepositoryRetainsExplanation()
    {
        const string json = """
            {"version":1,"signatures":[{"id":"nested-rule","name":"Nested rule","score":4,
              "when":{"all":[{"field":"subject","operator":"containsAny","value":"example"}]}}]}
            """;
        var error = Assert.Throws<InvalidDataException>(() => SignatureFormat.Parse(json));
        Assert.Contains("when.all[0]", error.Message);
        Assert.Contains("'values' array", error.Message);
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            File.WriteAllText(Path.Combine(directory, "invalid.json"), json);
            var snapshot = new SignatureRepository(directory).Load();
            Assert.Empty(snapshot.Rules);
            Assert.Contains("nested-rule", Assert.Single(snapshot.Errors));
            Assert.Contains("when.all[0]", snapshot.Errors[0]);
        }
        finally { Directory.Delete(directory, true); }
    }
}
