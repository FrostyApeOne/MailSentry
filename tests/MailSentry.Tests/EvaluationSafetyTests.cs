using MailSentry;
using Xunit;
public class EvaluationSafetyTests
{
    [Fact]
    public void RegexTimeoutDiscardsEvenAnAlreadyHighScore()
    {
        var rules = new[] { new Signature("first", "First", 100, new() { Field = "subject", Operator = "startsWith", Value = "a" }), new Signature("slow", "Slow", 7, new() { Field = "subject", Operator = "regex", Value = "^(a+)+$" }) };
        var result = new SpamClassifier(new()).Classify(new("id", "Example", "x@example.invalid", new string('a', 5000) + "!", ""), rules);
        Assert.Equal(Classification.Review, result.Classification); Assert.Equal(0, result.Score); Assert.Contains("Signature evaluation failed safely", result.Reasons);
    }
}
