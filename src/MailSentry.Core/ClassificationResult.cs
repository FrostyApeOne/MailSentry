namespace MailSentry;

public enum Classification
{
    Trusted,
    Review,
    Spam
}

public sealed record ClassificationResult(
    Classification Classification,
    int Score,
    IReadOnlyCollection<string> Reasons);
