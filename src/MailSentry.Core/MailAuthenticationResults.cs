namespace MailSentry;

// Only finite result codes cross the provider boundary. Never retain raw headers,
// IP addresses, authentication service IDs or provider diagnostic text here.
public sealed record MailAuthenticationResults(
    string Spf = "unknown", string Dkim = "unknown", string Dmarc = "unknown",
    string Source = "unavailable")
{
    public static MailAuthenticationResults Unknown { get; } = new();
    public bool IsProviderResult => Source == "microsoft";
    public string Summary => $"SPF: {Spf}; DKIM: {Dkim}; DMARC: {Dmarc} ({Source})";
}
