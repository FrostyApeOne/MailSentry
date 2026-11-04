namespace MailSentry;
public sealed class MailSentryOptions
{
    public int SpamThreshold { get; set; } = 7;
    public bool DryRun { get; set; } = true;
    public string QuarantineFolderName { get; set; } = "MailSentry Quarantine";
    public List<string> AllowedSenders { get; set; } = [];
    public List<string> AllowedDomains { get; set; } = [];
    public string SignatureDirectory { get; set; } = "signatures";
    public string DataDirectory { get; set; } = "data";
    public int MaximumMessages { get; set; } = 500;
}
