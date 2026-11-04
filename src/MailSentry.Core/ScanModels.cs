namespace MailSentry;

public sealed record ReviewMessage(MailMessage Message, ClassificationResult Result, Guid? AccountId = null, string? Mailbox = null)
{
    public string SelectionKey => AccountId is { } id ? id.ToString("N") + ":" + Message.Id : Message.Id;
}
public sealed record ScanSummary(DateTimeOffset Completed, int Scanned, int Spam, int Review, int Trusted, bool DryRun);
public sealed record ScanRunSummary(DateTimeOffset Completed, int Enabled, int Succeeded, int Failed, int Skipped, string Outcome);
public sealed record MailboxAccountView(Guid Id, string Mailbox, bool Enabled, string Authentication,
    DateTimeOffset? LastAuthenticationFailure, ScanSummary? LastScan, string ScanStatus, string? Error, DateTimeOffset? LastAttempt);
