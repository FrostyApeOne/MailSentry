namespace MailSentry;
public sealed record AccountEnabledRequest(bool Enabled);
public sealed record AccountRemovalRequest(bool Confirmed);
