namespace MailSentry;

public sealed record AccountMailMessage(Guid AccountId, MailMessage Message);
public interface IMailboxSession : IDisposable
{
    Guid AccountId { get; }
    string MicrosoftUserId { get; }
    string MaskedMailbox { get; }
    Task<IReadOnlyList<AccountMailMessage>> ReadJunkAsync(int maximum, CancellationToken ct);
    Task QuarantineAsync(AccountMailMessage message, CancellationToken ct);
}
public interface IMailboxSessionFactory
{
    Task<IMailboxSession> OpenAsync(StoredMailbox account, CancellationToken ct);
}
public sealed class MailboxAuthenticationException : Exception
{
    public MailboxAuthenticationException() : base("Authentication required. Re-authenticate this Microsoft account.") { }
}
public sealed class MailboxProviderException : Exception
{
    public MailboxProviderException() : base("Microsoft Graph request failed. Other accounts can still be scanned.") { }
}
