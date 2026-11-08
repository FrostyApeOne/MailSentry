using Microsoft.Graph;
using Microsoft.Graph.Models;
using Azure.Identity;
using Microsoft.Kiota.Abstractions;

namespace MailSentry;

public sealed class GraphMailboxSession(Guid accountId, string microsoftUserId, string maskedMailbox,
    GraphServiceClient client, MailSentryOptions options) : IQuarantineMailboxSession
{
    private readonly GraphMailReader _reader = new(client);
    private readonly GraphMailActions _actions = new(client, options);
    private readonly GraphQuarantineCleanup _cleanup = new(accountId, client, options);
    public Guid AccountId { get; } = accountId;
    public string MicrosoftUserId { get; } = microsoftUserId;
    public string MaskedMailbox { get; } = maskedMailbox;
    public async Task<IReadOnlyList<AccountMailMessage>> ReadJunkAsync(int maximum, CancellationToken ct)
    {
        try
        {
            return (await _reader.GetJunkMessagesAsync(maximum, ct)).Select(m =>
            {
                var message = new MailMessage(m.Id ?? "", m.From?.EmailAddress?.Name ?? "", m.From?.EmailAddress?.Address ?? "", m.Subject ?? "",
                    m.BodyPreview ?? "", m.ReceivedDateTime, m.Importance?.ToString() ?? "normal");
                return new AccountMailMessage(AccountId, message with
                {
                    Authentication = MicrosoftAuthenticationResults.Read(m.InternetMessageHeaders, message.SenderDomain)
                });
            }).ToArray();
        }
        catch (Exception e) when (e is AuthenticationRequiredException or AuthenticationFailedException) { throw new MailboxAuthenticationException(); }
        catch (ApiException e) when (e.ResponseStatusCode == 401) { throw new MailboxAuthenticationException(); }
        catch (ApiException) { throw new MailboxProviderException(); }
    }
    public async Task QuarantineAsync(AccountMailMessage message, CancellationToken ct)
    {
        if (message.AccountId != AccountId) throw new InvalidDataException("Message belongs to a different MailSentry account. No mailbox action was performed.");
        try { await _actions.QuarantineAsync(new Message { Id = message.Message.Id }, ct); }
        catch (Exception e) when (e is AuthenticationRequiredException or AuthenticationFailedException) { throw new MailboxAuthenticationException(); }
        catch (ApiException e) when (e.ResponseStatusCode == 401) { throw new MailboxAuthenticationException(); }
        catch (ApiException) { throw new MailboxProviderException(); }
    }
    public Task<QuarantineSnapshot> ReadQuarantineAsync(CancellationToken ct) => TranslateCleanup(() => _cleanup.ReadAsync(ct));
    public Task<bool> MoveQuarantinedToDeletedItemsAsync(QuarantineSnapshot snapshot, string messageId, CancellationToken ct) =>
        TranslateCleanup(() => _cleanup.MoveAsync(snapshot, messageId, ct));
    private static async Task<T> TranslateCleanup<T>(Func<Task<T>> operation)
    {
        try { return await operation(); }
        catch (Exception e) when (e is AuthenticationRequiredException or AuthenticationFailedException) { throw new MailboxAuthenticationException(); }
        catch (ApiException e) when (e.ResponseStatusCode == 401) { throw new MailboxAuthenticationException(); }
        catch (ApiException) { throw new MailboxProviderException(); }
    }
    public void Dispose() => client.Dispose();
}
