namespace MailSentry;

public sealed record QuarantineSnapshot(Guid AccountId, string? FolderId, string FolderName, IReadOnlyList<string> MessageIds);
public interface IQuarantineMailboxSession : IMailboxSession
{
    Task<QuarantineSnapshot> ReadQuarantineAsync(CancellationToken ct);
    Task<bool> MoveQuarantinedToDeletedItemsAsync(QuarantineSnapshot snapshot, string messageId, CancellationToken ct);
}
