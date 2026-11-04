using Microsoft.Graph;
using Microsoft.Kiota.Abstractions;

namespace MailSentry;

// One instance belongs to one verified Graph session. Only its own validated snapshot can be used for moves.
public sealed class GraphQuarantineCleanup(Guid accountId, GraphServiceClient client, MailSentryOptions options)
{
    private QuarantineSnapshot? _validated;
    private HashSet<string> _validatedIds = [];
    private static readonly string[] ProtectedFolders = ["inbox", "junkemail", "deleteditems", "sentitems", "drafts", "archive", "outbox"];

    public async Task<QuarantineSnapshot> ReadAsync(CancellationToken ct)
    {
        _validated = null; _validatedIds = [];
        if (string.IsNullOrWhiteSpace(options.QuarantineFolderName)) throw new InvalidDataException("Configure a dedicated quarantine folder.");
        var matches = new List<string>();
        var folders = await client.Me.MailFolders.GetAsync(c => { c.QueryParameters.Top = 100; c.QueryParameters.Select = ["id", "displayName"]; }, ct);
        var pages = new HashSet<string>(StringComparer.Ordinal);
        while (folders != null)
        {
            foreach (var folder in folders.Value ?? [])
                if (string.Equals(folder.DisplayName, options.QuarantineFolderName, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(folder.Id)) matches.Add(folder.Id);
            if (string.IsNullOrWhiteSpace(folders.OdataNextLink)) break;
            if (!pages.Add(folders.OdataNextLink)) throw new InvalidDataException("Repeated folder page. Cleanup stopped safely.");
            folders = await client.Me.MailFolders.WithUrl(folders.OdataNextLink).GetAsync(cancellationToken: ct);
        }
        if (matches.Count > 1) throw new InvalidDataException("Multiple folders have the configured quarantine name. Resolve the ambiguity before cleanup.");
        if (matches.Count == 0) return SetSnapshot(null, []);
        var folderId = matches[0];
        foreach (var name in ProtectedFolders)
        {
            try
            {
                var reserved = await client.Me.MailFolders[name].GetAsync(c => c.QueryParameters.Select = ["id"], ct);
                if (string.IsNullOrWhiteSpace(reserved?.Id)) throw new InvalidDataException("A standard mailbox folder could not be verified. Cleanup stopped safely.");
                if (reserved.Id == folderId) throw new InvalidDataException("The configured quarantine is a standard mailbox folder. Cleanup is forbidden.");
            }
            catch (ApiException e) when (e.ResponseStatusCode == 404 && (name is "archive" or "outbox")) { } // Some optional standard folders do not exist.
        }
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var response = await client.Me.MailFolders[folderId].Messages.GetAsync(c =>
        {
            c.QueryParameters.Top = 100; c.QueryParameters.Select = ["id", "parentFolderId"];
        }, ct);
        pages.Clear();
        // Collect the complete snapshot before moving anything so pagination cannot skip messages after moves.
        while (response != null)
        {
            foreach (var message in response.Value ?? [])
            {
                if (string.IsNullOrWhiteSpace(message.Id) || message.ParentFolderId != folderId)
                    throw new InvalidDataException("A message could not be verified as belonging to quarantine. Cleanup stopped safely.");
                ids.Add(message.Id);
                if (ids.Count > 100000) throw new InvalidDataException("Quarantine exceeds the cleanup limit of 100,000 messages. Reduce its size before retrying.");
            }
            if (string.IsNullOrWhiteSpace(response.OdataNextLink)) break;
            if (!pages.Add(response.OdataNextLink)) throw new InvalidDataException("Repeated message page. Cleanup stopped safely.");
            response = await client.Me.MailFolders[folderId].Messages.WithUrl(response.OdataNextLink).GetAsync(cancellationToken: ct);
        }
        return SetSnapshot(folderId, ids.Order(StringComparer.Ordinal).ToArray());
    }
    private QuarantineSnapshot SetSnapshot(string? folderId, IReadOnlyList<string> ids)
    {
        _validatedIds = ids.ToHashSet(StringComparer.Ordinal);
        return _validated = new(accountId, folderId, options.QuarantineFolderName, ids);
    }
    public async Task<bool> MoveAsync(QuarantineSnapshot snapshot, string messageId, CancellationToken ct)
    {
        if (snapshot.AccountId != accountId || !ReferenceEquals(snapshot, _validated) ||
            snapshot.FolderId is null || !_validatedIds.Contains(messageId))
            throw new InvalidDataException("Cleanup message or snapshot belongs to a different account/session. No mailbox action was performed.");
        if (options.DryRun) return false;
        try
        {
            var message = await client.Me.MailFolders[snapshot.FolderId].Messages[messageId]
                .GetAsync(c => c.QueryParameters.Select = ["id", "parentFolderId"], ct);
            if (message?.ParentFolderId != snapshot.FolderId || message.Id != messageId) return false;
            await client.Me.MailFolders[snapshot.FolderId].Messages[messageId].Move.PostAsync(
                new Microsoft.Graph.Me.MailFolders.Item.Messages.Item.Move.MovePostRequestBody { DestinationId = "deleteditems" }, cancellationToken: ct);
            return true;
        }
        catch (ApiException e) when (e.ResponseStatusCode == 404) { return false; } // Already moved/restored elsewhere.
    }
}
