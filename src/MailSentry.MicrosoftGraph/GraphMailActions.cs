using Microsoft.Graph;
using Microsoft.Graph.Models;
namespace MailSentry;

public sealed class GraphMailActions(GraphServiceClient graphClient, MailSentryOptions options)
{
    private string? _quarantineFolderId;
    public async Task QuarantineAsync(Message message, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(message.Id)) return;
        if (options.DryRun) return;
        var folderId = await GetOrCreateQuarantineFolderAsync(cancellationToken);
        await graphClient.Me.Messages[message.Id].Move.PostAsync(new Microsoft.Graph.Me.Messages.Item.Move.MovePostRequestBody { DestinationId = folderId }, cancellationToken: cancellationToken);
    }
    private async Task<string> GetOrCreateQuarantineFolderAsync(CancellationToken ct)
    {
        if (_quarantineFolderId != null) return _quarantineFolderId;
        var folders = await graphClient.Me.MailFolders.GetAsync(c => { c.QueryParameters.Top = 100; c.QueryParameters.Select = ["id", "displayName"]; }, ct);
        while (folders != null)
        {
            var existing = folders.Value?.FirstOrDefault(f => string.Equals(f.DisplayName, options.QuarantineFolderName, StringComparison.OrdinalIgnoreCase));
            if (existing?.Id is { } id) return _quarantineFolderId = id;
            if (string.IsNullOrWhiteSpace(folders.OdataNextLink)) break;
            folders = await graphClient.Me.MailFolders.WithUrl(folders.OdataNextLink).GetAsync(cancellationToken: ct);
        }
        var folder = await graphClient.Me.MailFolders.PostAsync(new MailFolder { DisplayName = options.QuarantineFolderName }, cancellationToken: ct);
        return _quarantineFolderId = folder?.Id ?? throw new InvalidOperationException("Unable to create quarantine folder.");
    }
}
