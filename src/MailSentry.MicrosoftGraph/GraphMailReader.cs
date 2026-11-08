using Microsoft.Graph;
using Microsoft.Graph.Models;

namespace MailSentry;

public sealed class GraphMailReader(GraphServiceClient graphClient)
{
    public async Task<IReadOnlyCollection<Message>> GetJunkMessagesAsync(
        int maximumMessages,
        CancellationToken cancellationToken = default)
    {
        var messages = new List<Message>();

        var response = await graphClient
            .Me
            .MailFolders["junkemail"]
            .Messages
            .GetAsync(config =>
            {
                config.QueryParameters.Top = Math.Min(maximumMessages, 100);

                config.QueryParameters.Select =
                [
                    "id",
                    "subject",
                    "from",
                    "receivedDateTime",
                    "bodyPreview",
                    "importance",
                    "internetMessageHeaders"
                ];

                config.QueryParameters.Orderby =
                [
                    "receivedDateTime DESC"
                ];
            },
            cancellationToken);

        while (response is not null)
        {
            if (response.Value is not null)
            {
                foreach (var message in response.Value)
                {
                    messages.Add(message);

                    if (messages.Count >= maximumMessages)
                        return messages;
                }
            }

            if (string.IsNullOrWhiteSpace(response.OdataNextLink))
                break;

            response = await graphClient
                .Me
                .MailFolders["junkemail"]
                .Messages
                .WithUrl(response.OdataNextLink)
                .GetAsync(
                    cancellationToken: cancellationToken);
        }

        return messages;
    }
}
