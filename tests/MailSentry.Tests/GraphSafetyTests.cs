using System.Net;
using System.Text;
using MailSentry;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Xunit;
public class GraphSafetyTests
{
    private sealed class Handler(params string[] responses) : HttpMessageHandler
    {
        public List<(string Method, string Uri, string Body)> Requests { get; } = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add((request.Method.Method, request.RequestUri!.ToString(), request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct)));
            return new(HttpStatusCode.OK) { Content = new StringContent(responses[Requests.Count - 1], Encoding.UTF8, "application/json") };
        }
    }
    [Fact]
    public async Task DryRunMakesNoGraphRequests()
    {
        var handler = new Handler(); using var http = new HttpClient(handler); var client = new GraphServiceClient(http);
        await new GraphMailActions(client, new() { DryRun = true }).QuarantineAsync(new() { Id = "synthetic", Subject = "synthetic" });
        Assert.Empty(handler.Requests);
    }
    [Fact]
    public async Task QuarantineUsesMoveAndFindsFolderAcrossPages()
    {
        var handler = new Handler("{\"value\":[],\"@odata.nextLink\":\"https://graph.microsoft.com/v1.0/me/mailFolders?$skip=100\"}", "{\"value\":[{\"id\":\"quarantine\",\"displayName\":\"MailSentry Quarantine\"}]}", "{\"id\":\"moved\"}");
        using var http = new HttpClient(handler); var client = new GraphServiceClient(http);
        await new GraphMailActions(client, new() { DryRun = false }).QuarantineAsync(new() { Id = "synthetic" });
        Assert.Equal(3, handler.Requests.Count); Assert.EndsWith("/move", handler.Requests[2].Uri); Assert.Equal("POST", handler.Requests[2].Method);
        Assert.Contains("quarantine", handler.Requests[2].Body); Assert.DoesNotContain(handler.Requests, r => r.Method == "DELETE");
    }
    [Fact]
    public async Task ReaderOnlyReadsJunkAndRespectsMaximumAcrossPages()
    {
        var handler = new Handler("{\"value\":[{\"id\":\"one\"}],\"@odata.nextLink\":\"https://graph.microsoft.com/v1.0/me/mailFolders/junkemail/messages?$skip=1\"}", "{\"value\":[{\"id\":\"two\"},{\"id\":\"three\"}]}");
        using var http = new HttpClient(handler); var client = new GraphServiceClient(http);
        var messages = await new GraphMailReader(client).GetJunkMessagesAsync(2); Assert.Equal(2, messages.Count);
        Assert.All(handler.Requests, r => { Assert.Equal("GET", r.Method); Assert.Contains("junkemail/messages", r.Uri); });
    }
}
