using MailSentry;
using Microsoft.Graph;
using System.Net;
using System.Text;
using System.Text.Json;
using Xunit;

public class GraphQuarantineCleanupTests
{
    private sealed class Handler(bool missing = false, bool missingInbox = false) : HttpMessageHandler
    {
        public List<(string Method, string Path, string Body)> Requests { get; } = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            Requests.Add((request.Method.Method, path, request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct)));
            string json;
            if (path.EndsWith("/mailFolders")) json = missing ? "{\"value\":[]}" : "{\"value\":[{\"id\":\"quarantine\",\"displayName\":\"MailSentry Quarantine\"}]}";
            else if (path.EndsWith("/mailFolders/inbox") && missingInbox) return new(HttpStatusCode.NotFound) { Content = new StringContent("{}", Encoding.UTF8, "application/json") };
            else if (path.EndsWith("/messages/one")) json = "{\"id\":\"one\",\"parentFolderId\":\"inbox-id\"}"; // Restored since snapshot.
            else if (path.EndsWith("/messages/two")) json = "{\"id\":\"two\",\"parentFolderId\":\"quarantine\"}";
            else if (path.EndsWith("/move")) json = "{\"id\":\"deleted\"}";
            else if (path.EndsWith("/messages") && request.RequestUri.Query.Contains("skip")) json = "{\"value\":[{\"id\":\"two\",\"parentFolderId\":\"quarantine\"}]}";
            else if (path.EndsWith("/messages")) json = "{\"value\":[{\"id\":\"one\",\"parentFolderId\":\"quarantine\"}],\"@odata.nextLink\":\"https://graph.microsoft.com/v1.0/me/mailFolders/quarantine/messages?$skip=1\"}";
            else json = JsonSerializer.Serialize(new { id = "protected-" + path.Split('/').Last() });
            return new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        }
    }
    [Fact]
    public async Task CompleteSnapshotIsPagedBeforeMovesAndRestoredMessagesAreSkipped()
    {
        var handler = new Handler(); using var http = new HttpClient(handler); var client = new GraphServiceClient(http);
        var account = Guid.NewGuid(); var cleanup = new GraphQuarantineCleanup(account, client, new() { DryRun = false });
        var snapshot = await cleanup.ReadAsync(default);
        Assert.Equal(new[] { "one", "two" }, snapshot.MessageIds);
        Assert.DoesNotContain(handler.Requests, r => r.Method == "POST");
        Assert.False(await cleanup.MoveAsync(snapshot, "one", default));
        Assert.True(await cleanup.MoveAsync(snapshot, "two", default));
        var post = Assert.Single(handler.Requests, r => r.Method == "POST");
        Assert.EndsWith("/mailFolders/quarantine/messages/two/move", post.Path); Assert.Contains("deleteditems", post.Body);
        await Assert.ThrowsAsync<InvalidDataException>(() => cleanup.MoveAsync(snapshot with { FolderId = "inbox-id" }, "two", default));
        await Assert.ThrowsAsync<InvalidDataException>(() => cleanup.MoveAsync(snapshot with { AccountId = Guid.NewGuid() }, "two", default));
        await Assert.ThrowsAsync<InvalidDataException>(() => cleanup.MoveAsync(snapshot, "not-in-quarantine", default));
    }
    [Fact]
    public async Task MissingQuarantineIsEmptyAndNeverCreated()
    {
        var handler = new Handler(missing: true); using var http = new HttpClient(handler); var client = new GraphServiceClient(http);
        var cleanup = new GraphQuarantineCleanup(Guid.NewGuid(), client, new() { DryRun = false });
        var snapshot = await cleanup.ReadAsync(default);
        Assert.Null(snapshot.FolderId); Assert.Empty(snapshot.MessageIds); Assert.Single(handler.Requests);
        Assert.DoesNotContain(handler.Requests, r => r.Method != "GET");
    }
    [Fact]
    public async Task UnverifiableStandardFolderStopsCleanup()
    {
        var handler = new Handler(missingInbox: true); using var http = new HttpClient(handler); var client = new GraphServiceClient(http);
        var cleanup = new GraphQuarantineCleanup(Guid.NewGuid(), client, new() { DryRun = false });
        await Assert.ThrowsAnyAsync<Exception>(() => cleanup.ReadAsync(default));
        Assert.DoesNotContain(handler.Requests, r => r.Method != "GET");
    }
    [Fact]
    public async Task SessionRejectsAnotherAccountsSnapshot()
    {
        using var f = new MultiAccountFixture(); f.Options.DryRun = false;
        var a = await f.Add("a.tenant"); var b = await f.Add("b.tenant");
        f.Quarantined["a.tenant"] = ["one"]; f.Quarantined["b.tenant"] = ["one"];
        using var sessionA = await f.Authentication.OpenAsync(f.Accounts.Get(a), default);
        using var sessionB = await f.Authentication.OpenAsync(f.Accounts.Get(b), default);
        var snapshot = await ((IQuarantineMailboxSession)sessionA).ReadQuarantineAsync(default);
        var count = f.Requests.Count;
        await Assert.ThrowsAsync<InvalidDataException>(() => ((IQuarantineMailboxSession)sessionB).MoveQuarantinedToDeletedItemsAsync(snapshot, "one", default));
        Assert.Equal(count, f.Requests.Count);
    }
}
