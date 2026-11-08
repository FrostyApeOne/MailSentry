using System.Net;
using System.Text;
using System.Text.Json;
using MailSentry;
using Microsoft.Graph;
using Xunit;

public class AuthenticationEvidenceWorkflowTests
{
    private static string Junk(string result, string name = "РayРal") => JsonSerializer.Serialize(new
    {
        value = new[] { new
        {
            id = "same-id", subject = "Hello", bodyPreview = "Synthetic body",
            from = new { emailAddress = new { name, address = "sender@example.invalid" } },
            internetMessageHeaders = new[]
            {
                new { name = "Authentication-Results", value = $"spf={result}; dkim={result}; dmarc={result} header.from=example.invalid" },
                new { name = "Received", value = "from sender.invalid by ingress.mail.protection.outlook.com via Frontend Transport; date" },
                new { name = "X-Private-Diagnostic", value = "private-header-never-store" }
            }
        } }
    });

    private sealed class Handler : HttpMessageHandler
    {
        public List<string> Requests { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add(Uri.UnescapeDataString(request.RequestUri!.ToString()));
            var json = Requests.Count == 1
                ? Junk("pass")[..^1] + ",\"@odata.nextLink\":\"https://graph.microsoft.com/v1.0/me/mailFolders/junkemail/messages?$skip=1\"}"
                : Junk("fail");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") });
        }
    }

    [Fact]
    public async Task GraphReadsAndMapsAuthenticationOnEveryPageWithoutRetainingRawHeaders()
    {
        var handler = new Handler(); using var http = new HttpClient(handler);
        var account = Guid.NewGuid();
        using var session = new GraphMailboxSession(account, "synthetic-user", "sy****@example.invalid", new GraphServiceClient(http), new());
        var messages = await session.ReadJunkAsync(2, default);
        Assert.Equal(2, messages.Count); Assert.All(messages, x => Assert.Equal(account, x.AccountId));
        Assert.Contains("internetMessageHeaders", handler.Requests[0]);
        Assert.Equal("pass", messages[0].Message.Authentication.Dmarc);
        Assert.Equal("fail", messages[1].Message.Authentication.Dmarc);
        Assert.Equal("paypal", messages[0].Message.SenderNameSkeleton);
        Assert.DoesNotContain("private-header-never-store", JsonSerializer.Serialize(messages));
        Assert.All(handler.Requests, request => Assert.Contains("/junkemail/messages", request));
    }

    [Fact]
    public async Task EvidenceSurvivesRestartAndPreviewAcrossAccountsThenLiveScanUsesCorrectMailbox()
    {
        using var f = new MultiAccountFixture();
        var a = await f.Add("a.tenant"); var b = await f.Add("b.tenant");
        f.JunkResponseOverrides["a.tenant"] = Junk("fail"); f.JunkResponseOverrides["b.tenant"] = Junk("fail");
        File.Copy(Path.Combine(AppContext.BaseDirectory, "signatures", "007-authentication.json"), Path.Combine(f.SignaturePath, "007-authentication.json"));
        var scanner = new Scanner(f.Authentication, f.Options, f.Signatures, f.Store, f.Accounts);
        Assert.True(await scanner.ScanAsync());
        Assert.Equal(2, scanner.Unmatched.Count); Assert.All(scanner.Unmatched, x => Assert.Equal(3, x.Result.Score));
        var restarted = new Scanner(f.Authentication, f.Options, f.Signatures, f.Store, new AccountRepository(f.Store)); restarted.Refresh();
        Assert.All(restarted.Unmatched, x => Assert.Equal("fail", x.Message.Authentication.Dmarc));
        Assert.All(restarted.Unmatched, x => Assert.True(x.Message.SenderNameHasConfusables));
        var installer = new SignatureInstaller(f.Signatures, restarted, f.Options, f.Store);
        f.Requests.Clear();
        var preview = installer.Preview("008-financial-impersonation.json", File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "signatures", "008-financial-impersonation.json")));
        Assert.Equal(2, preview.NewSpam); Assert.Equal(2, preview.Accounts.Count);
        Assert.Equal(new[] { a, b }.Order(), preview.Matches.Select(x => x.AccountId).Order());
        Assert.All(preview.Matches, x => Assert.Equal("sy****@example.invalid", x.Mailbox));
        Assert.Empty(f.Requests);
        installer.Activate(preview.Token); Assert.Empty(f.Requests);
        Assert.True(await restarted.ScanAsync()); // DryRun still performs no writes.
        Assert.DoesNotContain(f.Requests, x => x.Method != "GET");
        f.Options.DryRun = false; f.Requests.Clear(); Assert.True(await restarted.ScanAsync());
        Assert.Equal(2, f.Requests.Count(x => x.Path.EndsWith("/move")));
        Assert.Contains(f.Requests, x => x.Home == "a.tenant" && x.Body.Contains("quarantine-a.tenant"));
        Assert.Contains(f.Requests, x => x.Home == "b.tenant" && x.Body.Contains("quarantine-b.tenant"));
        var state = JsonSerializer.Serialize(f.Accounts.ReadAll());
        var log = File.ReadAllText(Assert.Single(Directory.GetFiles(f.DirectoryPath, "audit-*.log")));
        Assert.DoesNotContain("private-header-never-store", state); Assert.DoesNotContain("private-header-never-store", log);
        Assert.DoesNotContain("РayРal", log); Assert.DoesNotContain("Synthetic body", log);
    }
}
