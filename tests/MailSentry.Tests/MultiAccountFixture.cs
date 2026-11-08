using Azure.Core;
using Azure.Identity;
using MailSentry;
using Microsoft.Graph;
using System.Net;
using System.Text;
using System.Text.Json;

public sealed class MultiAccountFixture : IDisposable
{
    public const string ClientId = "11111111-1111-1111-1111-111111111111";
    public string DirectoryPath { get; } = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
    public string SignaturePath => Path.Combine(DirectoryPath, "signatures");
    public OperationalStore Store { get; }
    public AccountRepository Accounts { get; }
    public MailSentryOptions Options { get; } = new();
    public SignatureRepository Signatures { get; }
    public LegacyAccountMigration Migration { get; }
    public FakeCredentials Credentials { get; } = new();
    public GraphAuthentication Authentication { get; }
    public List<(string Home, string Method, string Path, string Body)> Requests { get; } = [];
    public HashSet<string> AuthFailures { get; } = [];
    public HashSet<string> GraphFailures { get; } = [];
    public Dictionary<string, List<string>> Quarantined { get; } = [];
    public Dictionary<string, string> QuarantineFolderOverrides { get; } = [];
    public int? FailCleanupAfter { get; set; }
    public int CleanupMoves { get; private set; }
    public Dictionary<string, string> GraphIdentityOverrides { get; } = [];
    public Dictionary<string, string> JunkResponseOverrides { get; } = [];
    public MultiAccountFixture()
    {
        Directory.CreateDirectory(SignaturePath); Store = new(DirectoryPath); Accounts = new(Store); Signatures = new(SignaturePath);
        Migration = new(ClientId, Accounts, Store, Path.Combine(DirectoryPath, "legacy.json"));
        Authentication = new(ClientId, Accounts, Store, Options, Migration, Credentials,
            credential => new GraphServiceClient(new HttpClient(new Handler(this, ((FakeTokenCredential)credential).Home))));
        File.WriteAllText(Path.Combine(SignaturePath, "shared.json"), JsonSerializer.Serialize(new SignaturePack(1,
            [new("synthetic-spam", "Synthetic rule", 7, new() { Field = "subject", Operator = "equals", Value = "synthetic spam" })]), SignatureFormat.Json));
    }
    public async Task<Guid> Add(string home)
    {
        Credentials.LoginHome = home;
        return await Authentication.AuthenticateAsync(null, _ => Task.CompletedTask);
    }
    public void Dispose() { Directory.Delete(DirectoryPath, true); }
    public sealed class FakeTokenCredential(string home) : TokenCredential
    {
        public string Home => home;
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) => new("synthetic-token-never-log", DateTimeOffset.UtcNow.AddHours(1));
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) => ValueTask.FromResult(GetToken(requestContext, cancellationToken));
    }
    public sealed class FakeCredentials : IAccountCredentialFactory
    {
        public string LoginHome { get; set; } = "a.tenant";
        public int InteractiveCalls { get; private set; }
        public List<string> SilentHomes { get; } = [];
        public TokenCredential CreateSilent(AuthenticationRecord record) { SilentHomes.Add(record.HomeAccountId); return new FakeTokenCredential(record.HomeAccountId); }
        public Task<CredentialLogin> AuthenticateAsync(Func<AuthenticationPrompt, Task> display, CancellationToken ct)
        {
            InteractiveCalls++;
            return Task.FromResult(new CredentialLogin(AuthenticationRecordCodec.Parse(AccountStorageTests.Record(LoginHome)), new FakeTokenCredential(LoginHome)));
        }
    }
    private sealed class Handler(MultiAccountFixture fixture, string home) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath; var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
            fixture.Requests.Add((home, request.Method.Method, path, body));
            if (fixture.AuthFailures.Contains(home)) return Response(HttpStatusCode.Unauthorized, "{\"error\":{\"code\":\"InvalidAuthenticationToken\",\"message\":\"synthetic-token-never-log\"}}");
            if (path.EndsWith("/me")) return Response(HttpStatusCode.OK, JsonSerializer.Serialize(new { id = fixture.GraphIdentityOverrides.GetValueOrDefault(home, "graph-" + home), mail = "synthetic@example.invalid" }));
            if (fixture.GraphFailures.Contains(home)) return Response(HttpStatusCode.Forbidden, "{\"error\":{\"code\":\"ErrorAccessDenied\",\"message\":\"synthetic-private-error\"}}");
            if (path.EndsWith("/junkemail/messages")) return Response(HttpStatusCode.OK, fixture.JunkResponseOverrides.GetValueOrDefault(home,
                "{\"value\":[{\"id\":\"same-id\",\"subject\":\"synthetic spam\",\"from\":{\"emailAddress\":{\"address\":\"sender@example.invalid\"}}},{\"id\":\"review-id\",\"subject\":\"uncertain\"}]}"));
            var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            var folderPosition = Array.IndexOf(segments, "mailFolders");
            if (folderPosition >= 0 && segments.Length > folderPosition + 1)
            {
                var folder = segments[folderPosition + 1];
                if (segments.Length == folderPosition + 2)
                    return Response(HttpStatusCode.OK, JsonSerializer.Serialize(new { id = "protected-" + folder + "-" + home }));
                if (segments[folderPosition + 2] == "messages")
                {
                    var ids = fixture.Quarantined.GetValueOrDefault(home) ?? [];
                    if (segments.Length == folderPosition + 3)
                        return Response(HttpStatusCode.OK, JsonSerializer.Serialize(new { value = ids.Select(id => new { id, parentFolderId = folder }).ToArray() }));
                    var message = segments[folderPosition + 3];
                    if (!ids.Contains(message)) return Response(HttpStatusCode.NotFound, "{}");
                    if (request.Method == HttpMethod.Get)
                        return Response(HttpStatusCode.OK, JsonSerializer.Serialize(new { id = message, parentFolderId = folder }));
                    if (path.EndsWith("/move"))
                    {
                        if (fixture.FailCleanupAfter is { } limit && fixture.CleanupMoves >= limit)
                            return Response(HttpStatusCode.Forbidden, "{\"error\":{\"code\":\"ErrorAccessDenied\",\"message\":\"synthetic-private-error\"}}");
                        fixture.CleanupMoves++; ids.Remove(message);
                        return Response(HttpStatusCode.OK, "{\"id\":\"deleted-item\"}");
                    }
                }
            }
            if (path.EndsWith("/mailFolders")) return Response(HttpStatusCode.OK, JsonSerializer.Serialize(new { value = new[] { new { id = fixture.QuarantineFolderOverrides.GetValueOrDefault(home, "quarantine-" + home), displayName = fixture.Options.QuarantineFolderName } } }));
            if (path.EndsWith("/move")) return Response(HttpStatusCode.OK, "{\"id\":\"moved\"}");
            throw new InvalidOperationException("Unexpected synthetic Graph request.");
        }
        private static HttpResponseMessage Response(HttpStatusCode status, string json) => new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
    }
}
