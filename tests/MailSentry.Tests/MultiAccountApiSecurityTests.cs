using MailSentry;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Xunit;

public class MultiAccountApiSecurityTests
{
    [Theory]
    [InlineData("MAILSENTRY_")]
    [InlineData("ASPNETCORE_")]
    [InlineData("")]
    public async Task AccountApiPreservesHostAdminCsrfAndSafeProjectionControls(string environmentPrefix)
    {
        using var f = new MultiAccountFixture(); var a = await f.Add("a.tenant"); var b = await f.Add("b.tenant");
        var scanner = new Scanner(f.Authentication, f.Options, f.Signatures, f.Store, f.Accounts); Assert.True(await scanner.ScanAsync());
        var key = Assert.Single(scanner.Unmatched, x => x.AccountId == a).SelectionKey;
        var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); var port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop();
        var assembly = typeof(Scanner).Assembly.Location;
        const string password = "synthetic-test-password-only";
        var configurationFile = Path.Combine(f.DirectoryPath, "web-test-settings.json");
        File.WriteAllText(configurationFile, JsonSerializer.Serialize(new
        {
            MicrosoftGraph = new { ClientId = "must-be-overridden-by-environment" },
            MailSentry = new { DryRun = true },
            Admin = new { Password = "" }
        }));
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = f.DirectoryPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        ClearApplicationEnvironment(start);
        start.Environment[environmentPrefix + "Admin__Password"] = password;
        start.Environment[environmentPrefix + "MicrosoftGraph__ClientId"] = MultiAccountFixture.ClientId;
        start.Environment[environmentPrefix + "MailSentry__DataDirectory"] = f.DirectoryPath;
        start.Environment[environmentPrefix + "MailSentry__SignatureDirectory"] = f.SignaturePath;
        foreach (var arg in new[]{assembly,"--web","--urls",$"http://127.0.0.1:{port}","--configuration-file",configurationFile}) start.ArgumentList.Add(arg);
        // The referenced application lives in the test output; all runtime data is isolated and synthetic.
        using var process = Process.Start(start)!;
        using var http = new HttpClient(new HttpClientHandler { CookieContainer = new CookieContainer() }) { BaseAddress = new Uri($"http://127.0.0.1:{port}"), Timeout = TimeSpan.FromSeconds(5) };
        try
        {
            HttpResponseMessage? response = null;
            for (var attempt = 0; attempt < 100; attempt++)
            {
                try { response = await http.GetAsync("/api/status"); break; } catch (HttpRequestException) { if (process.HasExited) throw new InvalidOperationException("Synthetic Web host exited during startup."); await Task.Delay(100); }
            }
            Assert.NotNull(response); Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, (await http.GetAsync("/api/signatures/file?fileName=shared.json")).StatusCode);
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("admin:" + password)));
            var proxyRequest = new HttpRequestMessage(HttpMethod.Get, "/api/status"); proxyRequest.Headers.Add("X-Forwarded-Proto", "https");
            Assert.Equal(HttpStatusCode.Forbidden, (await http.SendAsync(proxyRequest)).StatusCode);
            var badHost = new HttpRequestMessage(HttpMethod.Get, "/api/status"); badHost.Headers.Host = "untrusted.invalid";
            Assert.Equal(HttpStatusCode.BadRequest, (await http.SendAsync(badHost)).StatusCode);
            response = await http.GetAsync("/api/status"); Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Contains("no-store", response.Headers.CacheControl!.ToString()); Assert.True(response.Headers.Contains("Content-Security-Policy"));
            var status = await response.Content.ReadAsStringAsync();
            using (var parsedStatus = JsonDocument.Parse(status))
            {
                Assert.True(parsedStatus.RootElement.GetProperty("dryRun").GetBoolean());
                var signatures = parsedStatus.RootElement.GetProperty("signatures");
                Assert.Equal(1, signatures.GetProperty("count").GetInt32());
                Assert.False(signatures.TryGetProperty("rules", out _));
                Assert.Equal(64, signatures.GetProperty("revision").GetString()!.Length);
                Assert.Equal("shared.json", Assert.Single(signatures.GetProperty("files").EnumerateArray()).GetString());
            }
            foreach (var privateValue in new[] { "HomeAccountId", "homeAccountId", "AuthenticationRecord", "authenticationRecord", "graph-a.tenant", "a.tenant", "synthetic-token-never-log" }) Assert.DoesNotContain(privateValue, status);
            Assert.Equal(HttpStatusCode.BadRequest, (await http.PostAsync($"/api/accounts/{a}/enabled", Json("{\"enabled\":false}"))).StatusCode);
            Assert.True(f.Accounts.Get(a).Account.Enabled);
            Assert.Equal(HttpStatusCode.BadRequest, (await http.PostAsync("/api/signatures/delete", Json("{\"fileName\":\"shared.json\",\"fingerprint\":\"invalid\",\"confirmed\":true}"))).StatusCode);
            Assert.Single(f.Signatures.Load().Rules);
            Assert.Equal(HttpStatusCode.BadRequest, (await http.PostAsync($"/api/accounts/{a}/quarantine/wipe", Json("{\"confirmed\":true,\"token\":\"invalid\"}"))).StatusCode);
            using var session = JsonDocument.Parse(await http.GetStringAsync("/api/session"));
            http.DefaultRequestHeaders.Add("X-CSRF-TOKEN", session.RootElement.GetProperty("token").GetString());
            Assert.Equal(HttpStatusCode.OK, (await http.PostAsync("/api/copy", Json(JsonSerializer.Serialize(new[] { key })))).StatusCode);
            var copy = await (await http.PostAsync("/api/copy", Json(JsonSerializer.Serialize(new[] { key })))).Content.ReadAsStringAsync();
            Assert.Contains("Mailbox:", copy); Assert.DoesNotContain("MESSAGE 2", copy); Assert.DoesNotContain("synthetic@example.invalid", copy);
            Assert.Equal(HttpStatusCode.BadRequest, (await http.PostAsync($"/api/accounts/{a}/remove", Json("{\"confirmed\":false}"))).StatusCode);
            Assert.Equal(2, f.Accounts.ReadAll().Count);
            Assert.Equal(HttpStatusCode.BadRequest, (await http.PostAsync($"/api/accounts/{a}/quarantine/wipe", Json("{\"confirmed\":false,\"token\":\"invalid\"}"))).StatusCode);
            Assert.Equal(HttpStatusCode.BadRequest, (await http.PostAsync($"/api/accounts/{a}/quarantine/wipe", Json("{\"confirmed\":true,\"token\":\"invalid\"}"))).StatusCode);
            var script = await http.GetStringAsync("/app.js"); Assert.Contains("Wipe quarantine mails", script);
            var previewJson = "{\"version\":1,\"signatures\":[{\"id\":\"api-preview\",\"name\":\"API preview\",\"score\":7,\"when\":{\"field\":\"subject\",\"operator\":\"equals\",\"value\":\"uncertain\"}}]}";
            var preview = await http.PostAsync("/api/signatures/preview-pasted", new StringContent(previewJson, Encoding.UTF8, "text/plain"));
            Assert.Equal(HttpStatusCode.OK, preview.StatusCode);
            using var impact = JsonDocument.Parse(await preview.Content.ReadAsStringAsync());
            Assert.Equal(2, impact.RootElement.GetProperty("accounts").GetArrayLength());
            Assert.Equal(HttpStatusCode.OK, (await http.PostAsync($"/api/accounts/{a}/enabled", Json("{\"enabled\":false}"))).StatusCode);
            var token = impact.RootElement.GetProperty("token").GetString();
            Assert.Equal(HttpStatusCode.BadRequest, (await http.PostAsync("/api/signatures/activate/" + token, Json("{}"))).StatusCode);
            Assert.Single(f.Signatures.Load().Rules);
            Assert.Equal(HttpStatusCode.OK, (await http.PostAsync($"/api/accounts/{a}/remove", Json("{\"confirmed\":true}"))).StatusCode);
            Assert.Equal(b, Assert.Single(f.Accounts.ReadAll()).Account.Id);
            using var savedFile = JsonDocument.Parse(await http.GetStringAsync("/api/signatures/file?fileName=shared.json"));
            var fingerprint = savedFile.RootElement.GetProperty("fingerprint").GetString();
            Assert.Equal(File.ReadAllText(Path.Combine(f.SignaturePath, "shared.json")), savedFile.RootElement.GetProperty("json").GetString());
            Assert.Equal(HttpStatusCode.BadRequest, (await http.GetAsync("/api/signatures/file?fileName=" + Uri.EscapeDataString("../appsettings.json"))).StatusCode);
            Assert.Equal(HttpStatusCode.BadRequest, (await http.PostAsync("/api/signatures/delete", Json(JsonSerializer.Serialize(new { fileName = "shared.json", fingerprint, confirmed = false })))).StatusCode);
            Assert.Equal(HttpStatusCode.BadRequest, (await http.PostAsync("/api/signatures/delete", Json("{\"fileName\":\"shared.json\",\"fingerprint\":\"invalid\",\"confirmed\":true}"))).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await http.PostAsync("/api/signatures/delete", Json(JsonSerializer.Serialize(new { fileName = "shared.json", fingerprint, confirmed = true })))).StatusCode);
            Assert.Empty(f.Signatures.Load().Rules);
            Assert.Equal(b, Assert.Single(f.Accounts.ReadAll()).Account.Id);
        }
        finally { if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); } }
    }
    [Theory]
    [InlineData("")]
    [InlineData("short-password")]
    public async Task MissingOrWeakAdminPasswordStopsWebBeforeCreatingState(string password)
    {
        using var f = new MultiAccountFixture();
        var configurationFile = Path.Combine(f.DirectoryPath, "isolated-startup-settings.json");
        var unopenedData = Path.Combine(f.DirectoryPath, "must-not-be-created");
        File.WriteAllText(configurationFile, JsonSerializer.Serialize(new
        {
            MicrosoftGraph = new { ClientId = MultiAccountFixture.ClientId },
            MailSentry = new { DataDirectory = unopenedData, SignatureDirectory = f.SignaturePath },
            Admin = new { Password = password }
        }));
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        {
            UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = f.DirectoryPath, RedirectStandardError = true, RedirectStandardOutput = true
        };
        ClearApplicationEnvironment(start);
        foreach (var arg in new[] { typeof(Scanner).Assembly.Location, "--web", "--configuration-file", configurationFile }) start.ArgumentList.Add(arg);
        using var process = Process.Start(start)!;
        try
        {
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
            Assert.Equal(2, process.ExitCode);
            var error = await process.StandardError.ReadToEndAsync();
            Assert.Contains("Admin:Password", error);
            Assert.False(Directory.Exists(unopenedData));
        }
        finally { if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); } }
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StartupErrorsDistinguishMalformedConfigurationFromLegacyCertificateSettings(bool certificateFailure)
    {
        using var f = new MultiAccountFixture();
        const string secret = "synthetic-startup-secret-never-log";
        var configurationFile = Path.Combine(f.DirectoryPath, "startup-settings.json");
        File.WriteAllText(configurationFile, certificateFailure ? JsonSerializer.Serialize(new
        {
            MicrosoftGraph = new { ClientId = MultiAccountFixture.ClientId },
            MailSentry = new { DataDirectory = f.DirectoryPath, SignatureDirectory = f.SignaturePath },
            Admin = new { Password = secret }
        }) : "{\"private\":\"" + secret + "\", invalid}");
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        {
            UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = f.DirectoryPath, RedirectStandardError = true, RedirectStandardOutput = true
        };
        ClearApplicationEnvironment(start);
        foreach (var arg in new[] { typeof(Scanner).Assembly.Location, "--web", "--configuration-file", configurationFile, "--urls", "https://127.0.0.1:0" }) start.ArgumentList.Add(arg);
        if (certificateFailure)
        {
            start.Environment["ASPNETCORE_Kestrel__Certificates__Default__Path"] = Path.Combine(f.DirectoryPath, "missing-certificate.pfx");
            start.Environment["ASPNETCORE_Kestrel__Certificates__Default__Password"] = secret;
        }
        using var process = Process.Start(start)!;
        try
        {
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
            Assert.Equal(2, process.ExitCode);
            var error = await process.StandardError.ReadToEndAsync();
            Assert.Contains(certificateFailure ? "certificate" : "configuration", error);
            Assert.DoesNotContain(secret, error);
            Assert.DoesNotContain(secret, await process.StandardOutput.ReadToEndAsync());
        }
        finally { if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); } }
    }
    private static void ClearApplicationEnvironment(ProcessStartInfo start)
    {
        foreach (var name in start.Environment.Keys.Where(k =>
            k.StartsWith("MAILSENTRY_", StringComparison.OrdinalIgnoreCase) ||
            k.StartsWith("ASPNETCORE_", StringComparison.OrdinalIgnoreCase) ||
            k.StartsWith("Admin__", StringComparison.OrdinalIgnoreCase) ||
            k.StartsWith("MicrosoftGraph__", StringComparison.OrdinalIgnoreCase) ||
            k.StartsWith("MailSentry__", StringComparison.OrdinalIgnoreCase) ||
            k.StartsWith("Kestrel__", StringComparison.OrdinalIgnoreCase) ||
            k.Equals("Urls", StringComparison.OrdinalIgnoreCase) ||
            k.Equals("AllowedHosts", StringComparison.OrdinalIgnoreCase) ||
            k.Equals("DOTNET_ENVIRONMENT", StringComparison.OrdinalIgnoreCase)).ToArray()) start.Environment.Remove(name);
    }
    private static StringContent Json(string body) => new(body, Encoding.UTF8, "application/json");
}
