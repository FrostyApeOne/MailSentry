using MailSentry;
using Microsoft.AspNetCore.Antiforgery;
using System.Security.Cryptography;
using System.Text;

var startupPhase = StartupPhase.Configuration;
try
{
    var webMode = args.Contains("--web");
    var applicationArgs = args.Where(a => a != "--web" && a != "--scan").ToArray();
    var commandLine = new ConfigurationBuilder().AddCommandLine(applicationArgs).Build();
    var configurationFile = Path.GetFullPath(commandLine["configuration-file"] ?? Path.Combine(AppContext.BaseDirectory, "appsettings.json"));
    var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = applicationArgs, ContentRootPath = AppContext.BaseDirectory, WebRootPath = Path.Combine(AppContext.BaseDirectory, "wwwroot") });
    StartupConfiguration.Load(builder.Configuration, configurationFile, builder.Environment.EnvironmentName,
        commandLine["configuration-file"] is not null, applicationArgs);
    builder.Logging.ClearProviders(); // Do not log authentication URLs, credentials or message content.
    AdminAccess? adminAccess = null;
    if (webMode)
    {
        try { adminAccess = new(builder.Configuration["Admin:Password"], builder.Configuration["Admin:AllowedHosts"]); }
        catch (InvalidDataException e) { Console.Error.WriteLine(e.Message); Environment.ExitCode = 2; return; }
    }
    var options = builder.Configuration.GetSection("MailSentry").Get<MailSentryOptions>() ?? new();
    var clientId = builder.Configuration["MicrosoftGraph:ClientId"] ?? "";
    try { ConfigurationValidation.Validate(options, clientId); }
    catch (InvalidDataException e) { Console.Error.WriteLine(e.Message); Environment.ExitCode = 2; return; }
    var data = Path.GetFullPath(options.DataDirectory, AppContext.BaseDirectory);
    var signatures = new SignatureRepository(Path.GetFullPath(options.SignatureDirectory, AppContext.BaseDirectory));
    startupPhase = StartupPhase.Storage;
    var store = new OperationalStore(data);
    var accounts = new AccountRepository(store);
    var migration = new LegacyAccountMigration(clientId, accounts, store, File.Exists(Path.Combine(Environment.CurrentDirectory, "auth-record.json")) ? Path.Combine(Environment.CurrentDirectory, "auth-record.json") : Path.Combine(AppContext.BaseDirectory, "auth-record.json"));
    await migration.RunAsync();
    var authentication = new GraphAuthentication(clientId, accounts, store, options, migration);
    var scanner = new Scanner(authentication, options, signatures, store, accounts);
    scanner.Refresh();
    var installer = new SignatureInstaller(signatures, scanner, options, store);
    var quarantineCleanup = new QuarantineCleanupService(authentication, accounts, options, store);
    if (!webMode)
    {
        var success = await scanner.ScanAsync();
        Console.WriteLine(scanner.Error ?? $"Scan completed: {scanner.LastScan}");
        Environment.ExitCode = success && scanner.Error is null ? 0 : 1; return;
    }
    builder.Services.Configure<Microsoft.AspNetCore.Http.Features.FormOptions>(o => o.MultipartBodyLengthLimit = 1048576);
    builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 1100000);
    builder.Services.AddAntiforgery(o => o.HeaderName = "X-CSRF-TOKEN");
    startupPhase = StartupPhase.Listener;
    var app = builder.Build();
    app.Use(async (ctx, next) =>
    {
        ctx.Response.Headers.CacheControl = "no-store";
        ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
        ctx.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
        if (adminAccess!.RejectionStatus(ctx) is { } status)
        {
            ctx.Response.StatusCode = status;
            if (status == StatusCodes.Status401Unauthorized) ctx.Response.Headers.WWWAuthenticate = "Basic realm=\"MailSentry\"";
            return;
        }
        if (HttpMethods.IsPost(ctx.Request.Method))
        {
            try { await ctx.RequestServices.GetRequiredService<IAntiforgery>().ValidateRequestAsync(ctx); }
            catch (AntiforgeryValidationException) { ctx.Response.StatusCode = 400; return; }
        }
        try { await next(); }
        catch (Exception e) when (e is InvalidDataException or System.Text.Json.JsonException or ArgumentException or IOException or UnauthorizedAccessException or CryptographicException)
        { ctx.Response.StatusCode = 400; await ctx.Response.WriteAsJsonAsync(new { error = e is InvalidDataException ? e.Message : "Invalid request or unavailable file. Check signature status before retrying activation." }); }
    });
    app.UseDefaultFiles(); app.UseStaticFiles();
    app.MapGet("/api/session", (HttpContext ctx, IAntiforgery anti) => new { token = anti.GetAndStoreTokens(ctx).RequestToken });
    app.MapGet("/api/status", () =>
    {
        scanner.Refresh();
        return new
        {
            provider = "Microsoft Outlook",
            accounts = scanner.AccountViews,
            authenticationOperations = authentication.Operations,
            migrationError = migration.Error,
            scanner = scanner.DisplayStatus,
            lastScan = scanner.LastScan,
            lastRun = scanner.LastRun,
            error = scanner.Error,
            dryRun = options.DryRun,
            signatures = signatures.Load(),
            signatureFiles = installer.FileNames(),
            unmatched = scanner.Unmatched.Count
        };
    });
    app.MapPost("/api/accounts/add", () => Results.Accepted(value: new { operationId = authentication.Start(null, app.Lifetime.ApplicationStopping) }));
    app.MapPost("/api/accounts/{id:guid}/reauthenticate", (Guid id) =>
        Results.Accepted(value: new { operationId = authentication.Start(id, app.Lifetime.ApplicationStopping) }));
    app.MapPost("/api/accounts/{id:guid}/enabled", (Guid id, AccountEnabledRequest request) =>
    {
        authentication.SetEnabled(id, request.Enabled); scanner.Refresh(); return Results.Ok();
    });
    app.MapPost("/api/accounts/{id:guid}/remove", async (Guid id, AccountRemovalRequest request) =>
    {
        await authentication.RemoveAsync(id, request.Confirmed, app.Lifetime.ApplicationStopping); scanner.Refresh(); return Results.Ok();
    });
    app.MapPost("/api/accounts/{id:guid}/quarantine/preview", async (Guid id) =>
        Results.Ok(await quarantineCleanup.PreviewAsync(id, app.Lifetime.ApplicationStopping)));
    app.MapPost("/api/accounts/{id:guid}/quarantine/wipe", async (Guid id, QuarantineCleanupRequest request) =>
    {
        var result = await quarantineCleanup.ExecuteAsync(id, request.Token, request.Confirmed, app.Lifetime.ApplicationStopping);
        scanner.Refresh(); return Results.Ok(result);
    });
    app.MapPost("/api/scan", async () =>
    {
        var success = await scanner.ScanAsync(app.Lifetime.ApplicationStopping);
        return Results.Ok(new { success, run = scanner.LastRun, error = scanner.Error });
    });
    app.MapGet("/api/unmatched", () => { scanner.Refresh(); return scanner.Unmatched; });
    app.MapPost("/api/copy", (string[] ids) => { scanner.Refresh(); return Results.Text(MessageExport.Create(scanner.Unmatched.Where(x => ids.Contains(x.SelectionKey))), "text/plain"); });
    app.MapPost("/api/signatures/preview", async (HttpRequest request) =>
    {
        if (request.ContentLength is null or > 1100000) return Results.BadRequest(new { error = "Upload limit is 1 MB." });
        var form = await request.ReadFormAsync(); var file = form.Files.GetFile("file");
        if (file is null || file.Length is < 1 or > 1048576) return Results.BadRequest(new { error = "Select a JSON file under 1 MB." });
        if (!await scanner.Gate.WaitAsync(0)) return Results.Conflict(new { error = "Scan running. Try again when it completes." });
        try { using var reader = new StreamReader(file.OpenReadStream()); return Results.Ok(installer.Preview(file.FileName, await reader.ReadToEndAsync())); }
        finally { scanner.Gate.Release(); }
    });
    app.MapGet("/api/signatures/file", (string fileName) => Results.Ok(installer.Read(fileName)));
    app.MapPost("/api/signatures/delete", async (SignatureDeletionRequest request) =>
    {
        if (!await scanner.Gate.WaitAsync(0)) return Results.Conflict(new { error = "Scan running. Try again when it completes." });
        try { return Results.Ok(installer.Delete(request)); }
        finally { scanner.Gate.Release(); }
    });
    app.MapPost("/api/signatures/preview-pasted", async (HttpRequest request) =>
    {
        if (request.ContentLength > 1048576)
            return Results.BadRequest(new { error = "Signature JSON limit is 1 MB." });
        if (!string.Equals(request.ContentType?.Split(';')[0].Trim(), "text/plain", StringComparison.OrdinalIgnoreCase))
            return Results.BadRequest(new { error = "Submit pasted JSON as text/plain." });
        if (!await scanner.Gate.WaitAsync(0))
            return Results.Conflict(new { error = "Scan running. Try again when it completes." });
        try
        {
            using var reader = new StreamReader(request.Body, Encoding.UTF8);
            return Results.Ok(installer.PreviewPasted(await reader.ReadToEndAsync(request.HttpContext.RequestAborted)));
        }
        finally { scanner.Gate.Release(); }
    });
    app.MapPost("/api/signatures/activate/{token}", async (string token) =>
    {
        if (!await scanner.Gate.WaitAsync(0)) return Results.Conflict(new { error = "Scan running. Try again when it completes." });
        try { return Results.Ok(installer.Activate(token)); } finally { scanner.Gate.Release(); }
    });
    app.MapPost("/api/signatures/cancel/{token}", async (string token) => { await scanner.Gate.WaitAsync(); try { installer.Cancel(token); return Results.Ok(); } finally { scanner.Gate.Release(); } });
    await app.RunAsync();


}
catch (IOException e) when (e.InnerException is Microsoft.AspNetCore.Connections.AddressInUseException)
{
    Console.Error.WriteLine("MailSentry could not start because the requested address/port is already in use. Stop the existing MailSentry instance or choose another port with --urls (for example, http://localhost:5081).");
    Environment.ExitCode = 2;
}
catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException or FormatException or System.Text.Json.JsonException or CryptographicException ||
    (startupPhase == StartupPhase.Listener && e is InvalidOperationException))
{
    Console.Error.WriteLine(StartupDiagnostics.Describe(startupPhase, e));
    Environment.ExitCode = 2;
}
