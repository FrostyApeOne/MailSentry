using Azure.Core;
using Azure.Identity;
using System.Text.Json;

namespace MailSentry;

public sealed record AuthenticationPrompt(string UserCode, string VerificationUri, DateTimeOffset ExpiresOn);

public sealed record CredentialLogin(AuthenticationRecord Record, TokenCredential Credential);
public interface IAccountCredentialFactory
{
    TokenCredential CreateSilent(AuthenticationRecord record);
    Task<CredentialLogin> AuthenticateAsync(Func<AuthenticationPrompt, Task> display, CancellationToken ct);
}
public sealed class AzureAccountCredentialFactory(string clientId) : IAccountCredentialFactory
{
    public const string CacheName = "JunkCleanerV2"; // Preserve existing encrypted cache across the upgrade.
    public static readonly string[] Scopes = ["Mail.ReadWrite", "User.Read"];
    public static TokenCachePersistenceOptions CacheOptions() => new() { Name = CacheName, UnsafeAllowUnencryptedStorage = false };
    public InteractiveBrowserCredentialOptions SilentOptions(AuthenticationRecord record) => new()
    {
        ClientId = clientId,
        TenantId = "consumers",
        RedirectUri = new Uri("http://localhost"),
        AuthenticationRecord = record,
        TokenCachePersistenceOptions = CacheOptions(),
        DisableAutomaticAuthentication = true
    };
    public TokenCredential CreateSilent(AuthenticationRecord record) => new InteractiveBrowserCredential(SilentOptions(record));
    public async Task<CredentialLogin> AuthenticateAsync(Func<AuthenticationPrompt, Task> display, CancellationToken ct)
    {
        var credential = new DeviceCodeCredential(new DeviceCodeCredentialOptions
        {
            ClientId = clientId,
            TenantId = "consumers",
            TokenCachePersistenceOptions = CacheOptions(),
            DeviceCodeCallback = (info, _) => display(new(info.UserCode, info.VerificationUri.ToString(), info.ExpiresOn))
        });
        var record = await credential.AuthenticateAsync(new TokenRequestContext(Scopes), ct);
        return new(record, credential);
    }
}
public static class AuthenticationRecordCodec
{
    public static AuthenticationRecord Parse(byte[] bytes)
    {
        if (bytes.Length > 65536) throw new InvalidDataException("Authentication record exceeds the supported size.");
        using var json = JsonDocument.Parse(bytes);
        if (json.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Authentication record must be an object.");
        var properties = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var property in json.RootElement.EnumerateObject())
            if (!properties.Add(property.Name)) throw new InvalidDataException("Authentication record has duplicate properties.");
        foreach (var field in new[] { "homeAccountId", "clientId", "authority", "tenantId", "version" })
        {
            if (!json.RootElement.TryGetProperty(field, out var value) || value.ValueKind != JsonValueKind.String ||
                string.IsNullOrWhiteSpace(value.GetString()) || value.GetString()!.Any(char.IsControl))
                throw new InvalidDataException("Authentication record is incomplete. Re-authenticate the affected account.");
        }
        if (json.RootElement.GetProperty("version").GetString() != "1.0")
            throw new InvalidDataException("Authentication record version is unsupported. Re-authenticate this account.");
        using var stream = new MemoryStream(bytes);
        return AuthenticationRecord.Deserialize(stream);
    }
    public static byte[] Serialize(AuthenticationRecord record)
    {
        using var stream = new MemoryStream(); record.Serialize(stream); return stream.ToArray();
    }
}
