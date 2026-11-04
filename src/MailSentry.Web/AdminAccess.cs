using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace MailSentry;

public sealed class AdminAccess
{
    private readonly byte[] expectedAuthorization;
    private readonly HashSet<string> hosts;

    public AdminAccess(string? password, string? allowedHosts)
    {
        if (string.IsNullOrWhiteSpace(password) || password.Length < 16)
            throw new InvalidDataException("Set Admin:Password (or MAILSENTRY_Admin__Password) to a unique password of at least 16 characters. Web administration always requires authentication, including localhost.");
        hosts = new((allowedHosts ?? "localhost;127.0.0.1;[::1]").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), StringComparer.OrdinalIgnoreCase);
        expectedAuthorization = SHA256.HashData(Encoding.UTF8.GetBytes("Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("admin:" + password))));
    }

    public int? RejectionStatus(HttpContext context)
    {
        if (!hosts.Contains(context.Request.Host.Host)) return StatusCodes.Status400BadRequest;
        // Forwarded headers are never trusted. A proxy must use HTTPS to MailSentry;
        // plain HTTP is reserved for direct, authenticated loopback administration.
        if (!context.Request.IsHttps && (context.Connection.RemoteIpAddress is not { } ip || !IPAddress.IsLoopback(ip) ||
            context.Request.Headers.Any(h => h.Key.Equals("Forwarded", StringComparison.OrdinalIgnoreCase) || h.Key.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase))))
            return StatusCodes.Status403Forbidden;
        var actual = SHA256.HashData(Encoding.UTF8.GetBytes(context.Request.Headers.Authorization.ToString()));
        return CryptographicOperations.FixedTimeEquals(expectedAuthorization, actual) ? null : StatusCodes.Status401Unauthorized;
    }
}
