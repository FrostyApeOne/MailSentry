using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
namespace MailSentry;

public sealed class OperationalStore(string directory)
{
    public string DirectoryPath { get; } = Path.GetFullPath(directory);
    private string StatePath => Path.Combine(DirectoryPath, "scan-state.bin");
    public bool IsBusy
    {
        get
        {
            if (!Directory.Exists(DirectoryPath)) return false;
            try { using var lease = TryAcquire(); return lease == null; }
            catch (UnauthorizedAccessException) { return false; }
        }
    }
    private static readonly object AuditGate = new();
    public FileStream? TryAcquire()
    {
        Directory.CreateDirectory(DirectoryPath);
        try { return new FileStream(Path.Combine(DirectoryPath, "scan.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
        catch (IOException) { return null; }
    }
    public void Audit(string action)
    {
        Directory.CreateDirectory(DirectoryPath);
        lock (AuditGate)
        {
            using var file = new FileStream(Path.Combine(DirectoryPath, $"audit-{DateTime.UtcNow:yyyy-MM-dd}.log"), FileMode.Append, FileAccess.Write, FileShare.Read);
            using var writer = new StreamWriter(file, Encoding.UTF8);
            writer.WriteLine($"{DateTimeOffset.UtcNow:O} | {action.Replace('\r', ' ').Replace('\n', ' ')}");
        }
    }
    public sealed record State(ScanSummary? LastScan, string? Mailbox, IReadOnlyList<ReviewMessage> Unmatched, string? Error);
    public void Save(State state)
    {
        Directory.CreateDirectory(DirectoryPath);
        var bytes = Protect(JsonSerializer.SerializeToUtf8Bytes(state));
        var temp = StatePath + ".tmp"; File.WriteAllBytes(temp, bytes); File.Move(temp, StatePath, true);
    }
    public State? Load()
    {
        try { return File.Exists(StatePath) ? JsonSerializer.Deserialize<State>(Unprotect(File.ReadAllBytes(StatePath))) : null; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or CryptographicException or JsonException) { return null; }
    }
    public void SaveRun(ScanRunSummary run) => ProtectedFile.Write(Path.Combine(DirectoryPath, "scan-run.bin"), JsonSerializer.SerializeToUtf8Bytes(run));
    public ScanRunSummary? LoadRun()
    {
        var path = Path.Combine(DirectoryPath, "scan-run.bin");
        return File.Exists(path) ? JsonSerializer.Deserialize<ScanRunSummary>(ProtectedFile.Read(path)) : null;
    }
    private static byte[] Protect(byte[] data)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("State storage requires Windows DPAPI.");
        return ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser);
    }
    private static byte[] Unprotect(byte[] data)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("State storage requires Windows DPAPI.");
        return ProtectedData.Unprotect(data, null, DataProtectionScope.CurrentUser);
    }
}
public static class ConfigurationValidation
{
    public static void Validate(MailSentryOptions o, string clientId)
    {
        if (!Guid.TryParse(clientId, out var id) || id == Guid.Empty) throw new InvalidDataException("Configure a valid MicrosoftGraph:ClientId.");
        if (o.SpamThreshold is < 7 or > 10000) throw new InvalidDataException("SpamThreshold must be between 7 and 10000.");
        if (o.MaximumMessages is < 1 or > 5000) throw new InvalidDataException("MaximumMessages must be between 1 and 5000.");
        string[] reserved = ["inbox", "junkemail", "junk email", "deleteditems", "deleted items", "sentitems", "sent items", "drafts", "archive"];
        if (string.IsNullOrWhiteSpace(o.QuarantineFolderName) || o.QuarantineFolderName.Length > 200 || reserved.Contains(o.QuarantineFolderName.Trim(), StringComparer.OrdinalIgnoreCase)) throw new InvalidDataException("Configure a dedicated quarantine folder name.");
        if (string.IsNullOrWhiteSpace(o.DataDirectory) || string.IsNullOrWhiteSpace(o.SignatureDirectory)) throw new InvalidDataException("Configure data and signature directories.");
        if (o.AllowedSenders is null || o.AllowedDomains is null || o.AllowedSenders.Any(s => string.IsNullOrWhiteSpace(s) || !s.Contains('@')) || o.AllowedDomains.Any(s => string.IsNullOrWhiteSpace(s) || s.Contains('@') || s.Contains('*') || s.Contains('/')))
            throw new InvalidDataException("Allow lists require explicit sender addresses or exact domains.");
    }
}
