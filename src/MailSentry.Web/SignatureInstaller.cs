using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace MailSentry;
public sealed record SignatureAccountImpact(Guid AccountId, string Mailbox, int Tested, int NewSpam, int StillUnmatched);
public sealed record SignatureMatch(Guid AccountId, string Mailbox, string Subject);
public sealed record SavedSignatureFile(string FileName, string Json, string Fingerprint);
public sealed record SignatureDeletionRequest(string FileName, string Fingerprint, bool Confirmed);
public sealed record SignatureImpact(string Token, string FileName, int Rules, int Conditions, int Tested, int NewSpam,
    int StillUnmatched, string[] Subjects, IReadOnlyList<SignatureAccountImpact> Accounts, IReadOnlyList<SignatureMatch> Matches);
public sealed class SignatureInstaller(SignatureRepository repository, Scanner scanner, MailSentryOptions options, OperationalStore? store = null)
{
    private sealed record Pending(string FileName, string Json, string Fingerprint, DateTimeOffset Expires);
    private readonly Dictionary<string, Pending> _pending = [];
    public string[] FileNames()
    {
        try
        {
            return Directory.GetFiles(repository.DirectoryPath, "*.json")
                .Where(f => (File.GetAttributes(f) & FileAttributes.ReparsePoint) == 0)
                .Select(Path.GetFileName).OfType<string>().Order(StringComparer.Ordinal).ToArray();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return []; }
    }

    private string SavedPath(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName) || fileName != Path.GetFileName(fileName) ||
            fileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || fileName.Contains('/') || fileName.Contains('\\') ||
            !fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Select a JSON file in the signature repository.");
        var path = Path.Combine(repository.DirectoryPath, fileName);
        if (!File.Exists(path)) throw new InvalidDataException("Signature file no longer exists. Refresh the list.");
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Linked signature files cannot be viewed or deleted.");
        return path;
    }

    public SavedSignatureFile Read(string fileName)
    {
        var path = SavedPath(fileName);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > 1048576) throw new InvalidDataException("Signature viewing limit is 1 MB.");
        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        using var reader = new StreamReader(new MemoryStream(bytes), Encoding.UTF8);
        return new(fileName, reader.ReadToEnd(), Convert.ToHexString(SHA256.HashData(bytes)));
    }

    public SignatureSnapshot Delete(SignatureDeletionRequest request)
    {
        if (!request.Confirmed) throw new InvalidDataException("Confirm signature file deletion first.");
        using var transaction = scanner.Repository.Begin();
        var saved = Read(request.FileName);
        if (!string.Equals(saved.Fingerprint, request.Fingerprint, StringComparison.Ordinal))
            throw new InvalidDataException("Signature file changed. Open it again and review before deleting.");
        store?.Audit("SIGNATURE_DELETION | Confirmed");
        File.Delete(SavedPath(request.FileName));
        _pending.Clear();
        var snapshot = repository.Load();
        scanner.Reevaluate(snapshot.Rules, transaction);
        store?.Audit($"SIGNATURE_DELETED | Rules={snapshot.Rules.Count}");
        return snapshot;
    }
    private string Fingerprint()
    {
        var files = Directory.GetFiles(repository.DirectoryPath, "*.json").Order(StringComparer.Ordinal).Select(f => Path.GetFileName(f) + File.ReadAllText(f));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", files) + JsonSerializer.Serialize(scanner.Unmatched) + JsonSerializer.Serialize(options) + scanner.Repository.Fingerprint())));
    }
    private SignaturePack Validate(string json, SignatureSnapshot current)
    {
        if (current.Errors.Count > 0) throw new InvalidDataException("Fix existing signature errors first.");
        var pack = SignatureFormat.Parse(json);
        var ids = current.Rules.Select(r => r.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (pack.Signatures.Any(r => ids.Contains(r.Id))) throw new InvalidDataException("Duplicate signature ID.");
        return pack;
    }
    public SignatureImpact PreviewPasted(string json) =>
        Preview($"pasted-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.json", json);

    public SignatureImpact Preview(string fileName, string json)
    {
        if (string.IsNullOrWhiteSpace(json) || Encoding.UTF8.GetByteCount(json) > 1048576)
            throw new InvalidDataException("Provide signature JSON between 1 byte and 1 MB.");
        using var transaction = scanner.Repository.Begin();
        if (Path.GetFileName(fileName) != fileName || !System.Text.RegularExpressions.Regex.IsMatch(fileName, @"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,100}\.json$") || File.Exists(Path.Combine(repository.DirectoryPath, fileName)))
            throw new InvalidDataException("Use a new JSON file name containing letters, digits, dots, hyphens or underscores.");
        scanner.Refresh(true);
        var fingerprint = Fingerprint();
        var current = repository.Load(); var pack = Validate(json, current);
        var classifier = new SpamClassifier(options); var rules = current.Rules.Concat(pack.Signatures).ToArray();
        var newSpam = scanner.Unmatched.Where(x => classifier.Classify(x.Message, rules).Classification == Classification.Spam).ToArray();
        foreach (var old in _pending.Where(x => x.Value.Expires < DateTimeOffset.UtcNow).Select(x => x.Key).ToArray()) _pending.Remove(old);
        if (_pending.Count >= 20) throw new InvalidDataException("Too many pending previews. Cancel an existing preview.");
        if (fingerprint != Fingerprint()) throw new InvalidDataException("Messages or signatures changed during preview. Upload again.");
        var token = Guid.NewGuid().ToString("N"); _pending[token] = new(fileName, json, fingerprint, DateTimeOffset.UtcNow.AddMinutes(15));
        return new(token, fileName, pack.Signatures.Count, pack.Signatures.Sum(x => Count(x.When)), scanner.Unmatched.Count, newSpam.Length, scanner.Unmatched.Count - newSpam.Length, newSpam.Select(x => x.Message.Subject).ToArray(),
            scanner.AccountViews.Where(a => a.Enabled).Select(a =>
            {
                var tested = scanner.Unmatched.Count(m => m.AccountId == a.Id);
                var matched = newSpam.Count(m => m.AccountId == a.Id);
                return new SignatureAccountImpact(a.Id, a.Mailbox, tested, matched, tested - matched);
            }).ToArray(), newSpam.Select(x => new SignatureMatch(x.AccountId!.Value, x.Mailbox!, x.Message.Subject)).ToArray());
    }
    private static int Count(Condition c) => c.All?.Sum(Count) ?? c.Any?.Sum(Count) ?? 1;
    public void Cancel(string token) => _pending.Remove(token);
    public SignatureSnapshot Activate(string token)
    {
        using var transaction = scanner.Repository.Begin();
        scanner.Refresh(true);
        if (!_pending.Remove(token, out var pending) || pending.Expires < DateTimeOffset.UtcNow) throw new InvalidDataException("Preview expired. Upload and preview again.");
        if (pending.Fingerprint != Fingerprint()) throw new InvalidDataException("Messages or signatures changed. Upload and preview again before confirming.");
        _ = Validate(pending.Json, repository.Load());
        store?.Audit("SIGNATURE_ACTIVATION | Confirmed");
        var destination = Path.Combine(repository.DirectoryPath, pending.FileName);
        var temp = Path.Combine(repository.DirectoryPath, Guid.NewGuid() + ".tmp");
        try { File.WriteAllText(temp, pending.Json); File.Move(temp, destination, false); }
        finally { if (File.Exists(temp)) File.Delete(temp); }
        var snapshot = repository.Load();
        if (snapshot.Errors.Count > 0) throw new InvalidDataException("Signature repository changed during activation; scoring is disabled.");
        scanner.Reevaluate(snapshot.Rules, transaction); store?.Audit($"SIGNATURE_ACTIVATED | Rules={snapshot.Rules.Count}"); return snapshot;
    }
}
