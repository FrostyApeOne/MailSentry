using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace MailSentry;

public sealed record MailMessage(string Id, string SenderName, string SenderAddress, string Subject,
    string BodyPreview, DateTimeOffset? ReceivedDateTime = null, string Importance = "normal")
{
    public string SenderDomain => SenderAddress.LastIndexOf('@') is var at && at > 0 && at < SenderAddress.Length - 1
        ? SenderAddress[(at + 1)..].Trim().ToLowerInvariant() : "";
}
public sealed record SignaturePack(int Version, List<Signature> Signatures);
public sealed record Signature(string Id, string Name, int Score, Condition When);
public sealed class Condition
{
    public string? Field { get; set; }
    public string? Operator { get; set; }
    public string? Value { get; set; }
    public List<string>? Values { get; set; }
    public List<Condition>? All { get; set; }
    public List<Condition>? Any { get; set; }
}
public static class SignatureFormat
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, MaxDepth = 24 };
    public static SignaturePack Parse(string json)
    {
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 24 });
        RejectDuplicateProperties(document.RootElement);
        var pack = JsonSerializer.Deserialize<SignaturePack>(json, Json) ?? throw new InvalidDataException("Empty signature pack.");
        if (pack.Version != 1 || pack.Signatures is not { Count: > 0 and <= 1000 }) throw new InvalidDataException("Unsupported version or rule count.");
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in pack.Signatures)
        {
            if (s is null || string.IsNullOrWhiteSpace(s.Id) || s.Id.Length > 100 || !ids.Add(s.Id) || string.IsNullOrWhiteSpace(s.Name) || s.Name.Length > 200 || s.Score is < 1 or > 100)
                throw new InvalidDataException("Invalid or duplicate signature ID, name, or score.");
            try { Validate(s.When, 0, "when"); }
            catch (InvalidDataException e) { throw new InvalidDataException($"Signature '{s.Id}', {e.Message}", e); }
        }
        return pack;
    }
    private static void RejectDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new InvalidDataException("Duplicate JSON property.");
                RejectDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array) foreach (var child in element.EnumerateArray()) RejectDuplicateProperties(child);
    }
    private static void Validate(Condition? c, int depth, string path)
    {
        if (c is null || depth > 12) throw new InvalidDataException("Invalid condition depth.");
        if (c.All != null || c.Any != null)
        {
            if ((c.All != null && c.Any != null) || c.Field != null || c.Operator != null || c.Value != null || c.Values != null)
                throw new InvalidDataException("Compound conditions cannot mix operators or leaf fields.");
            var children = c.All ?? c.Any!;
            if (children.Count is < 1 or > 100) throw new InvalidDataException("Empty or oversized compound condition.");
            for (var i = 0; i < children.Count; i++)
                Validate(children[i], depth + 1, $"{path}.{(c.All != null ? "all" : "any")}[{i}]");
            return;
        }
        if (c.Field is not ("senderName" or "senderAddress" or "senderDomain" or "subject" or "body" or "content" or "importance")) throw new InvalidDataException("Unsupported field.");
        if (c.Operator is not ("contains" or "containsAny" or "containsAll" or "startsWith" or "endsWith" or "equals" or "regex")) throw new InvalidDataException("Unsupported operator.");
        if (c.Operator is "containsAny" or "containsAll")
        {
            if (c.Value != null || c.Values is not { Count: > 0 and <= 100 } || c.Values.Any(v => string.IsNullOrWhiteSpace(v) || v.Length > 2000)) throw new InvalidDataException($"{path}: operator '{c.Operator}' on field '{c.Field}' requires a nonempty 'values' array (up to 100 nonblank strings, each at most 2000 characters) and no 'value' property.");
        }
        else if (c.Values != null || string.IsNullOrWhiteSpace(c.Value) || c.Value.Length > 2000) throw new InvalidDataException($"{path}: operator '{c.Operator}' on field '{c.Field}' requires a single nonblank 'value' string (at most 2000 characters), not a 'values' array.");
        if (c.Operator == "regex")
        {
            var regex = new Regex(c.Value!, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50));
            try { if (regex.IsMatch("")) throw new InvalidDataException("Regex must not match empty input."); }
            catch (RegexMatchTimeoutException) { throw new InvalidDataException("Regex validation timed out."); }
        }
    }
    public static string Normalize(string? v) => (v ?? "").Normalize(NormalizationForm.FormKC)
        .Replace('\u2010', '-').Replace('\u2011', '-').Replace('\u2012', '-').Replace('\u2013', '-').Replace('\u2014', '-').Replace('\u2212', '-')
        .Replace('\u2018', '\'').Replace('\u2019', '\'').Replace('\u201C', '"').Replace('\u201D', '"').Trim().ToLowerInvariant();
    public static bool Matches(Condition c, MailMessage m)
    {
        if (c.All != null) return c.All.All(x => Matches(x, m));
        if (c.Any != null) return c.Any.Any(x => Matches(x, m));
        var text = Normalize(c.Field switch
        {
            "senderName" => m.SenderName,
            "senderAddress" => m.SenderAddress,
            "senderDomain" => m.SenderDomain,
            "subject" => m.Subject,
            "body" => m.BodyPreview,
            "importance" => m.Importance,
            "content" => $"{m.SenderName} {m.Subject} {m.BodyPreview}",
            _ => ""
        });
        var value = Normalize(c.Value);
        return c.Operator switch
        {
            "contains" => text.Contains(value, StringComparison.Ordinal),
            "containsAny" => c.Values!.Any(v => text.Contains(Normalize(v), StringComparison.Ordinal)),
            "containsAll" => c.Values!.All(v => text.Contains(Normalize(v), StringComparison.Ordinal)),
            "startsWith" => text.StartsWith(value, StringComparison.Ordinal),
            "endsWith" => text.EndsWith(value, StringComparison.Ordinal),
            "equals" => text == value,
            "regex" => Regex.IsMatch(text, c.Value!, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50)),
            _ => false
        };
    }
}
public sealed record SignatureSnapshot(IReadOnlyList<Signature> Rules, IReadOnlyList<string> Files, IReadOnlyList<string> Errors);
public sealed class SignatureRepository(string directory)
{
    public string DirectoryPath { get; } = Path.GetFullPath(directory);
    public SignatureSnapshot Load()
    {
        var rules = new List<Signature>(); var files = new List<string>(); var errors = new List<string>();
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var file in Directory.GetFiles(DirectoryPath, "*.json").Order(StringComparer.Ordinal))
            {
                try
                {
                    if (new FileInfo(file).Length > 1024 * 1024) throw new InvalidDataException();
                    var pack = SignatureFormat.Parse(File.ReadAllText(file));
                    if (pack.Signatures.Any(s => ids.Contains(s.Id))) throw new InvalidDataException("Duplicate signature ID across packs.");
                    foreach (var rule in pack.Signatures) { ids.Add(rule.Id); rules.Add(rule); }
                    files.Add(Path.GetFileName(file));
                }
                catch (Exception e) when (e is JsonException or InvalidDataException or ArgumentException or IOException or UnauthorizedAccessException)
                { errors.Add(e is InvalidDataException ? $"{Path.GetFileName(file)}: {e.Message}" : $"{Path.GetFileName(file)}: invalid signature pack ({e.GetType().Name})."); }
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { errors.Add("Signature directory unavailable."); }
        // A broken or ambiguous repository disables scoring for this snapshot.
        return new(errors.Count == 0 ? rules : [], files, errors);
    }
}
public sealed class SpamClassifier(MailSentryOptions options)
{
    public ClassificationResult Classify(MailMessage m, IReadOnlyList<Signature> rules)
    {
        if (options.AllowedSenders.Any(s => string.Equals(s.Trim(), m.SenderAddress.Trim(), StringComparison.OrdinalIgnoreCase)) ||
            (m.SenderDomain.Length > 0 && options.AllowedDomains.Any(d => string.Equals(d.Trim(), m.SenderDomain, StringComparison.OrdinalIgnoreCase))))
            return new(Classification.Trusted, 0, ["Explicit allow list"]);
        var score = 0; var reasons = new List<string>();
        try
        {
            foreach (var rule in rules) if (SignatureFormat.Matches(rule.When, m)) { score = checked(score + rule.Score); reasons.Add(rule.Name); }
        }
        catch (Exception e) when (e is RegexMatchTimeoutException or OverflowException)
        { return new(Classification.Review, 0, ["Signature evaluation failed safely"]); }
        return new(score >= options.SpamThreshold ? Classification.Spam : Classification.Review, score, reasons);
    }
}
