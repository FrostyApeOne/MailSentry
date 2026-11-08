using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace MailSentry;

public sealed record SignatureSnapshot(IReadOnlyList<Signature> Rules, IReadOnlyList<string> Files,
    IReadOnlyList<string> Errors, string Revision = "")
{
    // Includes invalid packs for inspection/removal; Files contains accepted packs.
    public IReadOnlyList<string> FileNames { get; init; } = Files;
}
public sealed record SignatureSummary(int Count, IReadOnlyList<string> Files, IReadOnlyList<string> Errors, string Revision);
public sealed record SignatureRepositoryStatistics(long Verifications, long FileReads, long PackParses);

public sealed class SignatureRepository(string directory, TimeProvider? timeProvider = null)
{
    private sealed record FileStamp(string Name, long Length, long LastWriteTicks, FileAttributes Attributes);
    private sealed record CapturedFile(FileStamp Stamp, byte[] Bytes, string Hash);
    private sealed record CachedPack(string Hash, IReadOnlyList<Signature> Rules, string? Error);
    private readonly object _gate = new();
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private Dictionary<string, CachedPack> _packs = new(StringComparer.Ordinal);
    private FileStamp[] _manifest = [];
    private SignatureSnapshot? _snapshot;
    private SignatureSummary? _summary;
    private bool _invalidated = true;
    private DateTimeOffset _nextMetadataCheck, _nextContentCheck;
    private long _verifications, _fileReads, _packParses;
    public string DirectoryPath { get; } = Path.GetFullPath(directory);
    public SignatureRepositoryStatistics Statistics
    {
        get { lock (_gate) return new(_verifications, _fileReads, _packParses); }
    }

    // Authoritative operations always capture fresh bytes, including after
    // waiting for another refresh. Only presentation requests share a check.
    public SignatureSnapshot Load()
    {
        lock (_gate) return Verify();
    }

    // Presentation only. Metadata is checked at most once per second, with full
    // content verification every 30 seconds even if timestamps were preserved.
    public SignatureSummary GetSummary()
    {
        lock (_gate)
        {
            var now = _time.GetUtcNow();
            if (_summary is null || _invalidated || now >= _nextContentCheck) Verify();
            else if (now >= _nextMetadataCheck)
            {
                try { if (!_manifest.SequenceEqual(ReadManifest())) Verify(); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException) { Verify(); }
                _nextMetadataCheck = now.AddSeconds(1);
            }
            return _summary!;
        }
    }

    public void Invalidate()
    {
        lock (_gate) _invalidated = true;
    }

    private FileStamp[] ReadManifest()
    {
        return new DirectoryInfo(DirectoryPath).GetFiles("*.json").OrderBy(f => f.Name, StringComparer.Ordinal)
            .Select(f => new FileStamp(f.Name, f.Length, f.LastWriteTimeUtc.Ticks, f.Attributes)).ToArray();
    }

    private SignatureSnapshot Verify()
    {
        var result = VerifyCore();
        _invalidated = false;
        _verifications++;
        return result;
    }

    private SignatureSnapshot VerifyCore()
    {
        var captures = new List<CapturedFile>(); var errors = new List<string>();
        var streams = new List<FileStream>(); FileStamp[] manifest = [];
        using var revision = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        try
        {
            manifest = ReadManifest();
            foreach (var file in manifest)
            {
                Append(revision, file.Name);
                try
                {
                    // Hold read-only handles until capture completes: Windows editors
                    // cannot overwrite/delete an already captured pack mid-refresh.
                    var stream = new FileStream(Path.Combine(DirectoryPath, file.Name), FileMode.Open, FileAccess.Read, FileShare.Read);
                    streams.Add(stream);
                    if (stream.Length > 1048576) throw new InvalidDataException("Signature file exceeds 1 MB.");
                    var bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes);
                    if (stream.ReadByte() != -1) throw new InvalidDataException("Signature file changed during loading.");
                    _fileReads++;
                    var hash = Convert.ToHexString(SHA256.HashData(bytes));
                    Append(revision, hash); captures.Add(new(file, bytes, hash));
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException)
                {
                    var error = FileError(file.Name, e); errors.Add(error); Append(revision, error);
                }
            }
            if (!manifest.SequenceEqual(ReadManifest()))
                errors.Add("Signature repository changed during loading. Scoring is disabled; retry after editing finishes.");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException)
        { errors.Add("Signature directory unavailable."); }
        finally { foreach (var stream in streams) stream.Dispose(); }
        foreach (var error in errors) Append(revision, error);
        var contentRevision = Convert.ToHexString(revision.GetHashAndReset());
        _manifest = manifest;
        var now = _time.GetUtcNow(); _nextMetadataCheck = now.AddSeconds(1); _nextContentCheck = now.AddSeconds(30);
        if (_snapshot?.Revision == contentRevision) return _snapshot;

        var next = new Dictionary<string, CachedPack>(StringComparer.Ordinal);
        var rules = new List<Signature>(); var files = new List<string>();
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var capture in captures)
        {
            var name = capture.Stamp.Name;
            if (!_packs.TryGetValue(name, out var pack) || pack.Hash != capture.Hash)
            {
                try
                {
                    _packParses++;
                    using var reader = new StreamReader(new MemoryStream(capture.Bytes), Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                    var parsed = SignatureFormat.Parse(reader.ReadToEnd());
                    pack = new(capture.Hash, Array.AsReadOnly(parsed.Signatures.ToArray()), null);
                }
                catch (Exception e) when (e is JsonException or InvalidDataException or ArgumentException)
                { pack = new(capture.Hash, Array.AsReadOnly(Array.Empty<Signature>()), FileError(name, e)); }
            }
            next.Add(name, pack);
            if (pack.Error != null) { errors.Add(pack.Error); continue; }
            if (pack.Rules.Any(s => ids.Contains(s.Id)))
            { errors.Add($"{name}: Duplicate signature ID across packs."); continue; }
            foreach (var rule in pack.Rules) { ids.Add(rule.Id); rules.Add(rule); }
            files.Add(name);
        }
        _packs = next;
        // An invalid repository NEVER serves last-known-good rules for scoring.
        _snapshot = new(Array.AsReadOnly(errors.Count == 0 ? rules.ToArray() : []),
            Array.AsReadOnly(files.ToArray()), Array.AsReadOnly(errors.ToArray()), contentRevision)
        { FileNames = Array.AsReadOnly(manifest.Where(f => (f.Attributes & FileAttributes.ReparsePoint) == 0).Select(f => f.Name).ToArray()) };
        _summary = new(_snapshot.Rules.Count, _snapshot.FileNames, _snapshot.Errors, _snapshot.Revision);
        return _snapshot;
    }

    private static string FileError(string name, Exception e) => e is InvalidDataException
        ? $"{name}: {e.Message}" : $"{name}: invalid signature pack ({e.GetType().Name}).";

    private static void Append(IncrementalHash hash, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[4]; BinaryPrimitives.WriteInt32LittleEndian(length, bytes.Length);
        hash.AppendData(length); hash.AppendData(bytes);
    }
}
