using System.Text.Json;
using MailSentry;
using Xunit;

public class SignatureRepositoryCacheTests : IDisposable
{
    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 11, 8, 9, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(int seconds) => _now = _now.AddSeconds(seconds);
    }
    private readonly string _directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
    private readonly Clock _clock = new();
    private readonly SignatureRepository _repository;
    public SignatureRepositoryCacheTests()
    {
        Directory.CreateDirectory(_directory); _repository = new(_directory, _clock);
    }
    public void Dispose() { Directory.Delete(_directory, true); }
    private string PathFor(string name = "one.json") => Path.Combine(_directory, name);
    private void Write(string id = "one", string value = "alpha", string name = "one.json") =>
        File.WriteAllText(PathFor(name), JsonSerializer.Serialize(new SignaturePack(1,
            [new(id, id, 7, new() { Field = "subject", Operator = "contains", Value = value })]), SignatureFormat.Json));

    [Fact]
    public void WarmDashboardReadsDoNotReadOrReparseFiles()
    {
        Write(); var first = _repository.GetSummary(); var before = _repository.Statistics;
        for (var i = 0; i < 100; i++) Assert.Same(first, _repository.GetSummary());
        Assert.Equal(before, _repository.Statistics);
        _clock.Advance(2); Assert.Same(first, _repository.GetSummary());
        Assert.Equal(before, _repository.Statistics); // Metadata checks do not read contents.
        Assert.Equal(1, first.Count); Assert.Equal("one.json", Assert.Single(first.Files));
        Assert.DoesNotContain("alpha", JsonSerializer.Serialize(first));
    }

    [Fact]
    public void AuthoritativeLoadVerifiesContentButReusesValidatedSnapshot()
    {
        Write(); var first = _repository.Load(); var before = _repository.Statistics;
        Assert.Same(first, _repository.Load());
        Assert.Equal(before.FileReads + 1, _repository.Statistics.FileReads);
        Assert.Equal(before.Verifications + 1, _repository.Statistics.Verifications);
        Assert.Equal(before.PackParses, _repository.Statistics.PackParses);
    }

    [Fact]
    public void ChangingOneFileReparsesOnlyThatPackAndReusesOtherRules()
    {
        Write(); Write("two", name: "two.json");
        var first = _repository.Load(); var before = _repository.Statistics;
        Write(value: "bravo"); var next = _repository.Load();
        Assert.NotEqual(first.Revision, next.Revision);
        Assert.Equal(before.PackParses + 1, _repository.Statistics.PackParses);
        Assert.Same(first.Rules[1], next.Rules[1]);
        Assert.Equal("alpha", first.Rules[0].When.Value); // Captured scans retain their own rules.
        Assert.Equal("bravo", next.Rules[0].When.Value);
    }

    [Fact]
    public void StrictChecksDetectChangesWithIdenticalSizeAndTimestamp()
    {
        Write(); var first = _repository.Load(); var timestamp = File.GetLastWriteTimeUtc(PathFor());
        var length = new FileInfo(PathFor()).Length;
        Write(value: "bravo"); File.SetLastWriteTimeUtc(PathFor(), timestamp);
        Assert.Equal(length, new FileInfo(PathFor()).Length);
        _clock.Advance(2); Assert.Equal(first.Revision, _repository.GetSummary().Revision);
        var verified = _repository.Load();
        Assert.NotEqual(first.Revision, verified.Revision); Assert.Equal("bravo", verified.Rules[0].When.Value);
    }

    [Fact]
    public void PeriodicContentVerificationFindsPreservedTimestampEdits()
    {
        Write(); var first = _repository.GetSummary(); var timestamp = File.GetLastWriteTimeUtc(PathFor());
        Write(value: "bravo"); File.SetLastWriteTimeUtc(PathFor(), timestamp);
        _clock.Advance(31);
        Assert.NotEqual(first.Revision, _repository.GetSummary().Revision);
        Assert.Equal(2, _repository.Statistics.PackParses);
    }

    [Fact]
    public void MetadataChangesAndExplicitInvalidationRefreshImmediatelyWhenDue()
    {
        Write(); var first = _repository.GetSummary();
        Write(value: "longer changed value"); _clock.Advance(2);
        var second = _repository.GetSummary(); Assert.NotEqual(first.Revision, second.Revision);
        Write(value: "third"); _repository.Invalidate();
        Assert.NotEqual(second.Revision, _repository.GetSummary().Revision);
    }

    [Fact]
    public void InvalidEditsDisableScoringAndUnchangedInvalidContentIsNotReparsed()
    {
        Write(); _repository.Load(); File.WriteAllText(PathFor(), "{");
        var invalid = _repository.Load();
        Assert.Empty(invalid.Rules); Assert.NotEmpty(invalid.Errors);
        Assert.Equal("one.json", Assert.Single(invalid.FileNames));
        var parses = _repository.Statistics.PackParses;
        Assert.Same(invalid, _repository.Load()); Assert.Equal(parses, _repository.Statistics.PackParses);
        Write(); Assert.Single(_repository.Load().Rules); Assert.Empty(_repository.Load().Errors);
    }

    [Fact]
    public void DuplicateIdsAreRecheckedAcrossCachedAndChangedPacks()
    {
        Write(); _repository.Load(); Write(name: "duplicate.json");
        var invalid = _repository.Load(); Assert.Empty(invalid.Rules); Assert.NotEmpty(invalid.Errors);
        File.Delete(PathFor("duplicate.json"));
        var fixedSnapshot = _repository.Load(); Assert.Single(fixedSnapshot.Rules); Assert.Empty(fixedSnapshot.Errors);
        Assert.Equal(2, _repository.Statistics.PackParses); // Original cached pack is still valid.
    }

    [Fact]
    public void AddRenameAndDeleteChangeRevisionAndEvictRemovedPacks()
    {
        Write(); var first = _repository.Load();
        File.Move(PathFor(), PathFor("renamed.json")); var renamed = _repository.Load();
        Assert.NotEqual(first.Revision, renamed.Revision); Assert.Equal("renamed.json", Assert.Single(renamed.Files));
        Write("two", name: "two.json"); Assert.Equal(2, _repository.Load().Rules.Count);
        File.Delete(PathFor("renamed.json")); Assert.Single(_repository.Load().Rules);
        File.Delete(PathFor("two.json")); var empty = _repository.Load();
        Assert.Empty(empty.Rules); Assert.Empty(empty.FileNames); Assert.Empty(empty.Errors);
    }

    [Fact]
    public void MissingDirectoryFailsSafelyAndRecovers()
    {
        Write(); _repository.Load(); File.Delete(PathFor()); Directory.Delete(_directory);
        var missing = _repository.Load(); Assert.Empty(missing.Rules); Assert.NotEmpty(missing.Errors);
        Directory.CreateDirectory(_directory); Write(); Assert.Single(_repository.Load().Rules);
    }

    [Fact]
    public void PartiallyWrittenOrLockedPackCannotFallBackToCachedRules()
    {
        Write(); _repository.Load();
        using (var writing = new FileStream(PathFor(), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var blocked = _repository.Load(); Assert.Empty(blocked.Rules); Assert.NotEmpty(blocked.Errors);
        }
        Assert.Single(_repository.Load().Rules);
    }

    [Fact]
    public void OversizedFilesAreRejectedBeforeReadingTheirContents()
    {
        Write(); _repository.Load(); var reads = _repository.Statistics.FileReads;
        using (var file = new FileStream(PathFor(), FileMode.Open)) file.SetLength(1048577);
        var invalid = _repository.Load(); Assert.Empty(invalid.Rules); Assert.NotEmpty(invalid.Errors);
        Assert.Equal(reads, _repository.Statistics.FileReads);
    }

    [Fact]
    public async Task ConcurrentAuthoritativeChecksEachVerifyBytesButParseOnlyOnce()
    {
        Write();
        var results = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() => _repository.Load())));
        Assert.All(results, result => Assert.Same(results[0], result));
        Assert.Equal(16, _repository.Statistics.Verifications);
        Assert.Equal(16, _repository.Statistics.FileReads);
        Assert.Equal(1, _repository.Statistics.PackParses);
    }

    [Fact]
    public async Task ConcurrentDashboardRequestsShareOneValidatedSnapshot()
    {
        for (var i = 0; i < 25; i++) Write($"rule-{i}", name: $"{i}.json");
        var results = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => Task.Run(() => _repository.GetSummary())));
        Assert.All(results, result => Assert.Same(results[0], result));
        Assert.Equal(1, _repository.Statistics.Verifications);
        Assert.Equal(25, _repository.Statistics.PackParses);
    }

    [Fact]
    public void ConditionsCopyCallerOwnedCollections()
    {
        var values = new List<string> { "alpha" };
        var leaf = new Condition { Field = "subject", Operator = "containsAny", Values = values };
        var children = new List<Condition> { leaf };
        var condition = new Condition { All = children };
        values.Clear(); children.Clear();
        Assert.Equal("alpha", Assert.Single(Assert.Single(condition.All!).Values!));
    }

    [Fact]
    public void PublishedCollectionsAndNestedConditionsCannotBeMutated()
    {
        File.WriteAllText(PathFor(), """
            {"version":1,"signatures":[{"id":"nested","name":"Nested","score":7,"when":{"all":[{"field":"subject","operator":"containsAny","values":["alpha","bravo"]}]}}]}
            """);
        var snapshot = _repository.Load(); var rule = Assert.Single(snapshot.Rules);
        Assert.Throws<NotSupportedException>(() => ((IList<Signature>)snapshot.Rules).Clear());
        Assert.Throws<NotSupportedException>(() => ((IList<Condition>)rule.When.All!).Clear());
        Assert.Throws<NotSupportedException>(() => ((IList<string>)rule.When.All![0].Values!)[0] = "changed");
        Assert.Throws<NotSupportedException>(() => ((IList<string>)snapshot.Files).Clear());
        Assert.Throws<NotSupportedException>(() => ((IList<string>)snapshot.Errors).Add("changed"));
        Assert.Same(snapshot, _repository.Load());
    }
}
