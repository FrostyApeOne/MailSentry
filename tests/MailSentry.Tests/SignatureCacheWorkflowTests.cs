using MailSentry;
using Xunit;

public class SignatureCacheWorkflowTests
{
    [Fact]
    public async Task LiveScanRechecksBytesRatherThanUsingTheDashboardSnapshot()
    {
        using var f = new MultiAccountFixture(); await f.Add("a.tenant");
        f.Options.DryRun = false;
        Assert.Equal(1, f.Signatures.GetSummary().Count);
        var path = Path.Combine(f.SignaturePath, "shared.json");
        var timestamp = File.GetLastWriteTimeUtc(path); var length = new FileInfo(path).Length;
        File.WriteAllText(path, File.ReadAllText(path).Replace("synthetic spam", "synthetic xxxx"));
        File.SetLastWriteTimeUtc(path, timestamp); Assert.Equal(length, new FileInfo(path).Length);
        f.Requests.Clear();
        var scanner = new Scanner(f.Authentication, f.Options, f.Signatures, f.Store, f.Accounts);
        Assert.True(await scanner.ScanAsync()); Assert.Equal(0, scanner.LastScan!.Spam);
        Assert.Equal(2, scanner.Unmatched.Count);
        Assert.DoesNotContain(f.Requests, request => request.Method != "GET");
    }

    [Fact]
    public void ActivationRejectsPreservedTimestampEditsAndUsesNoStalePreview()
    {
        using var f = new MultiAccountFixture();
        var scanner = new Scanner(f.Authentication, f.Options, f.Signatures, f.Store, f.Accounts);
        var installer = new SignatureInstaller(f.Signatures, scanner, f.Options, f.Store);
        var preview = installer.PreviewPasted("""
            {"version":1,"signatures":[{"id":"added","name":"Added","score":7,"when":{"field":"subject","operator":"equals","value":"uncertain"}}]}
            """);
        var path = Path.Combine(f.SignaturePath, "shared.json");
        var timestamp = File.GetLastWriteTimeUtc(path); var length = new FileInfo(path).Length;
        File.WriteAllText(path, File.ReadAllText(path).Replace("synthetic spam", "synthetic xxxx"));
        File.SetLastWriteTimeUtc(path, timestamp); Assert.Equal(length, new FileInfo(path).Length);
        Assert.Throws<InvalidDataException>(() => installer.Activate(preview.Token));
        Assert.False(File.Exists(Path.Combine(f.SignaturePath, preview.FileName)));
    }

    [Fact]
    public void InstallationAndDeletionImmediatelyUpdateCachedSummaries()
    {
        using var f = new MultiAccountFixture();
        var scanner = new Scanner(f.Authentication, f.Options, f.Signatures, f.Store, f.Accounts);
        var installer = new SignatureInstaller(f.Signatures, scanner, f.Options, f.Store);
        var first = f.Signatures.GetSummary();
        var preview = installer.PreviewPasted("""
            {"version":1,"signatures":[{"id":"added","name":"Added","score":7,"when":{"field":"subject","operator":"equals","value":"uncertain"}}]}
            """);
        installer.Activate(preview.Token);
        var installed = f.Signatures.GetSummary();
        Assert.Equal(2, installed.Count); Assert.NotEqual(first.Revision, installed.Revision);
        var saved = installer.Read(preview.FileName);
        installer.Delete(new(saved.FileName, saved.Fingerprint, true));
        var deleted = f.Signatures.GetSummary();
        Assert.Equal(1, deleted.Count); Assert.Equal(first.Revision, deleted.Revision);
        Assert.DoesNotContain(saved.FileName, deleted.Files);
    }

    [Fact]
    public async Task InvalidRepositoryAfterDashboardWarmupPreventsLiveMailboxActions()
    {
        using var f = new MultiAccountFixture(); await f.Add("a.tenant");
        f.Options.DryRun = false; f.Signatures.GetSummary();
        File.WriteAllText(Path.Combine(f.SignaturePath, "broken.json"), "{");
        f.Requests.Clear();
        var scanner = new Scanner(f.Authentication, f.Options, f.Signatures, f.Store, f.Accounts);
        Assert.False(await scanner.ScanAsync()); Assert.Empty(f.Requests);
        Assert.Equal(0, f.Signatures.GetSummary().Count); Assert.NotEmpty(f.Signatures.GetSummary().Errors);
    }
}
