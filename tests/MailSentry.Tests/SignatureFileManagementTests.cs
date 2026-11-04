using MailSentry;
using Xunit;

public class SignatureFileManagementTests
{
    private static SignatureInstaller Installer(MultiAccountFixture f) => new(f.Signatures,
        new Scanner(f.Authentication, f.Options, f.Signatures, f.Store, f.Accounts), f.Options, f.Store);

    [Fact]
    public void ViewDoesNotChangeFilesAndDeletionRequiresConfirmationAndCurrentContents()
    {
        using var f = new MultiAccountFixture();
        var installer = Installer(f);
        var fileName = Assert.Single(installer.FileNames());
        var path = Path.Combine(f.SignaturePath, fileName);
        var original = File.ReadAllText(path);
        var saved = installer.Read(fileName);
        Assert.Equal(original, saved.Json);
        Assert.Equal(fileName, saved.FileName);
        Assert.Throws<InvalidDataException>(() => installer.Delete(new(fileName, saved.Fingerprint, false)));
        Assert.Equal(original, File.ReadAllText(path));
        File.AppendAllText(path, "\n");
        Assert.Throws<InvalidDataException>(() => installer.Delete(new(fileName, saved.Fingerprint, true)));
        Assert.True(File.Exists(path));
        var current = installer.Read(fileName);
        Assert.Empty(installer.Delete(new(fileName, current.Fingerprint, true)).Rules);
        Assert.False(File.Exists(path));
        Assert.Empty(installer.FileNames());
        Assert.Contains("SIGNATURE_DELETED", File.ReadAllText(Assert.Single(Directory.GetFiles(f.DirectoryPath, "audit-*.log"))));
    }

    [Fact]
    public void InvalidPacksCanBeInspectedAndRemovedWithoutTouchingOtherFiles()
    {
        using var f = new MultiAccountFixture();
        var installer = Installer(f);
        File.WriteAllText(Path.Combine(f.SignaturePath, "broken.json"), "{ invalid JSON");
        var original = Assert.Single(f.Signatures.Load().Files);
        Assert.Contains("broken.json", installer.FileNames());
        var saved = installer.Read("broken.json");
        Assert.Equal("{ invalid JSON", saved.Json);
        Assert.Empty(installer.Delete(new(saved.FileName, saved.Fingerprint, true)).Errors);
        Assert.Equal(original, Assert.Single(installer.FileNames()));
    }

    [Theory]
    [InlineData("../appsettings.json")]
    [InlineData("..\\appsettings.json")]
    [InlineData("C:\\private.json")]
    [InlineData("file.json:secret.json")]
    [InlineData("scan.lock")]
    [InlineData("")]
    [InlineData("missing.json")]
    public void OnlyExistingRepositoryJsonFilesCanBeViewedOrDeleted(string name)
    {
        using var f = new MultiAccountFixture();
        var installer = Installer(f);
        Assert.Throws<InvalidDataException>(() => installer.Read(name));
        Assert.Throws<InvalidDataException>(() => installer.Delete(new(name, "invalid", true)));
        Assert.Single(installer.FileNames());
    }

    [Fact]
    public void DeletionCannotRunDuringAScanAndInvalidatesPendingActivation()
    {
        using var f = new MultiAccountFixture();
        var installer = Installer(f);
        var pending = installer.PreviewPasted("""
            {"version":1,"signatures":[{"id":"pending","name":"Pending","score":7,"when":{"field":"subject","operator":"equals","value":"synthetic"}}]}
            """);
        var saved = installer.Read(Assert.Single(installer.FileNames()));
        using (var scanLock = f.Accounts.Begin())
            Assert.Throws<InvalidDataException>(() => installer.Delete(new(saved.FileName, saved.Fingerprint, true)));
        Assert.Single(installer.FileNames());
        installer.Delete(new(saved.FileName, saved.Fingerprint, true));
        Assert.Throws<InvalidDataException>(() => installer.Activate(pending.Token));
        Assert.Empty(installer.FileNames());
    }
}
