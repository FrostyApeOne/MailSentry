using MailSentry;
using System.Text.Json;
using Xunit;

public class PastedSignatureTests
{
    private static string Pack(string id) => JsonSerializer.Serialize(new SignaturePack(1,
        [new(id, "Synthetic campaign", 7, new() { Field = "subject", Operator = "equals", Value = "synthetic spam" })]), SignatureFormat.Json);

    [Fact]
    public void PastedJsonGeneratesUniqueNamesAndOnlySavesAfterConfirmation()
    {
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var repository = new SignatureRepository(directory);
            var options = new MailSentryOptions();
            var scanner = TestScanner.Create(directory, options, repository);
            var installer = new SignatureInstaller(repository, scanner, options);
            var json = Pack("pasted-example");
            var first = installer.PreviewPasted(json);
            var second = installer.PreviewPasted(json);
            Assert.StartsWith("pasted-", first.FileName);
            Assert.EndsWith(".json", first.FileName);
            Assert.Equal(first.FileName, Path.GetFileName(first.FileName));
            Assert.NotEqual(first.FileName, second.FileName);
            Assert.Empty(Directory.GetFiles(directory));
            installer.Cancel(second.Token);
            Assert.Throws<InvalidDataException>(() => installer.Activate(second.Token));
            installer.Activate(first.Token);
            Assert.Equal(json, File.ReadAllText(Path.Combine(directory, first.FileName)));
            Assert.Single(repository.Load().Rules);
            Assert.Throws<InvalidDataException>(() => installer.PreviewPasted(json));
            Assert.Single(Directory.GetFiles(directory));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    [InlineData("{")]
    [InlineData("{\"version\":1,\"signatures\":[]}")]
    public void InvalidPastedJsonCannotCreateFiles(string json)
    {
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var repository = new SignatureRepository(directory);
            var options = new MailSentryOptions();
            var scanner = TestScanner.Create(directory, options, repository);
            var installer = new SignatureInstaller(repository, scanner, options);
            Assert.ThrowsAny<Exception>(() => installer.PreviewPasted(json));
            Assert.Empty(Directory.GetFiles(directory));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void PastedJsonLimitMeasuresUtf8Bytes()
    {
        var options = new MailSentryOptions();
        var repository = new SignatureRepository(Path.GetTempPath());
        var scanner = TestScanner.Create(Path.GetTempPath(), options, repository);
        var installer = new SignatureInstaller(repository, scanner, options);
        var error = Assert.Throws<InvalidDataException>(() => installer.PreviewPasted(new string('\u00e9', 524289)));
        Assert.Contains("1 MB", error.Message);
    }
}
