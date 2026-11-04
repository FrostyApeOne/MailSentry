using MailSentry;
using System.Text.Json;
using Xunit;
public class WorkflowTests
{
    private static string Pack(string id) => JsonSerializer.Serialize(new SignaturePack(1, [new(id, id, 7, new() { Field = "subject", Operator = "contains", Value = "synthetic spam" })]), SignatureFormat.Json);
    [Fact]
    public void PreviewRequiresConfirmationAndRejectsStalePreview()
    {
        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
        try
        {
            var repo = new SignatureRepository(dir); var options = new MailSentryOptions(); var scanner = TestScanner.Create(dir, options, repo); var installer = new SignatureInstaller(repo, scanner, options);
            var preview = installer.Preview("test.json", Pack("one")); Assert.Empty(repo.Load().Rules);
            installer.Cancel(preview.Token); Assert.Throws<InvalidDataException>(() => installer.Activate(preview.Token));
            preview = installer.Preview("test.json", Pack("one")); File.WriteAllText(Path.Combine(dir, "other.json"), Pack("other"));
            Assert.Throws<InvalidDataException>(() => installer.Activate(preview.Token)); Assert.False(File.Exists(Path.Combine(dir, "test.json")));
            preview = installer.Preview("test.json", Pack("one")); Assert.Equal(2, installer.Activate(preview.Token).Rules.Count);
            Assert.Throws<InvalidDataException>(() => installer.Preview("duplicate.json", Pack("one")));
            Assert.Throws<InvalidDataException>(() => installer.Preview("../escape.json", Pack("new")));
        }
        finally { Directory.Delete(dir, true); }
    }
    [Fact]
    public void CopyContainsOnlyClassificationFieldsAndRedactsIncidentalPersonalData()
    {
        var m = new MailMessage("internal-id", "Campaign", "sender@example.invalid", "Hello recipient@example.invalid", "Visit https://example.invalid/?token=secret for recipient@example.invalid");
        var text = MessageExport.Create([new(m, new(Classification.Review, 4, ["Generated sender"]))]);
        Assert.Contains("sender@example.invalid", text); Assert.Contains("Generated sender", text);
        Assert.DoesNotContain("internal-id", text); Assert.DoesNotContain("token=secret", text); Assert.DoesNotContain("recipient@example.invalid", text);
    }
}
