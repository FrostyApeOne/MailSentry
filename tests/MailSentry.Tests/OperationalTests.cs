using MailSentry;
using Xunit;
public class OperationalTests
{
    [Fact]
    public void CrossProcessLeaseAndEncryptedState()
    {
        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")); var store = new OperationalStore(dir);
        try
        {
            using (var first = store.TryAcquire()) { Assert.NotNull(first); Assert.Null(new OperationalStore(dir).TryAcquire()); }
            using (var second = store.TryAcquire()) Assert.NotNull(second);
            var message = new MailMessage("synthetic-id", "Synthetic", "synthetic@example.invalid", "synthetic subject", "synthetic body");
            store.Save(new(null, "sy****@example.invalid", [new(message, new(Classification.Review, 0, []))], null));
            Assert.Equal("synthetic subject", store.Load()!.Unmatched[0].Message.Subject);
            Assert.DoesNotContain("synthetic subject", System.Text.Encoding.UTF8.GetString(File.ReadAllBytes(Path.Combine(dir, "scan-state.bin"))));
            store.Audit("START"); store.Audit("END"); Assert.Single(Directory.GetFiles(dir, "audit-*.log"));
        }
        finally { Directory.Delete(dir, true); }
    }
    [Theory]
    [InlineData(0, 500, "Quarantine")]
    [InlineData(6, 500, "Quarantine")]
    [InlineData(7, 0, "Quarantine")]
    [InlineData(7, 500, "Inbox")]
    public void UnsafeConfigurationRejected(int threshold, int maximum, string folder) => Assert.Throws<InvalidDataException>(() => ConfigurationValidation.Validate(new() { SpamThreshold = threshold, MaximumMessages = maximum, QuarantineFolderName = folder }, "11111111-1111-1111-1111-111111111111"));
    [Fact] public void NewInstallDefaultsAreSafe() { var options = new MailSentryOptions(); Assert.True(options.DryRun); ConfigurationValidation.Validate(options, "11111111-1111-1111-1111-111111111111"); }
}
