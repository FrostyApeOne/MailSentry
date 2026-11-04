using MailSentry;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using Xunit;

public class StartupConfigurationTests
{
    [Fact]
    public void EnvironmentSettingsAreRestoredButExplicitFilesRemainIsolated()
    {
        using var f = new MultiAccountFixture();
        var file = Path.Combine(f.DirectoryPath, "appsettings.json");
        const string key = "MailSentrySyntheticConfigurationProbe";
        File.WriteAllText(file, "{\"" + key + "\":\"base\"}");
        File.WriteAllText(Path.Combine(f.DirectoryPath, "appsettings.Production.json"), "{\"" + key + "\":\"production\"}");
        using var configuration = new ConfigurationManager();
        StartupConfiguration.Load(configuration, file, "Production", false, []);
        Assert.Equal("production", configuration[key]);
        StartupConfiguration.Load(configuration, file, "Production", true, []);
        Assert.Equal("base", configuration[key]);
        StartupConfiguration.Load(configuration, file, "Production", false, ["--" + key, "command-line"]);
        Assert.Equal("command-line", configuration[key]);
    }

    [Theory]
    [InlineData(StartupPhase.Configuration, "configuration")]
    [InlineData(StartupPhase.Storage, "storage")]
    [InlineData(StartupPhase.Listener, "certificate")]
    public void StartupDiagnosticsIdentifyThePhaseWithoutLeakingExceptionDetails(StartupPhase phase, string expected)
    {
        const string secret = "synthetic-secret-never-log";
        var message = StartupDiagnostics.Describe(phase, new IOException(secret));
        Assert.Contains(expected, message);
        Assert.DoesNotContain(secret, message);
        message = StartupDiagnostics.Describe(phase, new CryptographicException(secret));
        Assert.Contains(phase == StartupPhase.Storage ? "Windows account" : expected, message);
        Assert.DoesNotContain(secret, message);
    }
}
