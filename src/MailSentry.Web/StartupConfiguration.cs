namespace MailSentry;

public static class StartupConfiguration
{
    public static void Load(ConfigurationManager configuration, string file, string environmentName, bool explicitFile, string[] args)
    {
        configuration.Sources.Clear();
        configuration.AddJsonFile(file, optional: false, reloadOnChange: false);
        // Explicit files isolate test/custom hosts from the installation's other settings.
        if (!explicitFile)
            configuration.AddJsonFile(Path.Combine(Path.GetDirectoryName(file)!, $"appsettings.{environmentName}.json"), optional: true, reloadOnChange: false);
        // Retain legacy host-prefixed and ordinary ASP.NET Core environment settings.
        // MailSentry-specific overrides and command-line settings take precedence.
        configuration.AddEnvironmentVariables("ASPNETCORE_")
            .AddEnvironmentVariables("DOTNET_")
            .AddEnvironmentVariables()
            .AddEnvironmentVariables("MAILSENTRY_")
            .AddCommandLine(args);
    }
}

public enum StartupPhase { Configuration, Storage, Listener }

public static class StartupDiagnostics
{
    public static string Describe(StartupPhase phase, Exception error) => phase switch
    {
        StartupPhase.Listener => "MailSentry could not start its HTTP/HTTPS listeners. Check the HTTPS certificate path, password, private-key permissions and configured endpoints. HTTPS requires an available server certificate; forwarding headers do not provide one.",
        StartupPhase.Storage when error is System.Security.Cryptography.CryptographicException =>
            "MailSentry could not decrypt its account storage. Run with the same Windows account, computer and loaded user profile that created the data. Preserve the existing encrypted data and token cache.",
        StartupPhase.Storage => "MailSentry could not open its account storage. Check MailSentry:DataDirectory, directory permissions and the existing account files.",
        _ => "MailSentry could not load configuration. Check appsettings.json and any environment-specific settings for valid JSON, file access and correctly named environment variables. No configuration values have been logged."
    };
}
