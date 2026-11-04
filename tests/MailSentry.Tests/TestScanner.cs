using MailSentry;
public static class TestScanner
{
    public static Scanner Create(string directory, MailSentryOptions options, SignatureRepository signatures, OperationalStore? storage = null)
    {
        var store = storage ?? new OperationalStore(Path.Combine(directory, "test-data"));
        var accounts = new AccountRepository(store);
        var migration = new LegacyAccountMigration(MultiAccountFixture.ClientId, accounts, store, Path.Combine(directory, "missing.json"));
        var auth = new GraphAuthentication(MultiAccountFixture.ClientId, accounts, store, options, migration);
        return new Scanner(auth, options, signatures, store, accounts);
    }
}
