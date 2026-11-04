using MailSentry;
using Xunit;

public class AuthenticationCodecTests
{
    [Theory]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("{}")]
    [InlineData("{\"homeAccountId\":\"a\",\"homeAccountId\":\"b\"}")]
    public void MalformedRecordsAreRejectedBeforeCredentialCreation(string json) =>
        Assert.ThrowsAny<Exception>(() => AuthenticationRecordCodec.Parse(System.Text.Encoding.UTF8.GetBytes(json)));

    [Fact]
    public void UnsupportedRecordVersionIsRejectedSafely()
    {
        var record = System.Text.Encoding.UTF8.GetString(AccountStorageTests.Record("a.tenant")).Replace("1.0", "9.0");
        Assert.Throws<InvalidDataException>(() => AuthenticationRecordCodec.Parse(System.Text.Encoding.UTF8.GetBytes(record)));
    }
}
