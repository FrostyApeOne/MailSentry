using MailSentry;
using Microsoft.AspNetCore.Http;
using System.Net;
using System.Text;
using Xunit;

public class AdminAccessTests
{
    private const string Password = "synthetic-password-for-tests";

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("too-short")]
    [InlineData("                ")]
    public void WebRequiresPasswordEvenOnLocalhost(string? password) =>
        Assert.Throws<InvalidDataException>(() => new AdminAccess(password, null));

    [Theory]
    [InlineData("127.0.0.1", false, false, null, 401)]
    [InlineData("::1", false, false, null, 401)]
    [InlineData("127.0.0.1", false, true, null, 200)]
    [InlineData("192.0.2.1", false, true, null, 403)]
    [InlineData("192.0.2.1", true, true, null, 200)]
    [InlineData("192.0.2.1", true, false, null, 401)]
    [InlineData("127.0.0.1", false, true, "X-Forwarded-Proto", 403)]
    [InlineData("127.0.0.1", false, true, "Forwarded", 403)]
    [InlineData("127.0.0.1", false, true, "X-Forwarded-For", 403)]
    [InlineData("127.0.0.1", true, false, "X-Forwarded-Proto", 401)]
    public void AdminTransportAndCredentialsAreBothRequired(string address, bool https, bool authenticated, string? forwarded, int expected)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(address);
        context.Request.Host = new HostString("localhost");
        context.Request.Scheme = https ? "https" : "http";
        if (authenticated) context.Request.Headers.Authorization = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("admin:" + Password));
        if (forwarded != null) context.Request.Headers[forwarded] = "https";
        var access = new AdminAccess(Password, null);
        Assert.Equal(expected, access.RejectionStatus(context) ?? 200);
        context.Request.Host = new HostString("untrusted.invalid");
        Assert.Equal(400, access.RejectionStatus(context));
    }
}
