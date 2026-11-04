using System.Text.RegularExpressions;

namespace MailSentry;

public static class MessageExport
{
    private static string Clean(string value) => Regex.Replace(Regex.Replace(value, @"https?://\S+", "[link removed]", RegexOptions.IgnoreCase), @"[\w.+-]+@[\w.-]+\.[\p{L}]{2,}", "[email removed]");
    public static string Create(IEnumerable<ReviewMessage> messages) => "MailSentry unmatched messages\nGenerated: " + DateTimeOffset.UtcNow.ToString("O") + "\n\n" +
        string.Join("\n\n", messages.Select((x, i) => $"--- MESSAGE {i + 1} ---\n\n{(x.AccountId != null ? $"Mailbox:\n{x.Mailbox ?? "Microsoft mailbox"}\n\n" : "")}Sender name:\n{Clean(x.Message.SenderName)}\n\nSender:\n{x.Message.SenderAddress}\n\nSubject:\n{Clean(x.Message.Subject)}\n\nBody preview:\n{Clean(x.Message.BodyPreview[..Math.Min(1000, x.Message.BodyPreview.Length)])}\n\nExisting score:\n{x.Result.Score}\n\nMatched signatures:\n{string.Join("\n", x.Result.Reasons.Select(r => "- " + r))}"));
}
