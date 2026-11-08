using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Graph.Models;

namespace MailSentry;

public static class MicrosoftAuthenticationResults
{
    private static readonly TimeSpan Timeout = TimeSpan.FromMilliseconds(50);
    private static MatchCollection Find(string text, string pattern) =>
        Regex.Matches(text, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, Timeout);

    public static MailAuthenticationResults Read(IReadOnlyList<InternetMessageHeader>? headers, string senderDomain)
    {
        if (headers is null || headers.Count == 0) return MailAuthenticationResults.Unknown;
        if (headers.Count > 1000 || headers.Any(h => h is null)) return new(Source: "unusable");
        try { return ReadCore(headers, senderDomain); }
        catch (RegexMatchTimeoutException) { return new(Source: "unusable"); }
    }

    private static MailAuthenticationResults ReadCore(IReadOnlyList<InternetMessageHeader> headers, string senderDomain)
    {
        // Graph must preserve transport header order. Only accept a single result
        // ABOVE Microsoft's first recognised ingress Received header. Anything
        // below that boundary can have been supplied by the external sender,
        // even if it claims a Microsoft authserv-id or a Microsoft EHLO name.
        // Unrecognised transport layouts intentionally contribute no evidence.
        var boundary = -1;
        for (var i = 0; i < headers.Count; i++)
        {
            if (!string.Equals(headers[i].Name, "Received", StringComparison.OrdinalIgnoreCase)) continue;
            var trace = StructuralText(headers[i].Value);
            if (trace is null) return new(Source: "unusable");
            var receivers = Find(trace, @"\bby\s+([a-z0-9.-]+)(?=\s|;|$)");
            if (receivers.Count != 1) return new(Source: "untrusted");
            var receiver = receivers[0].Groups[1].Value.TrimEnd('.');
            if (!MicrosoftHost(receiver)) return new(Source: "untrusted");
            if (receiver.EndsWith(".mail.protection.outlook.com", StringComparison.OrdinalIgnoreCase) ||
                receiver.EndsWith(".olc.protection.outlook.com", StringComparison.OrdinalIgnoreCase) ||
                trace.Contains("via Frontend Transport", StringComparison.OrdinalIgnoreCase))
            { boundary = i; break; }
        }
        var results = headers.Select((h, index) => (h, index)).Where(x =>
            string.Equals(x.h.Name, "Authentication-Results", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (results.Length == 0) return MailAuthenticationResults.Unknown;
        var local = results.Where(x => boundary >= 0 && x.index < boundary).ToArray();
        if (local.Length != 1) return new(Source: "untrusted");
        var text = StructuralText(local[0].h.Value);
        if (text is null) return new(Source: "unusable");
        var segments = text.Split(';');
        var first = segments[0].Trim();
        // Microsoft commonly omits authserv-id. When present, require an exact
        // known ID, not an attacker-controlled suffix such as outlook.com.evil.
        if (!first.Contains('=') && !Regex.IsMatch(first, @"^(mx\.microsoft\.com|outlook\.com|hotmail\.com)(\s+1)?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, Timeout))
            return new(Source: "untrusted");
        var methods = new Dictionary<string, List<(string Result, string Properties)>>(StringComparer.OrdinalIgnoreCase);
        foreach (var segment in segments)
        {
            var matches = Find(segment, @"^\s*(spf|dkim|dmarc)(?:/1)?\s*=\s*([a-z]+)(?=\s|$)(.*)$");
            if (matches.Count == 0) continue;
            var match = matches[0]; var method = match.Groups[1].Value.ToLowerInvariant();
            if (!methods.TryGetValue(method, out var entries)) methods[method] = entries = [];
            entries.Add((match.Groups[2].Value.ToLowerInvariant(), match.Groups[3].Value));
        }
        string Single(string method, params string[] allowed) => methods.TryGetValue(method, out var entries) &&
            entries.Count == 1 && allowed.Contains(entries[0].Result) ? entries[0].Result : "unknown";
        var spf = Single("spf", "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror");
        var dkim = Single("dkim", "pass", "fail", "neutral", "none", "temperror", "permerror", "policy");
        // Multiple DKIM signatures are legitimate. Never let a failing signature
        // outweigh a passing one; otherwise ambiguous combinations remain unknown.
        if (methods.TryGetValue("dkim", out var signatures) && signatures.Count > 1)
            dkim = signatures.Any(x => x.Result == "pass") ? "pass" :
                signatures.All(x => x.Result == "fail") ? "fail" : "unknown";
        var dmarc = Single("dmarc", "pass", "fail", "none", "temperror", "permerror", "bestguesspass");
        if (methods.TryGetValue("dmarc", out var assessments) && assessments.Count == 1)
        {
            var domains = Find(assessments[0].Properties, @"(?<![\w.])header\.from\s*=\s*([a-z0-9][a-z0-9.-]*)(?=\s|$)");
            if (domains.Count != 1 || string.IsNullOrEmpty(senderDomain) ||
                !string.Equals(domains[0].Groups[1].Value.TrimEnd('.'), senderDomain.TrimEnd('.'), StringComparison.OrdinalIgnoreCase))
                dmarc = "unknown";
        }
        return new(spf, dkim, dmarc, "microsoft");
    }

    private static bool MicrosoftHost(string host) => host.Equals("outlook.com", StringComparison.OrdinalIgnoreCase) ||
        host.EndsWith(".outlook.com", StringComparison.OrdinalIgnoreCase) || host.Equals("hotmail.com", StringComparison.OrdinalIgnoreCase) ||
        host.EndsWith(".hotmail.com", StringComparison.OrdinalIgnoreCase);

    // Ignore quoted diagnostics and nested comments so e.g. reason="spf=fail"
    // cannot be mistaken for an assessment. Reject malformed folding/comments.
    private static string? StructuralText(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 16384) return null;
        var text = new StringBuilder(value.Length);
        var depth = 0; var quoted = false; var escaped = false;
        for (var i = 0; i < value.Length; i++)
        {
            var c = value[i];
            if (c == '\r')
            {
                if (i + 2 >= value.Length || value[i + 1] != '\n' || value[i + 2] is not (' ' or '\t')) return null;
                i++; text.Append(' '); continue;
            }
            if (c == '\n' || (char.IsControl(c) && c != '\t')) return null;
            if (escaped) { escaped = false; continue; }
            if ((quoted || depth > 0) && c == '\\') { escaped = true; continue; }
            if (depth == 0 && c == '"') { quoted = !quoted; text.Append(' '); continue; }
            if (quoted) continue;
            if (c == '(') { if (++depth > 10) return null; text.Append(' '); continue; }
            if (c == ')') { if (--depth < 0) return null; text.Append(' '); continue; }
            if (depth == 0) text.Append(c);
        }
        return depth == 0 && !quoted && !escaped ? text.ToString() : null;
    }
}
