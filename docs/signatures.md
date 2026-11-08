# Signature pack format (version 1)

```json
{
  "version": 1,
  "signatures": [
    {
      "id": "example-generated-prize",
      "name": "Generated sender with specific prize claim",
      "score": 7,
      "when": {
        "all": [
          { "field": "senderDomain", "operator": "startsWith", "value": "--" },
          { "field": "subject", "operator": "containsAll", "values": ["claim your prize", "expires today"] }
        ]
      }
    }
  ]
}
```

IDs must be unique across all packs (case-insensitive). Rules contribute positive integer scores, 1–100, once per matching message. Scores accumulate; reaching the configured threshold yields SPAM. Explicit allow lists always yield TRUSTED before evaluation. No match yields REVIEW.

Fields: `senderName`, `senderAddress`, `senderDomain`, `subject`, `body`, `content`, `importance`, `spf`, `dkim`, `dmarc`. `body` uses the provider's body preview, not full HTML. `content` concatenates sender name, subject and body preview, preserving the original classifier's behavior. `importance` is normal/high/low.

Operators: `contains`, `startsWith`, `endsWith`, `equals`, `regex` use a nonempty `value`. `containsAny` and `containsAll` use nonempty `values`. Matching is case-insensitive after NFKC normalization and normalization of typographic dashes/quotes. Regex patterns use .NET syntax, case-insensitive/culture-invariant matching and a 50 ms timeout; patterns must not match empty input. Regex patterns themselves are not text-normalized.

### Email authentication evidence

`spf`, `dkim` and `dmarc` expose Microsoft receiver results, not a fresh DNS or cryptographic check by MailSentry. Values are lower-case result codes: `pass`, `fail`, `none`, `neutral`, `softfail`, `temperror`, `permerror`, `policy`, `bestguesspass` as applicable to each protocol, or `unknown`. Missing, malformed, ambiguous or untrusted evidence becomes `unknown`, not `fail`. Old stored messages need a new scan to collect headers.

Only one `Authentication-Results` header above a recognised Microsoft ingress `Received` boundary is accepted. The preceding transport receivers must be Microsoft hosts; an explicit authserv-id must be `mx.microsoft.com`, `outlook.com` or `hotmail.com`. Ingress is recognised by a `.mail.protection.outlook.com` or `.olc.protection.outlook.com` receiver, or Microsoft `via Frontend Transport`. Results below ingress, `Authentication-Results-Original` and `ARC-Authentication-Results` are ignored. Header order must be preserved by Graph. Unrecognised layouts supply no scoring evidence. A DMARC result also needs a `header.from` domain matching the actual From domain. Multiple DKIM signatures with any pass yield `pass`; conflicting SPF/DMARC assessments yield `unknown`. See [Microsoft's header reference](https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo) and [RFC 8601's trust requirements](https://www.rfc-editor.org/rfc/rfc8601.html#section-1.6).

`007-authentication.json` contributes **3 points once** for DMARC failure corroborated by SPF fail/softfail or DKIM fail. These are correlated checks, so they do not accumulate three separate scores. A failure alone stays REVIEW. SPF failure with passing DMARC, missing signatures, DNS errors and `bestguesspass` add no points. Passing checks do not automatically trust mail or authenticate a display-name brand. Forwarders and mailing lists can break authentication; inspect impact before adding stronger rules. No mailbox address is automatically blocked or allow-listed. Explicit allow lists still win, even when authentication fails.

### Sender display-name lookalikes

NFKC already handles fullwidth and mathematical lettering and canonically equivalent accents. It does not equate Cyrillic `Р` or Greek `Ρ` with Latin `P`. Two additional operators, **only for `senderName`**, explicitly compare a limited lookalike representation:

```json
{ "field": "senderName", "operator": "confusableEquals", "value": "paypal" }
```

`confusableEquals` compares the whole display name; `confusableContains` finds an obfuscated brand within it. Both require a single 3–100 character ASCII brand `value` (letters/digits, spaces, dots, ampersands, apostrophes and hyphens). They match only if the canonical, case-insensitive text does **not** already match that target. Thus `РayРal` and `ＰａｙＰａｌ` match, while `PayPal` and `PayPal Мария` do not. Fullwidth and mathematical lettering is retained when checking whether a brand is obfuscated, then folded by NFKC for comparison. Existing text operators, addresses, sender domains and allow lists are never folded through this mapping.

The mapping covers common Greek/Cyrillic Latin lookalikes, a small number of other lookalikes, and removes Unicode format characters from the comparison only. It preserves accents and original text. This is a deliberately limited heuristic, **not a complete [Unicode UTS #39 skeleton implementation](https://www.unicode.org/reports/tr39/)**, IDN reputation check or proof of fraud. Ordinary international names and body-only lookalikes do not receive a generic Unicode score. Unmatched Junk and sanitised exports show the comparison text when it differs.

`008-financial-impersonation.json` contributes **4 points once** for an obfuscated financial brand, regardless of how many names in that rule match. This alone stays REVIEW; together with the 3-point authentication failure rule it reaches the default threshold of 7. The brand list lives in JSON and can be extended using the normal preview/activation workflow.

Compound conditions use `all` (AND) or `any` (OR), each containing nonempty condition arrays. Nesting is supported to 12 levels. A condition must be either one leaf or one compound. Do not mix `all`, `any`, or leaf fields. Unsupported properties are rejected. Maximums: 1000 signatures/pack, 100 children/compound, 100 values/operator, 2000 characters/value, 1 MB/file.

Treat generic marketing, random senders, unusual domains and emoji as supporting evidence. Use specific campaign combinations. Do not make broad signatures that classify generic “offer”, “discount”, “bonus”, “congratulations”, no-reply or unusual TLDs as spam alone. Upload, inspect the current impact, then confirm activation. A zero-impact preview is valid but supplies no evidence about accuracy. Validation checks structure and execution safety, not truth of a rule's claims.

External file errors disable the full snapshot. Correct the file to recover on the next scan or detected dashboard refresh; no rebuild/restart is needed. The dashboard uses a cached summary, checking metadata at most once per second and file contents every 30 seconds when requested. Scans, previews and activation always verify current contents immediately. Uploaded packs cannot replace an existing filename or reuse an existing ID. Edit/remove existing files administratively if needed; the first version intentionally has no rule editor. See [signature loading and cache safety](signature-loading.md).
